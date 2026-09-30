"""Inputs the ClusterFuzzLite targets found escaping the documented error type.

Each case is a document a verifier receives from somebody else. Every one was
refused before this file existed, so none of them was accepted, but each was
refused with an exception its module does not document: ``RecursionError``
from nesting a few hundred levels deep, a bare ``ValueError`` from Python's
integer-string limit, and ``UnanchorableValue`` from the anchor canonicalization
under a function documented to raise ``ProvenanceError``. A caller written
against the documented type does not catch any of them, so a single small
document took down the process that was checking it.

The reproducers are the smallest shapes the fuzz targets in ``.clusterfuzzlite/``
reported, rebuilt by hand so they do not depend on a corpus file.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time

import jsonschema
import pytest
from cryptography.exceptions import InvalidSignature

from agentrust_trace import content_marking, intent_bridge, provenance, validate
from agentrust_trace.sign import (
    TRACE_PROFILE_V0_2,
    UnanchorableValue,
    anchor_bytes,
    generate_key,
    key_to_jwk,
    sign_record,
    verify_record,
)

#: Deep enough to exhaust the default interpreter stack in every recursive walker
#: involved (jsonschema needs a few hundred levels, rfc8785 about a thousand).
DEPTH = 5000


def _nested(depth: int = DEPTH) -> list:
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


def _signed_record(key):
    record = {
        "eat_profile": TRACE_PROFILE_V0_2,
        "iat": int(time.time()),
        "subject": "spiffe://acme.example/agent/a",
        "model": {"provider": "acme", "model_id": "m-1"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
        "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    }
    return sign_record(record, key)


# --- sign.verify_record / validate --------------------------------------------------


@pytest.mark.parametrize("depth", [300, DEPTH])
def test_verify_record_refuses_a_deeply_nested_jwk_member_with_value_error(depth):
    """``cnf.jwk`` admits extra members of any canonicalizable shape, recursively.
    Three hundred nested arrays, about six hundred bytes, exhausted jsonschema's
    stack and ``RecursionError`` escaped ``verify_record``."""
    key = generate_key()
    record = _signed_record(key)
    verify_record(record, key_to_jwk(key))
    record["cnf"]["jwk"]["ext"] = _nested(depth)
    with pytest.raises(ValueError, match="nest"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_still_reports_a_shallow_extra_member_as_a_bad_signature():
    """The guard is for nesting the validator cannot walk, not for nesting."""
    key = generate_key()
    record = _signed_record(key)
    record["cnf"]["jwk"]["ext"] = _nested(20)
    with pytest.raises(InvalidSignature):
        verify_record(record, key_to_jwk(key))


def test_validate_json_and_iter_errors_report_nesting_as_a_schema_violation():
    record = _signed_record(generate_key())
    record["cnf"]["jwk"]["ext"] = _nested()
    with pytest.raises(jsonschema.ValidationError, match="nest"):
        validate.validate_json(record)
    errors = validate.iter_errors(record)
    assert len(errors) == 1 and "nest" in errors[0].message


def test_anchor_bytes_refuses_nesting_it_cannot_walk_by_name():
    with pytest.raises(UnanchorableValue, match="nest"):
        anchor_bytes({"a": _nested()})


# --- provenance -------------------------------------------------------------------


def _tools(input_schema):
    return [{"name": "search", "description": "d", "input_schema": input_schema}]


@pytest.mark.parametrize(
    "input_schema",
    [
        {"type": "number", "maximum": 1.5},
        {"type": "integer", "maximum": 2**64},
        {"type": "array", "items": _nested()},
    ],
    ids=["float", "unsafe-integer", "deep"],
)
def test_check_tool_catalog_refuses_an_unhashable_server_catalog_with_provenance_error(
    input_schema,
):
    """The tools are what a live server returned. A JSON Schema ``maximum`` of 1.5
    is ordinary content, and ``UnanchorableValue`` escaped a function documented
    to raise ``ProvenanceError``."""
    key = generate_key()
    record = provenance.sign_record(
        provenance.build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=_tools({"type": "object"}),
            artifact={"package": "p", "digest": "sha256:" + "a" * 64},
        ),
        key,
    )
    with pytest.raises(provenance.ProvenanceError):
        provenance.check_tool_catalog(record, _tools(input_schema))
    with pytest.raises(provenance.ProvenanceError) as caught:
        provenance.tool_catalog_hash(_tools(input_schema))
    # Still the anchor layer's refusal too, which tests/test_safe_integer_range.py
    # and any caller written before this change catch.
    assert isinstance(caught.value, UnanchorableValue)


def test_provenance_verify_record_refuses_a_deeply_nested_member_with_provenance_error():
    """``identity.artifact`` is checked for the members it names and nothing else, so
    an extra member reaches the RFC 8785 walk and exhausted its stack."""
    key = generate_key()
    record = provenance.sign_record(
        provenance.build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=_tools({"type": "object"}),
            artifact={"package": "p", "digest": "sha256:" + "a" * 64},
        ),
        key,
    )
    record["identity"]["artifact"]["extra"] = _nested()
    with pytest.raises(provenance.ProvenanceError, match="nest"):
        provenance.verify_record(record, key_to_jwk(key))


# --- intent bridge ----------------------------------------------------------------


def test_verify_bridge_refuses_a_deeply_nested_tool_call_with_intent_bridge_error():
    """``tool_call`` is the execution evidence, digested with RFC 8785. Nesting past
    the interpreter stack escaped as ``RecursionError``."""
    key = generate_key()
    tool_call = {"name": "send_invoice", "arguments": {}}
    declaration = {"impact": "external-side-effect"}
    authorization = {
        "authorization_id": "a-1",
        "decision": "allow",
        "authorizer": "policy",
        "authorizer_key_id": "k-1",
        "authorized_at": 100,
        "expires_at": 200,
        "scope": {"tools": ["send_invoice"], "impacts": ["external-side-effect"]},
        "pic": {
            "profile": "PIC-CJSON/1.0",
            "intent_digest": "sha256:" + "1" * 64,
            "args_digest": "sha256:" + "2" * 64,
        },
        "declaration_digest": intent_bridge.digest_jcs(declaration),
        "tool_call_digest": intent_bridge.digest_jcs(tool_call),
        "transcript_required": False,
    }
    bridge = intent_bridge.sign_bridge(authorization, key)
    deep_call = {**tool_call, "arguments": {"x": _nested()}}
    with pytest.raises(intent_bridge.IntentBridgeError, match="canonical"):
        intent_bridge.verify_bridge(
            bridge,
            {**key_to_jwk(key), "kid": "k-1"},
            declaration=declaration,
            pic_intent_digest="sha256:" + "1" * 64,
            pic_args_digest="sha256:" + "2" * 64,
            tool_call=deep_call,
            now=150,
        )
    with pytest.raises(intent_bridge.IntentBridgeError):
        intent_bridge.digest_jcs({"x": _nested()})


# --- content marking --------------------------------------------------------------


def _record_bytes() -> bytes:
    return json.dumps(
        {"eat_profile": TRACE_PROFILE_V0_2, "subject": "spiffe://acme.example/agent/a"}
    ).encode()


def test_verify_assertion_refuses_a_port_past_the_integer_string_limit():
    """RFC 3986 puts no length on a port. ``int()`` of a 4,400 digit string raised
    Python's own ``ValueError`` about its integer-string limit instead of the
    ``ContentMarkingError`` every other malformed URL gets."""
    assertion = content_marking.build_assertion(
        _record_bytes(), url="https://records.example/r.json"
    )
    assertion["data"]["record"]["url"] = "https://records.example:" + "9" * 4400 + "/r.json"
    with pytest.raises(content_marking.ContentMarkingError, match="absolute http"):
        content_marking.verify_assertion(assertion, _record_bytes())


def test_record_url_still_accepts_a_port_with_leading_zeros():
    url = "https://records.example:00443/r.json"
    assertion = content_marking.build_assertion(_record_bytes(), url=url)
    assert assertion["data"]["record"]["url"] == url


def test_verify_assertion_refuses_deeply_nested_served_bytes_with_content_marking_error():
    """The bytes come from whoever serves the URL, and the hash matching them says
    only that they are the bytes the assertion was built over. ``json.loads`` of a
    deeply nested document raised ``RecursionError``."""
    deep = b"[" * 200_000 + b"]" * 200_000
    assertion = content_marking.build_assertion(
        _record_bytes(), url="https://records.example/r.json"
    )
    tampered = copy.deepcopy(assertion)
    tampered["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(deep).hexdigest()
    with pytest.raises(content_marking.ContentMarkingError, match="not JSON"):
        content_marking.verify_assertion(tampered, deep)
    with pytest.raises(content_marking.ContentMarkingError, match="not JSON"):
        content_marking.build_assertion(deep, url="https://records.example/r.json")


@pytest.mark.parametrize(
    "served",
    [
        b'{"eat_profile": "P", "subject": "spiffe://acme.example/agent/a",'
        b' "subject": "spiffe://acme.example/agent/b"}',
        b'{"eat_profile": "P", "subject": "spiffe://acme.example/agent/a",'
        b' "x": {"k": 1, "k": 2}}',
    ],
    ids=["top-level", "nested"],
)
def test_served_record_with_a_duplicate_member_is_refused(served):
    """``json.loads`` keeps the last of two same-named members and says nothing.
    A parser that keeps the first reads a different subject out of the same bytes,
    so the binding this module checks would hold for one reader and not another.
    RFC 8259 leaves duplicate names undefined; the checker refuses them."""
    with pytest.raises(content_marking.ContentMarkingError, match="duplicate"):
        content_marking.build_assertion(served, url="https://records.example/r.json")
    assertion = content_marking.build_assertion(
        _record_bytes(), url="https://records.example/r.json"
    )
    assertion["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(served).hexdigest()
    with pytest.raises(content_marking.ContentMarkingError, match="duplicate"):
        content_marking.verify_assertion(assertion, served)

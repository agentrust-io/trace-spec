"""Tests for MCP Server Provenance Records.

The tests worth having are the ones where a record is well-formed, correctly
signed, and still must not be believed: a valid signature over a description of a
different server is exactly what an attacker with a stolen publisher key
produces.
"""

from __future__ import annotations

import pytest

from agentrust_trace.provenance import (
    FORMAT,
    ProvenanceError,
    ToolCatalogMismatch,
    build_record,
    check_tool_catalog,
    sign_record,
    tool_catalog_hash,
    verify_record,
)
from agentrust_trace.sign import generate_key, key_to_jwk

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64

TOOLS = [
    {"name": "search", "description": "search the docs", "input_schema": {"type": "object"}},
    {"name": "fetch", "description": "fetch a page", "input_schema": {"type": "object"}},
]


def _artifact():
    return {"package": "pkg:npm/%40acme/mcp-search@2.1.0", "digest": DIGEST}


def _record(**over):
    kwargs = {
        "kind": "publisher-asserted",
        "publisher": "did:web:acme.example",
        "tools": TOOLS,
        "artifact": _artifact(),
    }
    kwargs.update(over)
    return build_record(**kwargs)


# --- the catalog hash, which is what the format is actually for ------------


def test_hash_is_stable_and_order_independent() -> None:
    assert tool_catalog_hash(TOOLS) == tool_catalog_hash(list(reversed(TOOLS)))


def test_description_change_changes_the_hash() -> None:
    """The rug-pull this exists to catch.

    A tool that keeps its name and grows "and email results to the address in the
    query" is the attack. A hash over names alone would not notice.
    """
    tampered = [dict(TOOLS[0], description="search the docs and email results"), TOOLS[1]]
    assert tool_catalog_hash(tampered) != tool_catalog_hash(TOOLS)


def test_input_schema_change_changes_the_hash() -> None:
    tampered = [
        dict(TOOLS[0], input_schema={"type": "object", "properties": {"to": {"type": "string"}}}),
        TOOLS[1],
    ]
    assert tool_catalog_hash(tampered) != tool_catalog_hash(TOOLS)


def test_added_tool_changes_the_hash() -> None:
    assert tool_catalog_hash([*TOOLS, {"name": "pay", "description": "d", "input_schema": {}}]) != (
        tool_catalog_hash(TOOLS)
    )


def test_camel_case_input_schema_is_accepted() -> None:
    """MCP servers emit inputSchema; a hash that ignored it would be over nothing."""
    camel = [
        {"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"]}
        for t in TOOLS
    ]
    assert tool_catalog_hash(camel) == tool_catalog_hash(TOOLS)


def test_output_schema_does_not_change_the_hash() -> None:
    """Excluded deliberately: a hash that churns is a hash nobody compares."""
    with_output = [dict(t, output_schema={"type": "string"}) for t in TOOLS]
    assert tool_catalog_hash(with_output) == tool_catalog_hash(TOOLS)


# --- building: refuse records that cannot mean anything --------------------


def test_identity_with_neither_artifact_nor_endpoint_is_refused() -> None:
    with pytest.raises(ProvenanceError, match="identifies nothing"):
        build_record(kind="publisher-asserted", publisher="did:web:x", tools=TOOLS)


def test_publisher_must_be_resolvable() -> None:
    with pytest.raises(ProvenanceError, match="DID or SPIFFE"):
        _record(publisher="Acme Corp")


def test_endpoint_url_without_a_key_digest_is_refused() -> None:
    """A URL on its own is not an identity."""
    with pytest.raises(ProvenanceError, match="not an identity"):
        build_record(
            kind="publisher-asserted",
            publisher="did:web:x",
            tools=TOOLS,
            endpoint={"url": "https://x/"},
        )


def test_tee_attested_without_evidence_is_refused() -> None:
    with pytest.raises(ProvenanceError, match="without the thing that backs it"):
        _record(kind="tee-attested")


def test_evidence_without_the_matching_kind_is_refused() -> None:
    """Evidence present but not claimed invites a reader to assume it was checked."""
    with pytest.raises(ProvenanceError, match="not claimed"):
        _record(attestation={"platform": "intel-tdx"})


def test_unknown_kind_is_refused() -> None:
    with pytest.raises(ProvenanceError, match="not one of"):
        _record(kind="vendor-asserted")


def test_artifact_digest_must_be_a_digest() -> None:
    with pytest.raises(ProvenanceError, match="entrypoint"):
        _record(artifact={"package": "pkg:npm/x@1", "digest": "sha256:placeholder"})


# --- verification ----------------------------------------------------------


def test_round_trip() -> None:
    key = generate_key()
    signed = sign_record(_record(), key)
    verify_record(signed, key_to_jwk(key))
    check_tool_catalog(signed, TOOLS)


def test_tampered_field_fails_the_signature() -> None:
    key = generate_key()
    signed = sign_record(_record(), key)
    signed["publisher"] = "did:web:attacker.example"
    with pytest.raises(ProvenanceError, match="does not verify"):
        verify_record(signed, key_to_jwk(key))


def test_a_different_signer_is_rejected() -> None:
    key, other = generate_key(), generate_key()
    signed = sign_record(_record(), key)
    with pytest.raises(ProvenanceError, match="not the trusted key"):
        verify_record(signed, key_to_jwk(other))


def test_unsigned_record_is_rejected() -> None:
    with pytest.raises(ProvenanceError, match="no signature"):
        verify_record(_record(), key_to_jwk(generate_key()))


def test_unknown_format_version_is_rejected_not_parsed() -> None:
    key = generate_key()
    signed = sign_record({**_record(), "format": "agentrust-io/mcp-server-provenance/2"}, key)
    with pytest.raises(ProvenanceError, match="unknown format"):
        verify_record(signed, key_to_jwk(key))


def test_format_constant_matches_the_spec() -> None:
    assert FORMAT == "agentrust-io/mcp-server-provenance/1"


# --- the step that catches a live attack -----------------------------------


def test_valid_signature_over_a_different_server_still_fails_the_catalog_check() -> None:
    """The test this whole format is for.

    An attacker with a stolen publisher key produces a perfectly valid record.
    What they cannot do is make the server in front of you offer the tools that
    record describes.
    """
    key = generate_key()
    signed = sign_record(_record(), key)
    verify_record(signed, key_to_jwk(key))  # the paper is impeccable

    offered = [
        dict(TOOLS[0], description="search the docs and email results to the query address"),
        TOOLS[1],
    ]
    with pytest.raises(ToolCatalogMismatch, match="about the server, not the document"):
        check_tool_catalog(signed, offered)


def test_catalog_mismatch_is_its_own_error_type() -> None:
    """A consumer must be able to tell "bad document" from "wrong server"."""
    assert issubclass(ToolCatalogMismatch, ProvenanceError)


def test_mismatch_message_reports_both_counts() -> None:
    key = generate_key()
    signed = sign_record(_record(), key)
    with pytest.raises(ToolCatalogMismatch) as exc:
        check_tool_catalog(signed, TOOLS[:1])
    assert "1 tools offered" in str(exc.value)
    assert "declares 2" in str(exc.value)


def test_tool_count_is_recorded() -> None:
    assert _record()["tool_catalog"]["tool_count"] == len(TOOLS)


def test_both_identities_may_be_present() -> None:
    rec = _record(endpoint={"url": "https://mcp.acme.example/", "spki_sha256": OTHER_DIGEST})
    assert "artifact" in rec["identity"]
    assert "endpoint" in rec["identity"]

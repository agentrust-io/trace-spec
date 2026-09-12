"""Tests for the content-marking binding.

The binding is a hash over the bytes served at a URL. Everything that matters is
a way that hash can be right-looking and wrong: computed over a re-serialization
nobody will fetch, checked against a record that was swapped afterwards, or
attached to an assertion describing a different execution entirely.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from agentrust_trace.content_marking import (
    ASSERTION_LABEL,
    ContentMarkingError,
    RecordMismatch,
    _digest,
    build_assertion,
    verify_assertion,
)

URL = "https://registry.example/records/abc123.json"


def _record(**over):
    base = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": 1760000000,
        "subject": "spiffe://example.org/agent/image-bot",
        "data_class": "public",
    }
    base.update(over)
    return base


def _bytes(record) -> bytes:
    return json.dumps(record).encode()


# --- the binding -----------------------------------------------------------


def test_round_trip() -> None:
    raw = _bytes(_record())
    a = build_assertion(raw, url=URL)
    assert a["label"] == ASSERTION_LABEL
    assert verify_assertion(a, raw)["subject"] == "spiffe://example.org/agent/image-bot"


def test_a_changed_record_is_caught() -> None:
    """The case the hash exists for: the URL serves something else later."""
    a = build_assertion(_bytes(_record()), url=URL)
    with pytest.raises(RecordMismatch, match="changed after the asset was signed"):
        verify_assertion(a, _bytes(_record(data_class="confidential")))


def test_reserialization_alone_breaks_the_hash() -> None:
    """Why build_assertion takes bytes rather than an object.

    A hash over a re-serialized dict is a hash of bytes nobody will fetch: the
    same record with different separators is different bytes.
    """
    record = _record()
    a = build_assertion(json.dumps(record).encode(), url=URL)
    with pytest.raises(RecordMismatch):
        verify_assertion(a, json.dumps(record, indent=2).encode())


def test_record_bytes_are_required_to_verify() -> None:
    """There is no signature-only path: an unchecked hash is a URL in a file."""
    import inspect

    sig = inspect.signature(verify_assertion)
    assert sig.parameters["record_bytes"].default is inspect.Parameter.empty


def test_sha384_is_supported() -> None:
    raw = _bytes(_record())
    a = build_assertion(raw, url=URL, alg="sha384")
    assert a["data"]["record"]["hash"].startswith("sha384:")
    assert verify_assertion(a, raw)


def test_unsupported_algorithm_is_refused() -> None:
    with pytest.raises(ContentMarkingError, match="sha256 or sha384"):
        build_assertion(_bytes(_record()), url=URL, alg="md5")


# --- the assertion must describe what it points at ------------------------


def test_a_swapped_subject_is_caught() -> None:
    a = build_assertion(_bytes(_record()), url=URL)
    other = _record(subject="spiffe://example.org/agent/someone-else")
    a["data"]["record"]["hash"] = build_assertion(_bytes(other), url=URL)["data"]["record"]["hash"]
    with pytest.raises(RecordMismatch, match="different record than it points at"):
        verify_assertion(a, _bytes(other))


def test_a_swapped_profile_is_caught() -> None:
    other = _record(eat_profile="tag:agentrust.io,2026:trace-v0.1")
    a = build_assertion(_bytes(other), url=URL)
    a["data"]["eat_profile"] = "tag:agentrust-io.com,2026:trace-v0.2"
    with pytest.raises(RecordMismatch, match="eat_profile"):
        verify_assertion(a, _bytes(other))


# --- refusals --------------------------------------------------------------


def test_record_without_a_resolvable_subject_is_refused() -> None:
    with pytest.raises(ContentMarkingError, match="SPIFFE or DID subject"):
        build_assertion(_bytes(_record(subject="image-bot")), url=URL)


def test_record_without_a_profile_is_refused() -> None:
    r = _record()
    del r["eat_profile"]
    with pytest.raises(ContentMarkingError, match="eat_profile"):
        build_assertion(_bytes(r), url=URL)


def test_empty_url_is_refused() -> None:
    with pytest.raises(ContentMarkingError, match="binds nothing"):
        build_assertion(_bytes(_record()), url="")


def test_empty_bytes_are_refused() -> None:
    with pytest.raises(ContentMarkingError, match="as it will be served"):
        build_assertion(b"", url=URL)


def test_wrong_label_is_refused() -> None:
    a = build_assertion(_bytes(_record()), url=URL)
    a["label"] = "com.someone-else.trace"
    with pytest.raises(ContentMarkingError, match="is not com.agentrust-io.trace"):
        verify_assertion(a, _bytes(_record()))


def test_unknown_version_is_rejected_not_parsed() -> None:
    a = build_assertion(_bytes(_record()), url=URL)
    a["data"]["version"] = 2
    with pytest.raises(ContentMarkingError, match="rejected rather than parsed"):
        verify_assertion(a, _bytes(_record()))


def test_malformed_hash_is_refused() -> None:
    a = build_assertion(_bytes(_record()), url=URL)
    a["data"]["record"]["hash"] = "sha256:placeholder"
    with pytest.raises(ContentMarkingError, match="not a sha256"):
        verify_assertion(a, _bytes(_record()))



# --- record_bytes that are valid JSON but not an object --------------------
#
# json.loads(record_bytes).get(...) assumed the decoded value is a dict. Valid
# JSON is not always an object -- an array, a string, a number, null, and a
# bool are all valid top-level JSON -- and record_bytes is exactly the kind of
# externally-sourced input (served at a URL, in verify_assertion's case) that
# is not guaranteed to be shaped the way a caller expects.


@pytest.mark.parametrize("bad_json", [b"[1,2,3]", b'"just a string"', b"42", b"null", b"true"])
def test_build_assertion_refuses_non_object_json_instead_of_crashing(bad_json) -> None:
    with pytest.raises(ContentMarkingError, match="must decode to a JSON object"):
        build_assertion(bad_json, url=URL)


def test_verify_assertion_refuses_non_object_record_at_the_url() -> None:
    """The record at the URL matches the declared hash but is not an object.

    Not reachable through this module's own build_assertion, which now refuses
    to build an assertion over non-object bytes -- but verify_assertion is
    written against the spec, not against this module's own producer, and a
    peer implementation, or a corrupted/misconfigured server response, can
    still bring a hash-matching non-object body here.
    """
    bad_json = b"[1,2,3]"
    a = build_assertion(_bytes(_record()), url=URL)
    a["data"]["record"]["hash"] = _digest(bad_json, "sha256")

    with pytest.raises(ContentMarkingError, match="must decode to a JSON object"):
        verify_assertion(a, bad_json)


def test_verify_assertion_refuses_invalid_json_at_the_url() -> None:
    """The bytes at the URL match the declared hash but are not JSON at all."""
    garbage = b"not json at all {{{"
    a = build_assertion(_bytes(_record()), url=URL)
    a["data"]["record"]["hash"] = _digest(garbage, "sha256")

    with pytest.raises(ContentMarkingError, match="is not JSON"):
        verify_assertion(a, garbage)


# --- optional anchor -------------------------------------------------------


def test_anchor_is_carried_when_given() -> None:
    a = build_assertion(_bytes(_record()), url=URL, anchor="https://registry.example/e/1")
    assert a["data"]["anchor"] == "https://registry.example/e/1"


def test_anchor_is_omitted_when_absent() -> None:
    """Omitted rather than null: an unanchored record has no entry to name."""
    assert "anchor" not in build_assertion(_bytes(_record()), url=URL)["data"]


# --- record_bytes that are not bytes at all -----------------------------------
#
# build_assertion validates the type of record_bytes and verify_assertion did
# not. The int case is the one worth a test of its own: bytes(5) is five zero
# bytes, so the value was hashed, did not match, and the caller was told the
# record at the URL had changed. That is a specific accusation about somebody
# else's server, made confidently and with a digest attached, when the only
# thing wrong was the argument.

NOT_BYTES = [None, 5, 0, "a string", "", [], ["x"], {"a": 1}, True]


@pytest.mark.parametrize("bad", NOT_BYTES)
def test_verify_assertion_refuses_record_bytes_that_are_not_bytes(bad) -> None:
    a = build_assertion(_bytes(_record()), url=URL)
    with pytest.raises(ContentMarkingError, match="record_bytes must be the bytes retrieved"):
        verify_assertion(a, bad)


def test_an_int_no_longer_reports_a_record_mismatch() -> None:
    """The failure this closes, named on its own so it cannot come back quietly.

    RecordMismatch means "the URL is serving something else". Reporting it for a
    caller's type error points the reader at the wrong party, and it is worse than
    a crash for exactly that reason: a crash says the call was wrong.
    """
    a = build_assertion(_bytes(_record()), url=URL)
    with pytest.raises(ContentMarkingError) as excinfo:
        verify_assertion(a, 5)
    assert not isinstance(excinfo.value, RecordMismatch)
    assert "does not match the assertion" not in str(excinfo.value)


def test_empty_bytes_are_refused_like_build_assertion_refuses_them() -> None:
    a = build_assertion(_bytes(_record()), url=URL)
    with pytest.raises(ContentMarkingError, match="record_bytes must be the bytes retrieved"):
        verify_assertion(a, b"")


# --- presence, not just agreement (#326) -----------------------------------
#
# `verify_assertion` compared the duplicated binding fields with `.get()` equality,
# which establishes that two values agree and not that either exists. A peer-produced
# assertion omitting `data.subject`, paired with a hash-matching record that also
# omitted `subject`, compared `None` against `None` and verified.
#
# `build_assertion` refuses to build from an incomplete record, so these pairs are
# constructed by hand: the defect is in what a consumer accepts from a peer, not in
# what this producer emits.


def _pair(record: dict, drop_from_assertion: tuple[str, ...] = ()) -> tuple[dict, bytes]:
    """An assertion whose hash genuinely matches *record*, so the pair is self-consistent.

    Without recomputing the hash the pair fails at the digest check and the presence
    check is never reached, which would make every test below pass for the wrong reason.
    """
    record_bytes = _bytes(record)
    assertion = build_assertion(_bytes(_record()), url=URL)
    assertion["data"]["record"]["hash"] = (
        "sha256:" + hashlib.sha256(record_bytes).hexdigest()
    )
    for field in drop_from_assertion:
        assert field in assertion["data"], "the field must be present for its removal to count"
        del assertion["data"][field]
    return assertion, record_bytes


@pytest.mark.parametrize("field", ["subject", "eat_profile"])
def test_a_field_absent_from_both_sides_is_not_a_binding(field: str) -> None:
    record = _record()
    del record[field]
    assertion, record_bytes = _pair(record, drop_from_assertion=(field,))
    with pytest.raises(ContentMarkingError, match="required"):
        verify_assertion(assertion, record_bytes)


def test_both_fields_absent_from_both_sides_is_not_a_binding() -> None:
    record = _record()
    del record["subject"], record["eat_profile"]
    assertion, record_bytes = _pair(record, drop_from_assertion=("subject", "eat_profile"))
    with pytest.raises(ContentMarkingError, match="required"):
        verify_assertion(assertion, record_bytes)


@pytest.mark.parametrize("field", ["subject", "eat_profile"])
def test_an_assertion_missing_a_required_field_does_not_accuse_the_server(field: str) -> None:
    """The caller's assertion is malformed, so the reader must not be pointed at the URL.

    Same principle as `test_an_int_no_longer_reports_a_record_mismatch`.
    """
    assertion, record_bytes = _pair(_record(), drop_from_assertion=(field,))
    with pytest.raises(ContentMarkingError) as excinfo:
        verify_assertion(assertion, record_bytes)
    assert not isinstance(excinfo.value, RecordMismatch)


@pytest.mark.parametrize("field", ["subject", "eat_profile"])
def test_a_record_missing_a_required_field_is_a_record_mismatch(field: str) -> None:
    """Here the URL really is serving something that is not a conformant record."""
    record = _record()
    del record[field]
    assertion, record_bytes = _pair(record)
    with pytest.raises(RecordMismatch, match="required"):
        verify_assertion(assertion, record_bytes)


def test_a_complete_pair_still_verifies() -> None:
    """The control: presence checks must refuse nothing that used to bind."""
    record = _record()
    assertion = build_assertion(_bytes(record), url=URL)
    assert verify_assertion(assertion, _bytes(record)) == record

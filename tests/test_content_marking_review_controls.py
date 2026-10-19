"""Public-API paired regressions for content-marking boundaries.

These preserve current behavior without deciding the author's pending error-message,
profile-documentation or fetched-record validation choices.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from agentrust_trace.content_marking import (
    ContentMarkingError,
    RecordMismatch,
    build_assertion,
    verify_assertion,
)

URL = "https://registry.example/records/review.json"
RECORD = {
    "subject": "spiffe://example.org/agent/review",
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1760000000,
}


def _raw(**extra: object) -> bytes:
    return json.dumps({**RECORD, **extra}, ensure_ascii=False).encode("utf-8")


def _retarget(assertion: dict[str, Any], raw: bytes, alg: str) -> dict[str, Any]:
    result = copy.deepcopy(assertion)
    result["data"]["record"]["hash"] = f"{alg}:" + hashlib.new(alg, raw).hexdigest()
    return result


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
def test_bytearray_round_trip_matches_exact_bytes_and_hash(alg: str) -> None:
    raw = _raw(note="supplementary scalar: \U0001f600")
    mutable = bytearray(raw)
    expected = build_assertion(raw, url=URL, alg=alg)
    built = build_assertion(mutable, url=URL, alg=alg)
    assert built == expected
    assert built["data"]["record"]["hash"] == f"{alg}:" + hashlib.new(alg, raw).hexdigest()
    assert verify_assertion(built, mutable) == RECORD | {
        "note": "supplementary scalar: \U0001f600"
    }
    assert bytes(mutable) == raw


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
@pytest.mark.parametrize(
    "member",
    [
        b'"subject":"did:web:other.example","sub\\u006aect":"did:web:last.example"',
        b'"extra":{"k":1,"\\u006b":2}',
        b'"extra":[{"k":1,"\\u006b":2}]',
    ],
    ids=["escaped-top-level", "nested-object", "object-inside-array"],
)
def test_escaped_duplicate_members_refuse_build_and_hash_matching_verify(
    alg: str, member: bytes
) -> None:
    good = _raw(extra=[{"k": 1, "other": 2}])
    assertion = build_assertion(good, url=URL, alg=alg)
    assert verify_assertion(assertion, good)["extra"] == [{"k": 1, "other": 2}]
    # JSON escaping changes spelling, not member identity. Check both producers
    # and consumers, without requiring a specific wrapping of the diagnostic.
    bad = _raw()[:-1] + b"," + member + b"}"
    with pytest.raises(ContentMarkingError, match="duplicate member") as error:
        build_assertion(bad, url=URL, alg=alg)
    assert not isinstance(error.value, RecordMismatch)
    with pytest.raises(ContentMarkingError, match="duplicate member") as error:
        verify_assertion(_retarget(assertion, bad, alg), bad)
    assert not isinstance(error.value, RecordMismatch)


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
def test_utf8_scalar_and_json_escape_pair_both_work_but_bind_distinct_bytes(alg: str) -> None:
    scalar = _raw(note="\U0001f600")
    escaped = json.dumps(RECORD | {"note": "\U0001f600"}, ensure_ascii=True).encode("utf-8")
    assert scalar != escaped
    a = build_assertion(scalar, url=URL, alg=alg)
    b = build_assertion(escaped, url=URL, alg=alg)
    assert verify_assertion(a, scalar) == verify_assertion(b, escaped)
    assert a["data"]["record"]["hash"] != b["data"]["record"]["hash"]
    with pytest.raises(RecordMismatch):
        verify_assertion(a, escaped)


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
def test_interior_bom_scalar_is_content_and_not_a_leading_byte_order_mark(alg: str) -> None:
    raw = _raw(note="before\ufeffafter")
    assertion = build_assertion(raw, url=URL, alg=alg)
    assert verify_assertion(assertion, raw)["note"] == "before\ufeffafter"
    prefixed = b"\xef\xbb\xbf" + raw
    with pytest.raises(ContentMarkingError, match="byte-order mark") as error:
        verify_assertion(_retarget(assertion, prefixed, alg), prefixed)
    assert not isinstance(error.value, RecordMismatch)


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
def test_direct_anchor_accepts_utf8_scalar_without_normalizing_its_spelling(alg: str) -> None:
    raw = _raw()
    anchor = "https://registry.example/entries/\U0001f600"
    assertion = build_assertion(raw, url=URL, alg=alg, anchor=anchor)
    assert assertion["data"]["anchor"] == anchor
    assert verify_assertion(assertion, raw) == RECORD


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
def test_trailing_newline_changes_binding_despite_identical_decoded_record(alg: str) -> None:
    raw = _raw()
    newline = raw + b"\n"
    assertion = build_assertion(raw, url=URL, alg=alg)
    assert verify_assertion(assertion, raw) == RECORD
    with pytest.raises(RecordMismatch):
        verify_assertion(assertion, newline)
    rebound = build_assertion(newline, url=URL, alg=alg)
    assert verify_assertion(rebound, newline) == RECORD
    assert rebound["data"]["record"]["hash"] != assertion["data"]["record"]["hash"]


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
@pytest.mark.parametrize("bad", [b"{not-json}", b"\xff", b'{"n":NaN}'])
def test_stale_hash_and_matching_hash_distinguish_changed_bytes_from_bad_json(
    alg: str, bad: bytes
) -> None:
    good = _raw()
    assertion = build_assertion(good, url=URL, alg=alg)
    assert verify_assertion(assertion, good) == RECORD
    with pytest.raises(RecordMismatch):
        verify_assertion(assertion, bad)
    with pytest.raises(ContentMarkingError) as error:
        verify_assertion(_retarget(assertion, bad, alg), bad)
    assert not isinstance(error.value, RecordMismatch)

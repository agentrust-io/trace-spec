"""Immutable record snapshots and malformed-record error classification."""

from __future__ import annotations

import hashlib
import json

import pytest

from agentrust_trace import content_marking as marking

URL = "https://registry.example/records/snapshot.json"
RECORD = {"subject": "did:web:example.com", "eat_profile": "trace", "note": "original"}
RAW = json.dumps(RECORD).encode()
CHANGED = json.dumps(RECORD | {"note": "changed"}).encode()


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
def test_build_parses_and_hashes_one_snapshot(alg: str, monkeypatch: pytest.MonkeyPatch) -> None:
    expected = marking.build_assertion(RAW, url=URL, alg=alg)
    mutable = bytearray(RAW)
    original_loads = marking._loads

    def mutate_after_parse(data: bytes | bytearray, what: str) -> object:
        parsed = original_loads(data, what)
        mutable[:] = CHANGED
        return parsed

    # A deterministic caller mutation at the parse/hash seam replaces a flaky
    # thread race. The original buffer changes, but the built hash must not.
    monkeypatch.setattr(marking, "_loads", mutate_after_parse)
    actual = marking.build_assertion(mutable, url=URL, alg=alg)
    assert bytes(mutable) == CHANGED
    assert actual == expected
    assert marking.verify_assertion(actual, RAW) == RECORD
    with pytest.raises(marking.RecordMismatch):
        marking.verify_assertion(actual, CHANGED)


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
def test_verify_hashes_and_parses_one_snapshot(alg: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assertion = marking.build_assertion(RAW, url=URL, alg=alg)
    assert marking.verify_assertion(assertion, bytearray(RAW)) == RECORD
    mutable = bytearray(RAW)
    original_digest = marking._digest

    def mutate_after_hash(data: bytes | bytearray, algorithm: str) -> str:
        digest = original_digest(data, algorithm)
        mutable[:] = CHANGED
        return digest

    monkeypatch.setattr(marking, "_digest", mutate_after_hash)
    actual = marking.verify_assertion(assertion, mutable)
    assert bytes(mutable) == CHANGED
    assert actual == RECORD
    with pytest.raises(marking.RecordMismatch):
        marking.verify_assertion(assertion, CHANGED)


@pytest.mark.parametrize("alg", ["sha256", "sha384"])
@pytest.mark.parametrize("field", ["subject", "eat_profile"])
@pytest.mark.parametrize("missing", [False, True], ids=["null", "absent"])
def test_hash_matching_malformed_record_is_not_a_mismatch(
    alg: str, field: str, missing: bool
) -> None:
    assertion = marking.build_assertion(RAW, url=URL, alg=alg)
    assert marking.verify_assertion(assertion, RAW) == RECORD
    bad: dict[str, object] = dict(RECORD)
    if missing:
        del bad[field]
    else:
        bad[field] = None
    raw = json.dumps(bad).encode()
    # First retain the stale hash: substituted bytes remain a mismatch.
    with pytest.raises(marking.RecordMismatch):
        marking.verify_assertion(assertion, raw)
    assertion["data"]["record"]["hash"] = f"{alg}:" + hashlib.new(alg, raw).hexdigest()
    with pytest.raises(marking.ContentMarkingError) as error:
        marking.verify_assertion(assertion, raw)
    assert type(error.value) is marking.ContentMarkingError

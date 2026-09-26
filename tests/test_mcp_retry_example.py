"""Check the worked example's retained facts and commitments, not an MCP verifier."""

from __future__ import annotations

import hashlib
import runpy
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import key_to_jwk, verify_record

DIRECTORY = Path(__file__).resolve().parents[1] / "examples" / "mcp-retry"
GENERATOR = runpy.run_path(str(DIRECTORY / "gen_mcp_retry.py"))


@pytest.fixture
def packet():
    return GENERATOR["load_json"]((DIRECTORY / "packet.json").read_text("utf-8"))


@pytest.fixture
def inputs():
    return GENERATOR["load_json"]((DIRECTORY / "verification-inputs.json").read_text("utf-8"))


def _verify_record(packet, inputs):
    result = verify_record(
        packet["record"],
        inputs["trusted_key"],
        allow_embedded_key=False,
        now=inputs["now"],
        max_age_seconds=60,
        max_future_skew_seconds=0,
    )
    assert result.revocation.outcome == "no_check_performed"


def _commitment(value, expected):
    # Independent of the generator's digest helper. This is not a semantic appraisal.
    if value is None:
        return "unavailable"
    actual = "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()
    return "matched" if actual == expected else "mismatch"


def test_record_and_full_retained_commitments_verify_separately(packet, inputs):
    _verify_record(packet, inputs)
    record, transcript = packet["record"], packet["transcript"]
    assert record["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2"
    assert record["policy"]["enforcement_mode"] == "declared"
    assert record["appraisal"]["status"] == "none"
    assert _commitment(transcript, record["tool_transcript"]["hash"]) == "matched"
    assert transcript["format"] == "example-only/mcp-retry-transcript-v1"
    for attempt in transcript["attempts"]:
        reference = attempt["declarations"]
        snapshot = packet["snapshots"][reference["digest"]]
        assert _commitment(snapshot, reference["digest"]) == "matched"
        assert snapshot["format"] == "example-only/mcp-declarations-v1"
        assert (
            snapshot["canonicalization"]
            == reference["canonicalization"]
            == transcript["canonicalization"]
            == "example-only/jcs-safe-integers-v1"
        )
        assert snapshot["server_observed"] == attempt["server_observed"]
        assert snapshot["protocol_revision"] == attempt["protocol_revision"]


def test_retry_retains_the_lost_response_without_inventing_an_execution_outcome(packet):
    first, retry = packet["transcript"]["attempts"]
    assert packet["record"]["tool_transcript"]["call_count"] == 2
    assert first["attempt_id"] != retry["attempt_id"]
    assert first["retry_of"] is None and retry["retry_of"] == first["attempt_id"]
    assert first["request_context"] != retry["request_context"]
    assert type(first["request"]["id"]) is type(retry["request"]["id"]) is int
    assert first["request"]["id"] != retry["request"]["id"]
    assert first["request"]["params"] == retry["request"]["params"]
    # No response or execution conclusion is added to the first observation.
    assert first["observation"] == {"kind": "response_stream_lost"}
    assert retry["observation"]["kind"] == "response_observed"
    response = retry["observation"]["response"]
    assert type(response["id"]) is int and response["id"] == retry["request"]["id"]
    assert response["result"]["resultType"] == "complete"
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"] == {"stock": 3}


def test_both_full_paginated_captures_survive_with_the_uncalled_tool_change(packet):
    before, after = [
        packet["snapshots"][attempt["declarations"]["digest"]]
        for attempt in packet["transcript"]["attempts"]
    ]
    assert before["capture_id"] != after["capture_id"]
    for snapshot in (before, after):
        first, last = snapshot["pages"]
        assert snapshot["source"] == "fresh-discovery"
        assert snapshot["collection_complete_observed"] is True
        assert first["request_cursor"] is None
        assert first["result"]["nextCursor"] == last["request_cursor"] == "page-2"
        assert "nextCursor" not in last["result"]
        for page in (first, last):
            assert page["result"]["resultType"] == "complete"
            assert page["result"]["ttlMs"] == 0
            assert page["result"]["cacheScope"] == "private"
    assert before["pages"][0] == after["pages"][0]  # Selected tool unchanged.
    uncalled = [s["pages"][1]["result"]["tools"][0] for s in (before, after)]
    assert [t["_meta"]["example.org/declaration-revision"] for t in uncalled] == ["one", "two"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "inventory.other"),
        ("outputSchema", {"type": "array"}),
        ("_meta", {"example.org/declaration-revision": "changed"}),
    ],
)
def test_each_uncalled_declaration_member_is_committed(packet, inputs, field, value):
    reference = packet["transcript"]["attempts"][0]["declarations"]["digest"]
    snapshot = packet["snapshots"][reference]
    snapshot["pages"][1]["result"]["tools"][0][field] = value
    _verify_record(packet, inputs)
    assert (
        _commitment(packet["transcript"], packet["record"]["tool_transcript"]["hash"]) == "matched"
    )
    assert _commitment(snapshot, reference) == "mismatch"


@pytest.mark.parametrize(
    "path,value",
    [
        (("attempts", 1, "declarations", "digest"), "sha256:" + "0" * 64),
        (("attempts", 1, "retry_of"), None),
        (("attempts", 1, "observation", "response", "result", "structuredContent", "stock"), 4),
        (("attempts", 0, "observation", "kind"), "proven_not_executed"),
        (("attempts", 1, "request", "id"), "2"),
        (("execution_scope",), "different-scope"),
    ],
)
def test_attempt_edits_preserve_the_record_signature_but_break_its_commitment(
    packet,
    inputs,
    path,
    value,
):
    parent = packet["transcript"]
    for member in path[:-1]:
        parent = parent[member]
    parent[path[-1]] = value
    _verify_record(packet, inputs)
    assert (
        _commitment(packet["transcript"], packet["record"]["tool_transcript"]["hash"]) == "mismatch"
    )


def test_dropping_a_retained_page_breaks_the_snapshot_commitment(packet, inputs):
    reference = packet["transcript"]["attempts"][0]["declarations"]["digest"]
    snapshot = packet["snapshots"][reference]
    snapshot["pages"].pop()
    _verify_record(packet, inputs)
    assert _commitment(snapshot, reference) == "mismatch"


@pytest.mark.parametrize("missing", ["transcript", "snapshot"])
def test_missing_evidence_is_unavailable_not_a_successful_comparison(packet, inputs, missing):
    if missing == "transcript":
        del packet["transcript"]
        retained = packet.get("transcript")
        expected = packet["record"]["tool_transcript"]["hash"]
    else:
        expected = packet["transcript"]["attempts"][0]["declarations"]["digest"]
        del packet["snapshots"][expected]
        retained = packet["snapshots"].get(expected)
    _verify_record(packet, inputs)
    assert _commitment(retained, expected) == "unavailable"


def test_wrong_trusted_key_is_not_replaced_by_the_embedded_key(packet, inputs):
    inputs["trusted_key"] = key_to_jwk(Ed25519PrivateKey.from_private_bytes(b"\x07" * 32))
    with pytest.raises(ValueError, match="does not identify the trusted key"):
        _verify_record(packet, inputs)


def test_changing_the_signed_transcript_hash_invalidates_the_signature(packet, inputs):
    packet["record"]["tool_transcript"]["hash"] = "sha256:" + "0" * 64
    with pytest.raises(InvalidSignature):
        _verify_record(packet, inputs)


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"nested":[{"x":0,"x":1}]}'])
def test_duplicate_json_members_are_refused_before_commitment(text):
    with pytest.raises(ValueError, match="duplicate JSON member"):
        GENERATOR["load_json"](text)


@pytest.mark.parametrize(
    "number",
    [
        "1.0",
        "1e0",
        "0.5",
        "NaN",
        "Infinity",
        "-Infinity",
        "9007199254740992",
        "-9007199254740992",
    ],
)
def test_example_numeric_subset_is_explicitly_refused(number):
    with pytest.raises(ValueError, match="unsupported numeric value"):
        GENERATOR["load_json"]('{"nested":[' + number + "]}")


def test_local_canonicalization_preserves_supported_boolean_null_and_safe_integer():
    text = '{"values":[true,false,null,9007199254740991,-9007199254740991]}'
    value = GENERATOR["load_json"](text)
    assert GENERATOR["canonical_bytes"](value) == text.encode()

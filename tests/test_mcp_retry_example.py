"""Assess the retained MCP retry example, not a normative MCP verifier.

The SDK checks the v0.2 record. The small assessment below checks this example's
local commitments and observations separately. Its outcomes are not conformance
claims, server authentication, execution proof, or complete-history claims.
"""

from __future__ import annotations

import hashlib
import runpy
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import key_to_jwk, sign_record, verify_record

DIRECTORY = Path(__file__).resolve().parents[1] / "examples" / "mcp-retry"
GENERATOR = runpy.run_path(str(DIRECTORY / "gen_mcp_retry.py"))
CANONICALIZATION = GENERATOR["CANONICALIZATION"]


@pytest.fixture
def packet() -> dict[str, Any]:
    return GENERATOR["load_json"]((DIRECTORY / "packet.json").read_text("utf-8"))


@pytest.fixture
def inputs() -> dict[str, Any]:
    return GENERATOR["load_json"]((DIRECTORY / "verification-inputs.json").read_text("utf-8"))


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _same_id(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right


def _verify_record(packet: dict[str, Any], inputs: dict[str, Any]) -> None:
    result = verify_record(
        packet["record"],
        inputs["trusted_key"],
        allow_embedded_key=False,
        now=inputs["now"],
        max_age_seconds=60,
        max_future_skew_seconds=0,
    )
    assert result.revocation.outcome == "no_check_performed"


def _snapshot_status(packet: dict[str, Any], attempt: dict[str, Any]) -> str:
    reference = attempt["declarations"]
    _require(
        reference["canonicalization"] == CANONICALIZATION, "unsupported snapshot canonicalization"
    )
    retained = packet.get("snapshots", {})
    commitment = reference["digest"]
    if commitment not in retained:
        return "unavailable"
    snapshot = retained[commitment]
    if GENERATOR["digest"](snapshot) != commitment:
        return "mismatch"
    _require(
        snapshot["canonicalization"] == CANONICALIZATION, "unsupported snapshot canonicalization"
    )
    _require(snapshot["format"] == GENERATOR["SNAPSHOT_FORMAT"], "unsupported snapshot format")
    _require(
        snapshot["server_observed"] == attempt["server_observed"]
        and snapshot["protocol_revision"] == attempt["protocol_revision"],
        "snapshot context differs from attempt",
    )

    # This establishes an observed terminal traversal, not an atomic catalog.
    pages = snapshot["pages"]
    if not pages or snapshot["collection_complete_observed"] is not True:
        return "incomplete"
    expected_cursor: str | None = None
    seen: set[str | None] = set()
    for index, page in enumerate(pages):
        cursor = page["request_cursor"]
        if not _same_id(cursor, expected_cursor) or cursor in seen:
            return "incomplete"
        seen.add(cursor)
        result = page["result"]
        if result["resultType"] != "complete":
            return "incomplete"
        if "nextCursor" not in result:
            return "complete_observed" if index == len(pages) - 1 else "incomplete"
        expected_cursor = result["nextCursor"]
        if type(expected_cursor) is not str or expected_cursor in seen:
            return "incomplete"
    return "incomplete"


def _assess(packet: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    """Check only the local example contract; no untrusted network resolution."""
    _verify_record(packet, inputs)
    result: dict[str, Any] = {"record": "verified"}
    transcript = packet.get("transcript")
    if transcript is None:
        return {**result, "transcript": "unavailable"}
    if GENERATOR["digest"](transcript) != packet["record"]["tool_transcript"]["hash"]:
        return {**result, "transcript": "mismatch"}
    _require(
        transcript["canonicalization"] == CANONICALIZATION,
        "unsupported transcript canonicalization",
    )
    _require(
        transcript["format"] == GENERATOR["TRANSCRIPT_FORMAT"], "unsupported transcript format"
    )
    _require(
        isinstance(transcript["execution_scope"], str) and bool(transcript["execution_scope"]),
        "missing execution scope",
    )
    attempts = transcript["attempts"]
    _require(
        packet["record"]["tool_transcript"]["call_count"] == len(attempts),
        "call count differs from recorded attempts",
    )
    _require(len(attempts) == 2, "example requires two retained attempts")
    prior: dict[str, dict[str, Any]] = {}
    request_contexts: set[str] = set()
    observations = []
    for index, attempt in enumerate(attempts):
        identifier = attempt["attempt_id"]
        _require(identifier not in prior, "duplicate attempt identity")
        context = attempt["request_context"]
        _require(
            bool(context) and context not in request_contexts,
            "duplicate or missing request context",
        )
        request = attempt["request"]
        _require(type(request["id"]) in (int, str), "unsupported request ID type")
        _require(
            (attempt["retry_of"] is None) == (index == 0),
            "example retry linkage is missing or misplaced",
        )
        if attempt["retry_of"] is not None:
            _require(attempt["retry_of"] in prior, "retry does not name a prior attempt")
            original = prior[attempt["retry_of"]]
            _require(
                not _same_id(request["id"], original["request"]["id"]), "retry reused request ID"
            )
        observation = attempt["observation"]
        if observation["kind"] == "response_stream_lost":
            _require(
                "response" not in observation, "lost response observation also contains a response"
            )
            outcome = "unknown"
        elif observation["kind"] == "response_observed":
            response = observation["response"]
            _require(_same_id(response["id"], request["id"]), "response ID differs from request ID")
            outcome = "producer_observed_response"
        else:
            raise ValueError("unsupported observation kind")
        observations.append(
            {
                "attempt_id": identifier,
                "snapshot": _snapshot_status(packet, attempt),
                "execution_evidence": outcome,
            }
        )
        prior[identifier] = attempt
        request_contexts.add(context)
    return {**result, "transcript": "matched", "attempts": observations}


def _resign(packet: dict[str, Any]) -> None:
    record = packet["record"]
    record["tool_transcript"]["hash"] = GENERATOR["digest"](packet["transcript"])
    packet["record"] = sign_record(
        {key: value for key, value in record.items() if key != "signature"},
        GENERATOR["fixture_key"](),
    )


def _snapshot(packet: dict[str, Any], index: int = 0) -> dict[str, Any]:
    digest = packet["transcript"]["attempts"][index]["declarations"]["digest"]
    return packet["snapshots"][digest]


def _recommit_snapshot(packet: dict[str, Any], index: int = 0) -> None:
    snapshot = _snapshot(packet, index)
    digest = GENERATOR["digest"](snapshot)
    packet["snapshots"][digest] = snapshot
    packet["transcript"]["attempts"][index]["declarations"]["digest"] = digest
    _resign(packet)


def test_packet_keeps_evidence_layers_and_unknown_outcome_separate(packet, inputs):
    assert _assess(packet, inputs) == {
        "record": "verified",
        "transcript": "matched",
        "attempts": [
            {
                "attempt_id": "attempt-1",
                "snapshot": "complete_observed",
                "execution_evidence": "unknown",
            },
            {
                "attempt_id": "attempt-2",
                "snapshot": "complete_observed",
                "execution_evidence": "producer_observed_response",
            },
        ],
    }
    assert packet["record"]["eat_profile"].endswith(":trace-v0.2")
    assert packet["record"]["policy"]["enforcement_mode"] == "declared"
    assert packet["record"]["tool_transcript"]["call_count"] == 2
    first, retry = packet["transcript"]["attempts"]
    assert first["retry_of"] is None and retry["retry_of"] == first["attempt_id"]
    assert first["request_context"] != retry["request_context"]
    assert first["declarations"]["digest"] != retry["declarations"]["digest"]
    # The selected tool is unchanged; the changed declaration is uncalled.
    before, after = _snapshot(packet), _snapshot(packet, 1)
    assert before["pages"][0]["result"]["tools"] == after["pages"][0]["result"]["tools"]
    assert before["pages"][1]["result"]["tools"] != after["pages"][1]["result"]["tools"]


def test_hash_preimages_independently_match_retained_full_objects(packet):
    def independent(value):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()

    assert independent(packet["transcript"]) == packet["record"]["tool_transcript"]["hash"]
    for commitment, snapshot in packet["snapshots"].items():
        assert independent(snapshot) == commitment
        assert GENERATOR["canonical_bytes"](snapshot) == rfc8785.dumps(snapshot)


@pytest.mark.parametrize("field", ["name", "outputSchema", "_meta"])
def test_each_uncalled_declaration_member_is_bound(packet, inputs, field):
    tool = _snapshot(packet)["pages"][1]["result"]["tools"][0]
    tool[field] = {
        "name": "inventory.other",
        "outputSchema": {"type": "array"},
        "_meta": {"example.org/declaration-revision": "changed"},
    }[field]
    result = _assess(packet, inputs)
    assert result["record"] == "verified" and result["transcript"] == "matched"
    assert [item["snapshot"] for item in result["attempts"]] == [
        "mismatch",
        "complete_observed",
    ]


@pytest.mark.parametrize("field", ["digest", "retry", "response", "scope"])
def test_transcript_edits_preserve_record_signature_but_break_binding(packet, inputs, field):
    retry = packet["transcript"]["attempts"][1]
    if field == "digest":
        retry["declarations"]["digest"] = "sha256:" + "0" * 64
    elif field == "retry":
        retry["retry_of"] = None
    elif field == "response":
        retry["observation"]["response"]["result"]["structuredContent"]["stock"] = 4
    else:
        packet["transcript"]["execution_scope"] = "different-scope"
    assert _assess(packet, inputs) == {"record": "verified", "transcript": "mismatch"}


def test_missing_transcript_is_unavailable_not_a_verified_call(packet, inputs):
    del packet["transcript"]
    assert _assess(packet, inputs) == {"record": "verified", "transcript": "unavailable"}


def test_missing_snapshot_is_distinct_from_changed_snapshot(packet, inputs):
    commitment = packet["transcript"]["attempts"][0]["declarations"]["digest"]
    del packet["snapshots"][commitment]
    result = _assess(packet, inputs)
    assert [item["snapshot"] for item in result["attempts"]] == [
        "unavailable",
        "complete_observed",
    ]
    assert result["attempts"][0]["execution_evidence"] == "unknown"


@pytest.mark.parametrize(
    "change,reason",
    [
        ("duplicate", "duplicate attempt identity"),
        ("retry", "retry does not name a prior attempt"),
        ("retry_missing", "example retry linkage is missing or misplaced"),
        ("request_id", "retry reused request ID"),
        ("response_id", "response ID differs from request ID"),
        ("context", "duplicate or missing request context"),
        ("canonicalization", "unsupported transcript canonicalization"),
        ("snapshot_canonicalization", "unsupported snapshot canonicalization"),
        ("outcome", "unsupported observation kind"),
        ("count", "call count differs from recorded attempts"),
    ],
)
def test_resigned_semantic_counterexamples_reach_the_local_gate(packet, inputs, change, reason):
    first, retry = packet["transcript"]["attempts"]
    if change == "duplicate":
        retry["attempt_id"] = first["attempt_id"]
    elif change == "retry":
        retry["retry_of"] = "absent-attempt"
    elif change == "retry_missing":
        retry["retry_of"] = None
    elif change == "request_id":
        retry["request"]["id"] = first["request"]["id"]
    elif change == "response_id":
        retry["observation"]["response"]["id"] = str(retry["request"]["id"])
    elif change == "context":
        retry["request_context"] = first["request_context"]
    elif change == "canonicalization":
        packet["transcript"]["canonicalization"] = "example-only/unsupported"
    elif change == "snapshot_canonicalization":
        first["declarations"]["canonicalization"] = "example-only/unsupported"
    elif change == "outcome":
        first["observation"]["kind"] = "proven_not_executed"
    else:
        packet["record"]["tool_transcript"]["call_count"] = 1
    _resign(packet)
    _verify_record(packet, inputs)
    with pytest.raises(ValueError, match=reason):
        _assess(packet, inputs)


@pytest.mark.parametrize("change", ["missing_page", "reordered", "cursor_loop", "flag"])
def test_resigned_incomplete_capture_never_earns_complete_snapshot(packet, inputs, change):
    snapshot = _snapshot(packet)
    if change == "missing_page":
        snapshot["pages"].pop()
    elif change == "reordered":
        snapshot["pages"].reverse()
    elif change == "cursor_loop":
        snapshot["pages"][1]["result"]["nextCursor"] = "page-2"
    else:
        snapshot["collection_complete_observed"] = False
    _recommit_snapshot(packet)
    _verify_record(packet, inputs)
    assert _assess(packet, inputs)["attempts"][0]["snapshot"] == "incomplete"


def test_matching_string_request_response_ids_keep_their_json_type(packet, inputs):
    retry = packet["transcript"]["attempts"][1]
    # The lexical value equals the first numeric ID, but its JSON type differs.
    retry["request"]["id"] = "1"
    retry["observation"]["response"]["id"] = "1"
    _resign(packet)
    assert _assess(packet, inputs)["attempts"][1]["execution_evidence"] == (
        "producer_observed_response"
    )


def test_wrong_trusted_key_is_not_replaced_by_the_embedded_key(packet, inputs):
    inputs["trusted_key"] = key_to_jwk(Ed25519PrivateKey.from_private_bytes(b"\x07" * 32))
    with pytest.raises(ValueError, match="does not identify the trusted key"):
        _assess(packet, inputs)


def test_signed_record_binds_the_transcript_commitment_before_resolution(packet, inputs):
    packet["record"]["tool_transcript"]["hash"] = "sha256:" + "0" * 64
    del packet["transcript"]
    with pytest.raises(InvalidSignature):
        _assess(packet, inputs)


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"nested":[{"x":0,"x":1}]}'])
def test_duplicate_json_members_are_refused_before_commitment(text):
    with pytest.raises(ValueError, match="duplicate JSON member"):
        GENERATOR["load_json"](text)


@pytest.mark.parametrize(
    "number",
    ["1.0", "1e0", "0.5", "NaN", "Infinity", "-Infinity", "9007199254740992", "-9007199254740992"],
)
def test_example_numeric_subset_is_explicitly_refused(number):
    with pytest.raises(ValueError, match="unsupported numeric value"):
        GENERATOR["load_json"]('{"nested":[' + number + "]}")


def test_local_canonicalization_preserves_supported_boolean_null_and_safe_integer():
    text = '{"values":[true,false,null,9007199254740991,-9007199254740991]}'
    value = GENERATOR["load_json"](text)
    assert GENERATOR["canonical_bytes"](value) == text.encode()
    assert value["values"][:3] == [True, False, None]

"""TR-ANC inclusion-proof tests (#70).

The bug: Level 2 passed on any string that parsed as an https URI, so
`https://example.invalid/nothing-here` earned an anchoring badge. These tests
hold TR-ANC to what section 3.2 actually asks for.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from trace_tests.inclusion import (
    InclusionError,
    canonical_claim_bytes,
    parse_receipt,
    verify_inclusion,
)
from trace_tests.modules import tr_anc
from trace_tests.result import Status

LEAF = b"\x00"
NODE = b"\x01"


def _leaf(claim: dict) -> bytes:
    return hashlib.sha256(LEAF + canonical_claim_bytes(claim)).digest()


def _tree(claims: list[dict]) -> tuple[bytes, list[list[bytes]]]:
    """Build an RFC 6962 tree, returning (root, levels)."""
    level = [_leaf(c) for c in claims]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(NODE + level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(level[-1])  # promoted unpaired, per the anchor format
        level = nxt
        levels.append(level)
    return level[0], levels


def _audit_path(levels: list[list[bytes]], index: int) -> list[str]:
    path, idx = [], index
    for level in levels[:-1]:
        sib = idx ^ 1
        if sib < len(level):
            path.append("sha256:" + level[sib].hex())
        idx //= 2
    return path


def _receipt(claims: list[dict], index: int) -> dict:
    root, levels = _tree(claims)
    return {
        "leaf_index": index,
        "leaf_count": len(claims),
        "audit_path": _audit_path(levels, index),
        "merkle_root": "sha256:" + root.hex(),
    }


def _trace(n: int = 0) -> dict:
    return {"transparency": "https://log.example.com/entries/1", "iat": 1000 + n, "subject": f"agent-{n}"}


def _codes(findings) -> dict[str, Status]:
    return {f.code: f.status for f in findings}


# --- the reported bug ------------------------------------------------------

def test_a_uri_pointing_nowhere_no_longer_earns_level_2():
    """#70: this exact record passed before. It must not now."""
    trace = {"transparency": "https://example.invalid/nothing-here"}
    codes = _codes(tr_anc.check(trace))
    assert codes["TR-ANC-001"] is Status.PASS, "the URI really is well-formed"
    assert codes["TR-ANC-002"] is Status.FAIL, "but nothing proves the record is anchored"


def test_the_pass_message_no_longer_overstates_what_was_checked():
    trace = {"transparency": "https://example.invalid/nothing-here"}
    anc001 = next(f for f in tr_anc.check(trace) if f.code == "TR-ANC-001")
    assert "pointer" in anc001.message


# --- real proofs -----------------------------------------------------------

@pytest.mark.parametrize("count,index", [(1, 0), (2, 0), (2, 1), (3, 2), (5, 3), (8, 7), (9, 8)])
def test_a_genuine_inclusion_proof_passes(count, index):
    claims = [_trace(i) for i in range(count)]
    codes = _codes(tr_anc.check(claims[index], receipt=_receipt(claims, index)))
    assert codes["TR-ANC-002"] is Status.PASS


def test_a_proof_for_a_different_record_fails():
    claims = [_trace(i) for i in range(4)]
    codes = _codes(tr_anc.check(claims[0], receipt=_receipt(claims, 1)))
    assert codes["TR-ANC-002"] is Status.FAIL


def test_a_record_modified_after_anchoring_fails():
    claims = [_trace(i) for i in range(4)]
    receipt = _receipt(claims, 2)
    tampered = dict(claims[2])
    tampered["subject"] = "agent-elsewhere"
    assert _codes(tr_anc.check(tampered, receipt=receipt))["TR-ANC-002"] is Status.FAIL


def test_a_forged_root_fails():
    claims = [_trace(i) for i in range(4)]
    receipt = _receipt(claims, 1)
    receipt["merkle_root"] = "sha256:" + "00" * 32
    assert _codes(tr_anc.check(claims[1], receipt=receipt))["TR-ANC-002"] is Status.FAIL


# --- malformed receipts are reported as malformed, not as "not included" ----

@pytest.mark.parametrize("field", ["leaf_index", "audit_path", "leaf_count", "merkle_root"])
def test_a_receipt_missing_a_field_says_which(field):
    claims = [_trace(i) for i in range(4)]
    receipt = _receipt(claims, 1)
    del receipt[field]
    finding = next(f for f in tr_anc.check(claims[1], receipt=receipt) if f.code == "TR-ANC-002")
    assert finding.status is Status.FAIL
    assert "malformed" in finding.message and field in finding.message


def test_an_out_of_range_leaf_index_fails_rather_than_raising():
    claims = [_trace(i) for i in range(4)]
    receipt = _receipt(claims, 1)
    receipt["leaf_index"] = 99
    assert _codes(tr_anc.check(claims[1], receipt=receipt))["TR-ANC-002"] is Status.FAIL


def test_a_boolean_is_not_an_integer_leaf_index():
    assert verify_inclusion({"a": 1}, True, [], 2, b"\x00" * 32) is False


def test_a_non_hex_audit_node_is_malformed():
    with pytest.raises(InclusionError):
        parse_receipt({"leaf_index": 0, "leaf_count": 1, "audit_path": ["not-a-hash"],
                       "merkle_root": "sha256:" + "00" * 32})


# --- the canonicalisation that must not be "fixed" -------------------------

def test_the_leaf_pre_image_is_sorted_key_ascii_not_jcs():
    """TRACE canonicalises twice by design; the anchor leaf is not JCS.

    A non-ASCII string is where the two disagree, and swapping one for the
    other silently invalidates every genuine proof.
    """
    claim = {"subject": "agent-\u00e9"}
    assert canonical_claim_bytes(claim) == json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    assert rb"\u00e9" in canonical_claim_bytes(claim)


# --- shape checks still work ----------------------------------------------

@pytest.mark.parametrize("value", [None, "", 0])
def test_a_missing_transparency_field_still_fails(value):
    assert _codes(tr_anc.check({"transparency": value}))["TR-ANC-001"] is Status.FAIL


def test_a_non_https_uri_still_fails():
    assert _codes(tr_anc.check({"transparency": "http://log.example.com/1"}))["TR-ANC-001"] is Status.FAIL


def test_a_non_string_transparency_still_fails():
    assert _codes(tr_anc.check({"transparency": 42}))["TR-ANC-001"] is Status.FAIL

"""TR-ANC-002 proves inclusion of the complete signed claim (registry-anchor-v1 section 1).

For ``cmcp-runtime`` the runner used to hand TR-ANC the nested ``trace`` only,
while TR-SIG judged the whole envelope and the reference registry anchors the
whole envelope. A registry-valid anchor then failed the suite, and a re-signed
envelope with different gateway facts still passed against the old proof
(reported on trace-spec#533). The anchor subject is now the complete claim.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trace_tests.inclusion import InclusionError, canonical_claim_bytes, parse_entry
from trace_tests.result import Status
from trace_tests.runner import run

LEAF = b"\x00"
URI = "https://log.example.com/entries/subject-1"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _sign(record: dict[str, Any], priv: Ed25519PrivateKey) -> dict[str, Any]:
    body = json.dumps(
        {k: v for k, v in record.items() if k != "signature"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()
    record["signature"] = _b64url(priv.sign(body))
    return record


def _envelope() -> tuple[dict[str, Any], Ed25519PrivateKey]:
    priv = Ed25519PrivateKey.generate()
    x = _b64url(priv.public_key().public_bytes_raw())
    record = {
        "cmcp_version": "1.0",
        "trace": {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": int(time.time()) - 30,
            "subject": "spiffe://cmcp.gateway/session/anchor-subject",
            "runtime": {"platform": "tpm2", "measurement": "sha256:" + "a" * 64},
            "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
            "data_class": "internal",
            "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "subject-test"}},
            "appraisal": {"status": "affirming", "verifier": "https://verifier.example.org"},
            "transparency": URI,
        },
        "gateway": {"session_id": "anchor-subject", "catalog": {"hash": "sha256:" + "c" * 64}},
        "signature": "",
    }
    return _sign(record, priv), priv


def _anchor(obj: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """A single-leaf receipt and its registry entry for *obj*."""
    root = hashlib.sha256(LEAF + canonical_claim_bytes(obj)).digest()
    receipt = {"leaf_index": 0, "leaf_count": 1, "audit_path": [],
               "merkle_root": "sha256:" + root.hex()}
    entry = {"ts": "2026-10-16T00:00:00Z", "merkle_root": receipt["merkle_root"],
             "leaf_count": 1, "producer": "subject-test/1.0.0", "batch_id": "subject-1"}
    return receipt, entry


def _anc002(record, receipt, entry):
    findings = run(record, "cmcp-runtime", 2, receipt=receipt, entry=entry)["TR-ANC"]
    return next(f for f in findings if f.code == "TR-ANC-002")


def test_complete_envelope_anchor_passes():
    record, _ = _envelope()
    receipt, entry = _anchor(record)
    finding = _anc002(record, receipt, entry)
    assert finding.status is Status.PASS, finding.message
    assert "complete signed claim" in finding.message


def test_nested_trace_only_anchor_fails():
    record, _ = _envelope()
    receipt, entry = _anchor(record["trace"])
    assert _anc002(record, receipt, entry).status is Status.FAIL


def test_resigned_envelope_with_changed_gateway_fails():
    record, priv = _envelope()
    receipt, entry = _anchor(record)
    changed = copy.deepcopy(record)
    changed["gateway"]["session_id"] = "someone-else"
    changed["gateway"]["catalog"]["hash"] = "sha256:" + "d" * 64
    _sign(changed, priv)
    results = run(changed, "cmcp-runtime", 2, receipt=receipt, entry=entry)
    signature_failures = [f for f in results["TR-SIG"] if f.failed()]
    assert not signature_failures, "the re-signed envelope is validly signed"
    assert _anc002(changed, receipt, entry).status is Status.FAIL


def test_changed_signature_fails():
    record, _ = _envelope()
    receipt, entry = _anchor(record)
    changed = copy.deepcopy(record)
    changed["signature"] = _b64url(b"\x00" * 64)
    assert _anc002(changed, receipt, entry).status is Status.FAIL


@pytest.mark.parametrize("ts", [
    "not-a-timestamp", "2026-10-16", "2026-10-16T00:00:00", "2026-10-16T00:00:00+00:00",
    "2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-16 00:00:00Z",
])
def test_entry_ts_must_be_utc_iso8601(ts):
    _, entry = _anchor({"transparency": URI})
    entry["ts"] = ts
    with pytest.raises(InclusionError, match="ts must be an ISO-8601 UTC timestamp"):
        parse_entry(entry)


@pytest.mark.parametrize("ts", ["2026-10-16T00:00:00Z", "2026-10-16T23:59:59.123Z"])
def test_entry_ts_accepts_utc_iso8601(ts):
    _, entry = _anchor({"transparency": URI})
    entry["ts"] = ts
    parse_entry(entry)

"""xChk sealed receipts as TRACE `approval-outcome` references.

Re-verifies examples/xchk-approval-outcome/ without xChk installed. The fixtures were
minted by the registry at in.xchk.io (scripts/trace-fixtures.js in minitru/xchk-server),
which also wrote expected.json. A generator's own summary of its output is a claim, so
every outcome here is recomputed from the committed bytes and compared with
expected.json, never read from it: the Trust Records with this repository's library,
the reference digests with rfc8785, and the bundles with the registry's own
standard-library verifier, vendored beside the fixtures and run as a subprocess.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature

from agentrust_trace import verify_record

XCHK_DIR = Path(__file__).resolve().parents[1] / "examples" / "xchk-approval-outcome"
VERIFIER = XCHK_DIR / "verify_receipt.py"
EXPECTED = json.loads((XCHK_DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
OUTCOME_KEYS = ("trace_record_verifies", "reference_resolves", "digest_matches", "bundle_verifies",
                "disposition", "verdict")


def _load(name: str) -> dict:
    return json.loads((XCHK_DIR / name).read_text(encoding="utf-8"))


def _jcs_sha256(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _bundle_verifies(bundle_name: str) -> bool:
    """The registry's offline verifier, run as it ships: exit 0 is every check passed."""
    proc = subprocess.run(
        [sys.executable, "-I", str(VERIFIER), str(XCHK_DIR / bundle_name)],
        capture_output=True, text=True, check=False, timeout=60,
    )
    return proc.returncode == 0


def _approval_reference(record: dict) -> dict:
    refs = [r for r in record["references"] if r["rel"] == "approval-outcome"]
    assert len(refs) == 1, "one approval-outcome per fixture"
    return refs[0]


def _record_verifies(record: dict) -> bool:
    try:
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=None)
    except (InvalidSignature, ValueError):
        return False
    return True


def _assess(record: dict, bundle_name: str | None) -> dict:
    """What a relying party concludes about the approval a record points at."""
    verifies = _record_verifies(record)
    reference = _approval_reference(record)
    assert reference["resolver"] == EXPECTED["resolver"]
    assert len(reference["id"]) == 64
    if bundle_name is None:
        return {"trace_record_verifies": verifies, "reference_resolves": False,
                "digest_matches": None, "bundle_verifies": None, "disposition": None,
                "verdict": "approval-unconfirmed"}
    bundle = _load(bundle_name)
    digest_matches = _jcs_sha256(bundle["record"]) == reference["digest"]
    bundle_ok = _bundle_verifies(bundle_name)
    disposition = bundle["record"].get("disposition")
    amended = bool(((bundle.get("decision") or {}).get("amendment") or {}).get("command"))
    if not (digest_matches and bundle_ok):
        verdict = "approval-contradicted"
    elif disposition != "approved":
        verdict = "not-an-approval"
    elif amended:
        verdict = "approval-confirmed-as-amended"
    else:
        verdict = "approval-confirmed"
    return {"trace_record_verifies": verifies, "reference_resolves": True,
            "digest_matches": digest_matches, "bundle_verifies": bundle_ok,
            "disposition": disposition, "verdict": verdict}


def test_the_committed_records_are_exactly_the_declared_cases() -> None:
    committed = {
        p.name for p in XCHK_DIR.glob("0*.json") if not p.name.endswith(".bundle.json")
    }
    assert committed == set(CASES)
    for name in CASES:
        bundle = EXPECTED["cases"][name]["bundle"]
        assert bundle is None or (XCHK_DIR / bundle).is_file()


@pytest.mark.parametrize("name", CASES)
def test_every_case_verifies_as_a_trust_record(name: str) -> None:
    """Rule 3 of section 3.1.2: the record stands whatever the reference resolves to."""
    verify_record(_load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)


@pytest.mark.parametrize("name", CASES)
def test_the_outcome_is_recomputed_from_the_committed_bytes(name: str) -> None:
    got = _assess(_load(name), EXPECTED["cases"][name]["bundle"])
    want = {k: EXPECTED["cases"][name][k] for k in OUTCOME_KEYS}
    assert got == want


def test_the_record_signature_covers_the_reference() -> None:
    record = copy.deepcopy(_load("01-approval-confirmed.json"))
    _approval_reference(record)["id"] = "0" * 64
    with pytest.raises(InvalidSignature):
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def test_the_reference_digest_is_the_registry_record_hash() -> None:
    """One number on both sides: rfc8785 over bundle.record equals the registry's own hash."""
    bundle = _load("01-approval-confirmed.bundle.json")
    assert _jcs_sha256(bundle["record"]) == "sha256:" + bundle["recordHash"]
    reference = _approval_reference(_load("01-approval-confirmed.json"))
    assert reference["digest"] == "sha256:" + bundle["recordHash"]


def test_the_altered_bundle_differs_in_one_field_only() -> None:
    before = _load("01-approval-confirmed.bundle.json")
    after = _load("02-bundle-altered-after-issue.bundle.json")
    assert after["record"]["summary"] != before["record"]["summary"]
    after["record"]["summary"] = before["record"]["summary"]
    assert after == before


def test_the_impersonated_approver_offers_a_key_the_binding_does_not_name() -> None:
    """The assertion in 06 verifies with the key the bundle offers; the binding names another."""
    before = _load("01-approval-confirmed.bundle.json")
    after = _load("06-assertion-from-another-credential.bundle.json")
    a_before, a_after = before["approver"], after["approver"]
    assert a_after["publicKey"]["raw"] != a_before["publicKey"]["raw"]
    assert a_after["binding"] == a_before["binding"]
    assert a_after["binding"]["fields"]["publicKey"] == a_before["publicKey"]["raw"]
    for field in ("authenticatorData", "clientDataJSON"):
        assert a_after["assertion"][field] == a_before["assertion"][field]
    assert a_after["assertion"]["signature"] != a_before["assertion"]["signature"]


def test_the_crossed_assertion_is_the_same_persons_answer_to_another_ask() -> None:
    """08: key, binding and user verification all genuine; the challenge the device signed names
    another ask."""
    before = _load("01-approval-confirmed.bundle.json")
    after = _load("08-assertion-over-another-ask.bundle.json")
    a_before, a_after = before["approver"], after["approver"]
    assert a_after["publicKey"] == a_before["publicKey"]
    assert a_after["binding"] == a_before["binding"]
    assert a_after["credentialId"] == a_before["credentialId"]
    assert a_after["challenge"] == a_before["challenge"]
    assert a_after["challenge"]["rule"] == "ask-v1"
    assert a_after["assertion"] != a_before["assertion"]
    a_after["assertion"] = a_before["assertion"]
    assert after == before

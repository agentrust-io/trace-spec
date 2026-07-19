"""Conformance checks for the informative action-receipt fixture set."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURE_DIR = Path(__file__).parent.parent / "examples" / "action-receipts" / "conformance"
ACTION_REF_FIELDS = ("agent_id", "action_type", "action_scope", "action_timestamp")


@dataclass(frozen=True)
class ReceiptResult:
    status: str
    controller_outcome: str
    failures: list[str]
    warnings: list[str]


def _load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_jcs(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _decode_base64url(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise ValueError("fixture value is not valid base64url") from exc


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _verify_signature(receipt: dict[str, Any], trusted_jwk: dict[str, str]) -> None:
    if trusted_jwk.get("kty") != "OKP" or trusted_jwk.get("crv") != "Ed25519":
        raise ValueError("fixture key must be an Ed25519 OKP JWK")
    public_key = Ed25519PublicKey.from_public_bytes(_decode_base64url(trusted_jwk["x"]))
    signing_input = {key: value for key, value in receipt.items() if key != "signature"}
    public_key.verify(_decode_base64url(receipt["signature"]), rfc8785.dumps(signing_input))


def _verify_fixture(fixture: dict[str, Any]) -> ReceiptResult:
    context = fixture["context"]
    action = fixture["action"]
    receipt = fixture.get("receipt")

    if receipt is None:
        if context["require_receipt"]:
            return ReceiptResult(
                status="receipt_missing_required",
                controller_outcome="unknown",
                failures=["receipt_missing"],
                warnings=[],
            )
        raise AssertionError("the conformance set has no optional missing-receipt case")

    failures: list[str] = []
    warnings: list[str] = []

    action_preimage = {field: action[field] for field in ACTION_REF_FIELDS}
    expected_action_ref = _sha256_jcs(action_preimage)
    if action["action_ref"] != expected_action_ref:
        failures.append("action_ref_invalid")
    if receipt["action_ref"] != action["action_ref"]:
        failures.append("action_ref_mismatch")

    if receipt["linked_call_id"] != context["call_id"]:
        failures.append("call_id_mismatch")
    if receipt["session_id"] != context["session_id"]:
        failures.append("session_id_mismatch")

    evidence = fixture["evidence"]
    if receipt["evidence_hash"] != _sha256_jcs(evidence):
        failures.append("evidence_hash_mismatch")

    trusted_jwk = fixture["trusted_issuer_keys"].get(receipt["issuer_key_id"])
    if trusted_jwk is None:
        failures.append("issuer_key_untrusted")
    else:
        try:
            _verify_signature(receipt, trusted_jwk)
        except (InvalidSignature, ValueError):
            failures.append("signature_or_key_mismatch")

    receipt_age = _parse_timestamp(context["verification_time"]) - _parse_timestamp(
        receipt["issued_at"]
    )
    if receipt_age.total_seconds() > context["max_receipt_age_seconds"]:
        failures.append("receipt_stale")
    if receipt_age.total_seconds() < 0:
        failures.append("receipt_from_future")

    if receipt["previous_receipt_hash"] != context["expected_previous_receipt_hash"]:
        failures.append("receipt_chain_gap")

    if evidence["physical_completion_claim"] != "none":
        failures.append("unsupported_physical_completion_claim")

    if receipt["issuer_independence"] == "gateway_self_report":
        warnings.append("issuer_not_independent")

    decision = receipt["decision"]
    if decision not in {"accepted", "rejected"}:
        failures.append("decision_invalid")

    if failures:
        return ReceiptResult(
            status="receipt_invalid",
            controller_outcome="unknown",
            failures=failures,
            warnings=warnings,
        )

    status = "receipt_valid_accepted" if decision == "accepted" else "receipt_valid_rejected"
    return ReceiptResult(
        status=status,
        controller_outcome=evidence["terminal_state"],
        failures=[],
        warnings=warnings,
    )


FIXTURE_PATHS = sorted(FIXTURE_DIR.glob("*.json"))


def test_fixture_set_is_complete() -> None:
    assert [path.name for path in FIXTURE_PATHS] == [
        "01-valid-controller-accepted.json",
        "02-valid-controller-rejected.json",
        "03-missing-required-receipt.json",
        "04-signature-key-mismatch.json",
        "05-action-ref-mismatch.json",
        "06-stale-receipt.json",
        "07-receipt-chain-gap.json",
        "08-same-party-self-report.json",
        "09-unsupported-physical-completion.json",
    ]


@pytest.mark.parametrize("fixture_path", FIXTURE_PATHS, ids=lambda path: path.stem)
def test_action_receipt_conformance_fixture(fixture_path: Path) -> None:
    fixture = _load_fixture(fixture_path)
    assert fixture["profile"] == "trace.action_receipt.conformance.v0"
    result = _verify_fixture(fixture)

    assert result.status == fixture["expected"]["status"]
    assert result.controller_outcome == fixture["expected"]["controller_outcome"]
    assert result.failures == fixture["expected"]["failures"]
    assert result.warnings == fixture["expected"]["warnings"]

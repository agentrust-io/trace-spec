"""Conformance checks for the Acta action-receipt fixtures.

Validates every fixture in examples/action-receipts/acta/ against
draft-farley-acta-signed-receipts-02 and against the expected
positive/negative results declared in expected.json, so envelope or
fixture drift fails CI instead of passing silently.

Uses only dependencies this project already declares: rfc8785 for JCS
canonicalization and cryptography for Ed25519 verification.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ACTA_DIR = Path(__file__).resolve().parents[1] / "examples" / "action-receipts" / "acta"
EXPECTED = json.loads((ACTA_DIR / "expected.json").read_text())
FIXTURES = sorted(p.name for p in ACTA_DIR.glob("0*.json"))

SIGNER_KEY = Ed25519PublicKey.from_public_bytes(
    bytes.fromhex(EXPECTED["signer_public_key_hex"])
)


def _jcs(obj) -> bytes:
    data = rfc8785.dumps(obj)
    return data if isinstance(data, bytes) else data.encode()


def _load(name: str) -> dict:
    return json.loads((ACTA_DIR / name).read_text())


def _signature_verifies(envelope: dict) -> bool:
    try:
        SIGNER_KEY.verify(bytes.fromhex(envelope["signature"]["sig"]), _jcs(envelope["payload"]))
        return True
    except InvalidSignature:
        return False


def test_expected_manifest_covers_all_fixtures():
    assert set(EXPECTED["results"]) == set(FIXTURES)


@pytest.mark.parametrize("name", FIXTURES)
def test_envelope_structure(name):
    """Draft-02 s2: exactly {payload, signature{alg,kid,sig}}; s2.2: issuer_id == kid."""
    env = _load(name)
    assert set(env) == {"payload", "signature"}
    assert set(env["signature"]) == {"alg", "kid", "sig"}
    assert env["signature"]["alg"] == "EdDSA"
    assert re.fullmatch(r"[0-9a-f]{128}", env["signature"]["sig"])
    payload = env["payload"]
    assert payload["type"] == "protectmcp:decision"
    assert payload["decision"] in {"allow", "deny", "rate_limit"}
    assert payload["issuer_id"] == env["signature"]["kid"]
    datetime.fromisoformat(payload["issued_at"])  # RFC 3339 with Z parses in 3.11+
    assert payload["issued_at"].endswith("Z")


@pytest.mark.parametrize("name", FIXTURES)
def test_signature_result_matches_expected(name):
    """Draft-02 s5.6: PureEdDSA over JCS(payload), key resolved from kid (not the receipt)."""
    expected = EXPECTED["results"][name]["signature"]
    actual = "pass" if _signature_verifies(_load(name)) else "fail"
    assert actual == expected, f"{name}: signature check {actual}, expected {expected}"


@pytest.mark.parametrize("name", sorted(EXPECTED["chain"]))
def test_chain_link_result_matches_expected(name):
    """Draft-02 s5.7: previousReceiptHash = SHA-256(JCS(entire predecessor envelope)).

    This is a distinct check from signature verification: fixture 04 is
    validly signed and must PASS the signature check while FAILING here.
    """
    env = _load(name)
    predecessor = _load(EXPECTED["chain"][name])
    recomputed = hashlib.sha256(_jcs(predecessor)).hexdigest()
    actual = "pass" if env["payload"].get("previousReceiptHash") == recomputed else "fail"
    assert actual == EXPECTED["results"][name]["chain"]


def test_stale_policy_digest_is_valid_but_stale():
    env = _load("05-stale-policy-digest.json")
    assert _signature_verifies(env), "05 must pass signature verification"
    assert env["payload"]["policy_digest"] != EXPECTED["current_policy_digest"], (
        "05 must fail the policy-freshness comparison"
    )


def test_session_binding_mismatch_is_valid_but_misbound():
    env = _load("06-session-binding-mismatch.json")
    assert _signature_verifies(env), "06 must pass signature verification"
    assert env["payload"]["session_id"] != EXPECTED["expected_session_id"], (
        "06 must fail the session-binding comparison"
    )


def test_key_mismatch_fixture_is_signed_by_the_committed_second_key():
    """03 is a real signature by the committed mismatched key, not random bytes."""
    env = _load("03-signature-key-mismatch.json")
    other = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex((ACTA_DIR / "mismatched-signer-public-key.txt").read_text().strip())
    )
    other.verify(bytes.fromhex(env["signature"]["sig"]), _jcs(env["payload"]))

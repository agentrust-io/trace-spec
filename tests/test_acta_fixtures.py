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


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_policy_freshness_result_matches_expected(name):
    """Every fixture's declared freshness, not only the one meant to fail it.

    Asserting the failure alone passes whether one fixture is stale or all of them
    are, which is how the set came to share a single ``policy_digest`` while four
    fixtures were declared to pass a comparison they failed.
    """
    declared = EXPECTED["results"][name]["policy_freshness"]
    if declared == "n/a":
        return
    env = _load(name)
    fresh = env["payload"]["policy_digest"] == EXPECTED["current_policy_digest"]
    assert ("pass" if fresh else "fail") == declared


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_session_binding_result_matches_expected(name):
    declared = EXPECTED["results"][name]["session_binding"]
    if declared == "n/a":
        return
    env = _load(name)
    actual = "pass" if env["payload"]["session_id"] == EXPECTED["expected_session_id"] else "fail"
    assert actual == declared


def test_the_two_distinguishing_fixtures_are_otherwise_valid():
    """05 and 06 must isolate their own axis: signature passes, one comparison fails."""
    for name in ("05-stale-policy-digest.json", "06-session-binding-mismatch.json"):
        assert _signature_verifies(_load(name)), f"{name} must pass signature verification"


def test_crosswalk_document_quotes_the_live_fixture_values():
    """The crosswalk embeds real digests and says so; regenerating must not falsify that.

    ``docs/crosswalks/acta-decision-receipts.md`` quotes 01 in full and states that the
    ``chain_head`` it shows "is real". Both go stale the moment the fixtures are
    regenerated, and nothing else would notice.
    """
    doc = (Path(__file__).resolve().parents[1] / "docs" / "crosswalks").joinpath(
        "acta-decision-receipts.md"
    ).read_text(encoding="utf-8")
    r01 = _load("01-valid-accepted.json")
    chain_head = hashlib.sha256(_jcs(_load("02-valid-denied.json"))).hexdigest()

    assert r01["payload"]["policy_digest"] in doc, "the quoted 01 payload is stale"
    assert r01["signature"]["sig"][:64] in doc, "the quoted 01 signature is stale"
    assert chain_head in doc, "the quoted chain head is not 02's current envelope hash"


def test_key_mismatch_fixture_is_signed_by_the_committed_second_key():
    """03 is a real signature by the committed mismatched key, not random bytes."""
    env = _load("03-signature-key-mismatch.json")
    other = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex((ACTA_DIR / "mismatched-signer-public-key.txt").read_text().strip())
    )
    other.verify(bytes.fromhex(env["signature"]["sig"]), _jcs(env["payload"]))

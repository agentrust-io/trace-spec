"""Tests for agentrust_trace.sign."""

import base64
import time

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace import TrustRecord, generate_key, key_to_jwk, sign_record, verify_record
from agentrust_trace.sign import _canonical_bytes


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _minimal_record() -> dict:
    return {
        "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
        "iat": 1750000000,
        "subject": "did:mesh:spiffe://factory.example/agent/payments/prod",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + "0" * 64,
        },
        "policy": {
            "bundle_hash": "sha256:" + "a" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "confidential",
        "build_provenance": {
            "slsa_level": 0,
            "digest": "sha256:" + "b" * 64,
        },
        "appraisal": {
            "status": "affirming",
            "verifier": "https://agt.example.org/verifier",
        },
        "transparency": "https://rekor.sigstore.dev/api/v1/log/entries/example",
        "tool_transcript": {
            "hash": "sha256:" + "c" * 64,
            "call_count": 3,
        },
    }


def test_sign_record_adds_signature_and_cnf():
    key = generate_key()
    record = sign_record(_minimal_record(), key)
    assert "signature" in record
    assert "cnf" in record
    assert record["cnf"]["jwk"]["kty"] == "OKP"
    assert record["cnf"]["jwk"]["crv"] == "Ed25519"
    assert "x" in record["cnf"]["jwk"]


def test_sign_record_signature_verifies():
    key = generate_key()
    record = sign_record(_minimal_record(), key)

    jwk = record["cnf"]["jwk"]
    pub_bytes = _b64url_decode(jwk["x"])
    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    sig_bytes = _b64url_decode(record["signature"])
    pub_key.verify(sig_bytes, body)  # raises InvalidSignature if wrong


def test_tampered_record_fails_verification():
    key = generate_key()
    record = sign_record(_minimal_record(), key)

    jwk = record["cnf"]["jwk"]
    pub_bytes = _b64url_decode(jwk["x"])
    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

    tampered = {**record, "data_class": "public"}
    body = _canonical_bytes({k: v for k, v in tampered.items() if k != "signature"})
    sig_bytes = _b64url_decode(record["signature"])
    with pytest.raises(InvalidSignature):
        pub_key.verify(sig_bytes, body)


def test_signed_record_passes_trust_record_validation():
    key = generate_key()
    record = sign_record(_minimal_record(), key)
    validated = TrustRecord.model_validate(record)
    assert validated.appraisal.status == "affirming"
    assert validated.subject.startswith("did:")


def test_key_to_jwk_shape():
    key = generate_key()
    jwk = key_to_jwk(key)
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert len(jwk["x"]) > 0


def test_sign_record_did_subject():
    key = generate_key()
    record = _minimal_record()
    record["subject"] = "did:key:z6MkhaXgBZDvotzL8oCYaXeFuJArwvX6mDMsKTJVjtN7R"
    signed = sign_record(record, key)
    validated = TrustRecord.model_validate(signed)
    assert validated.subject.startswith("did:key:")


def test_sign_record_spiffe_subject():
    key = generate_key()
    record = _minimal_record()
    record["subject"] = "spiffe://trust.example.org/agent/payments/prod"
    signed = sign_record(record, key)
    validated = TrustRecord.model_validate(signed)
    assert validated.subject.startswith("spiffe://")


def _trusted_jwk(record: dict) -> dict:
    """Return the public JWK of the key that signed *record* (the trust anchor)."""
    return record["cnf"]["jwk"]


def _fresh_record() -> dict:
    """A minimal record with a recent iat so the freshness check passes."""
    record = _minimal_record()
    record["iat"] = int(time.time())
    return record


def test_verify_record_passes_for_valid_signature():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    verify_record(record, key_to_jwk(key))  # must not raise


def test_verify_record_raises_for_tampered_record():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    trusted = key_to_jwk(key)
    record["iat"] = record["iat"] + 1  # tamper (and still fresh)
    with pytest.raises(InvalidSignature):
        verify_record(record, trusted)


def test_verify_record_raises_for_missing_signature():
    record = dict(_fresh_record())
    key = generate_key()
    with pytest.raises(ValueError, match="no 'signature' field"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_requires_trusted_key_by_default():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    with pytest.raises(ValueError, match="requires a trusted key"):
        verify_record(record)


def test_verify_record_embedded_key_opt_in_warns():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    with pytest.warns(UserWarning, match="cnf.jwk"):
        verify_record(record, allow_embedded_key=True)


def test_verify_record_rejects_wrong_trusted_key():
    key_a = generate_key()
    key_b = generate_key()
    record = sign_record(_fresh_record(), key_a)
    # Signed by A, verified against B's public key — must not verify.
    with pytest.raises(InvalidSignature):
        verify_record(record, key_to_jwk(key_b))


def test_verify_record_rejects_expired_record():
    key = generate_key()
    record = _minimal_record()
    record["iat"] = int(time.time()) - 90000  # ~25h old, beyond 24h default
    record = sign_record(record, key)
    with pytest.raises(ValueError, match="stale"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_expired_allowed_when_max_age_none():
    key = generate_key()
    record = _minimal_record()
    record["iat"] = int(time.time()) - 90000
    record = sign_record(record, key)
    verify_record(record, key_to_jwk(key), max_age_seconds=None)  # must not raise


def test_verify_record_rejects_non_okp_jwk():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    ec_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
    with pytest.raises(ValueError, match="kty"):
        verify_record(record, ec_jwk)


def test_verify_record_nonce_match():
    key = generate_key()
    record = _fresh_record()
    record["runtime"]["nonce"] = "abc123"
    record = sign_record(record, key)
    verify_record(record, key_to_jwk(key), expected_nonce="abc123")  # must not raise
    with pytest.raises(ValueError, match="nonce"):
        verify_record(record, key_to_jwk(key), expected_nonce="wrong")


def test_verify_record_rejects_malformed_signature():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    record["signature"] = "!!!not base64!!!"
    with pytest.raises(ValueError, match="base64url"):
        verify_record(record, key_to_jwk(key))

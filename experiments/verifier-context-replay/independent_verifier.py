"""Independent TRACE v0.2 cryptographic verifier for a deliberately bounded profile.

Does not import agentrust_trace code. Covers JCS Ed25519, pinned JWK, key
confirmation, freshness, nonce and frozen revocation identifiers. Validates against the published TRACE JSON Schema as data; does not import the
reference schema validator. Does not interpret external policy/manifest resolution.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import jsonschema
from dataclasses import dataclass
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "src" / "agentrust_trace" / "schema" / "trace-v0.2.json"

@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str

def _decode(text):
    if not isinstance(text, str) or not text or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in text):
        raise ValueError("invalid-base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def _thumbprint(key):
    if not isinstance(key, dict) or key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        raise ValueError("unsupported-trusted-key")
    x = key.get("x")
    if not isinstance(x, str):
        raise ValueError("missing-key-material")
    digest = hashlib.sha256(rfc8785.dumps({"crv": "Ed25519", "kty": "OKP", "x": x})).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

def verify(record, trusted_jwk, *, verification_time, max_age_seconds, max_future_skew_seconds,
           expected_nonce=None, revoked_identifiers=()):
    try:
        if type(verification_time) is not int or verification_time < 0 or verification_time > 253402300799:
            return Verdict("not-established", "invalid-verification-time")
        if max_age_seconds is not None and (type(max_age_seconds) is not int or max_age_seconds < 0):
            return Verdict("not-established", "invalid-age-bound")
        if type(max_future_skew_seconds) is not int or max_future_skew_seconds < 0:
            return Verdict("not-established", "invalid-future-bound")
        if not isinstance(record, dict) or record.get("eat_profile") != PROFILE:
            return Verdict("rejected", "profile")
        if "uri" not in jsonschema.FormatChecker().checkers:
            return Verdict("not-established", "uri-checker-unavailable")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        if not jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).is_valid(record):
            return Verdict("rejected", "schema")
        if not isinstance(trusted_jwk, dict):
            return Verdict("not-established", "trusted-root-missing")
        if _thumbprint(record.get("cnf", {}).get("jwk")) != _thumbprint(trusted_jwk):
            return Verdict("rejected", "key-confirmation")
        ids = (_thumbprint(trusted_jwk), trusted_jwk.get("kid"))
        if any(identifier is not None and identifier in revoked_identifiers for identifier in ids):
            return Verdict("rejected", "revoked")
        iat = record.get("iat")
        if type(iat) is not int:
            return Verdict("rejected", "iat")
        age = verification_time - iat
        if age < -max_future_skew_seconds:
            return Verdict("rejected", "future")
        if max_age_seconds is not None and age > max_age_seconds:
            return Verdict("rejected", "stale")
        if expected_nonce is not None:
            nonce = record.get("runtime", {}).get("nonce")
            if not isinstance(expected_nonce, str) or not isinstance(nonce, str) or not hmac.compare_digest(nonce, expected_nonce):
                return Verdict("rejected", "nonce")
        body = {key: value for key, value in record.items() if key != "signature"}
        raw = _decode(record.get("signature"))
        keybytes = _decode(trusted_jwk["x"])
        if len(raw) != 64 or len(keybytes) != 32:
            return Verdict("rejected", "signature-format")
        Ed25519PublicKey.from_public_bytes(keybytes).verify(raw, rfc8785.dumps(body))
        return Verdict("verified-crypto", "bounded-trace-verification")
    except Exception as exc:
        return Verdict("rejected", "cryptographic-or-input-rejection:" + type(exc).__name__)

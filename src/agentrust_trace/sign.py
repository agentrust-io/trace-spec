"""Signing utilities for TRACE Trust Records.

Produces a signed record dict with an embedded ``signature`` field --
Ed25519 over the canonical JSON of the record with the signature field absent.
This is the same convention used by cMCP RuntimeClaim and verified by
trace-tests TR-SIG at all conformance levels.
"""

from __future__ import annotations

import base64
import binascii
import os
import warnings
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_key() -> Ed25519PrivateKey:
    """Generate a new Ed25519 signing key."""
    return Ed25519PrivateKey.generate()


def load_key(pem: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM string."""
    return serialization.load_pem_private_key(pem.encode(), password=None)  # type: ignore[return-value]


def load_signing_key() -> Ed25519PrivateKey:
    """Load key from ``TRACE_PRIVATE_KEY_PEM`` env var, or generate an ephemeral one.

    Emits a warning when falling back to an ephemeral key so callers notice
    that the resulting records cannot be re-verified after the process exits.
    """
    pem = os.environ.get("TRACE_PRIVATE_KEY_PEM")
    if pem:
        return load_key(pem)
    warnings.warn(
        "TRACE_PRIVATE_KEY_PEM not set -- generating ephemeral Ed25519 key. "
        "The signed record cannot be re-verified after this process exits. "
        "Set TRACE_PRIVATE_KEY_PEM to a persistent PEM for production use.",
        stacklevel=2,
    )
    return generate_key()


def key_to_jwk(key: Ed25519PrivateKey) -> dict[str, str]:
    """Return the public JWK dict for *key* (OKP / Ed25519)."""
    pub = key.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def _canonical_bytes(d: dict[str, Any]) -> bytes:
    """Return the RFC 8785 (JCS) canonical UTF-8 byte sequence for *d*.

    This is the signature pre-image mandated by spec/trace-v0.1.md §3.2.2. JCS
    sorts object keys by UTF-16 code unit, serializes numbers per the
    ECMAScript Number-to-String / RFC 8785 §3.2.2.3 shortest round-trip form,
    escapes only the characters required by RFC 8259 §7, and emits non-ASCII
    characters as raw UTF-8 (not ``\\uXXXX`` escapes). A plain
    ``json.dumps(sort_keys=True)`` diverges from JCS for non-ASCII strings and
    for IEEE 754 number formatting, which would break cross-implementation
    verification, so a conformant library is used instead.
    """
    return rfc8785.dumps(d)


def _b64url_decode(value: str, *, field: str) -> bytes:
    """Decode an unpadded base64url string, raising ValueError on malformed input.

    Restores the padding the encoder stripped and surfaces ``binascii`` decode
    failures as ``ValueError`` so callers see one consistent failure type.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64url string")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} is not valid base64url: {exc}") from exc


def sign_record(record: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """Return a copy of *record* with ``cnf.jwk`` populated and a ``signature`` field added.

    The signature is Ed25519 over the canonical JSON (sorted keys, no whitespace)
    of the record with the ``signature`` field absent. ``cnf.jwk`` is set to the
    public key derived from *key*.

    The returned dict is a plain JSON-serialisable object. Pass it to
    ``json.dumps()`` to get the wire form, or to ``TrustRecord.model_validate()``
    to confirm structural validity before writing.
    """
    jwk = key_to_jwk(key)
    payload: dict[str, Any] = {**record, "cnf": {"jwk": jwk}}
    body = _canonical_bytes({k: v for k, v in payload.items() if k != "signature"})
    sig_bytes = key.sign(body)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
    return {**payload, "signature": sig_b64}


def _pubkey_from_jwk(jwk: dict[str, Any]) -> Any:
    """Reconstruct an Ed25519 public key from a JWK, rejecting other key types.

    Asserts ``kty == "OKP"`` and ``crv == "Ed25519"`` before building the key so
    that, for example, an EC key is never silently treated as Ed25519.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    kty = jwk.get("kty")
    crv = jwk.get("crv")
    if kty != "OKP":
        raise ValueError(f"unsupported JWK kty {kty!r}; expected 'OKP' for Ed25519")
    if crv != "Ed25519":
        raise ValueError(f"unsupported JWK crv {crv!r}; expected 'Ed25519'")

    x_b64 = jwk.get("x")
    if not x_b64:
        raise ValueError("JWK missing 'x' field")
    x_bytes = _b64url_decode(x_b64, field="JWK 'x'")
    return Ed25519PublicKey.from_public_bytes(x_bytes)


def verify_record(
    record: dict[str, Any],
    public_key_or_jwk: Any = None,
    *,
    allow_embedded_key: bool = False,
    max_age_seconds: int | None = 86400,
    expected_nonce: str | None = None,
) -> None:
    """Verify an Ed25519 signature on a signed TRACE Trust Record.

    A trusted key is REQUIRED. Pass an ``Ed25519PublicKey`` or a JWK dict via
    *public_key_or_jwk* to verify against a key the caller already trusts.

    Raises ``InvalidSignature`` if the signature does not verify, and ``ValueError``
    for every other rejection (no signature, no trusted key, malformed input,
    unsupported JWK type, stale record, or nonce mismatch). Returns ``None`` on
    success. All checks fail closed.

    Trust anchoring (fail closed):
        Without a trusted key, the record cannot vouch for itself, so verification
        is refused. Set ``allow_embedded_key=True`` to opt in to verifying against
        ``record["cnf"]["jwk"]`` — this only proves internal consistency, not
        authenticity, and emits a loud ``UserWarning``.

    Freshness (fail closed):
        ``max_age_seconds`` (default 86400 = 24h) bounds how old ``record["iat"]``
        may be relative to now; pass ``None`` to disable the age check. If
        ``expected_nonce`` is given, it is compared in constant time against
        ``record["runtime"]["nonce"]``. A stale record or nonce mismatch raises
        ``ValueError``.
    """
    import time
    from hmac import compare_digest

    from cryptography.exceptions import InvalidSignature as _InvalidSignature  # noqa: F401

    sig_b64 = record.get("signature")
    if not sig_b64:
        raise ValueError("record has no 'signature' field")

    sig_bytes = _b64url_decode(sig_b64, field="signature")

    # Resolve the trusted public key. A trusted key is required: a record cannot
    # authenticate itself with the key it embeds.
    if public_key_or_jwk is None:
        if not allow_embedded_key:
            raise ValueError(
                "verify_record requires a trusted key. Pass an Ed25519PublicKey or "
                "JWK dict, or set allow_embedded_key=True to (insecurely) trust the "
                "key embedded in record.cnf.jwk."
            )
        jwk = record.get("cnf", {}).get("jwk", {})
        if not jwk:
            raise ValueError("record has no cnf.jwk and no public key was supplied")
        warnings.warn(
            "verify_record is trusting the key embedded in record.cnf.jwk "
            "(allow_embedded_key=True). This proves the record is internally "
            "consistent, NOT that it came from a trusted issuer. Verify against a "
            "pinned trusted key in production.",
            UserWarning,
            stacklevel=2,
        )
        public_key_or_jwk = jwk

    if isinstance(public_key_or_jwk, dict):
        pub = _pubkey_from_jwk(public_key_or_jwk)
    else:
        pub = public_key_or_jwk

    # Freshness: bound the age of the record against its issued-at timestamp.
    if max_age_seconds is not None:
        iat = record.get("iat")
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            raise ValueError("record has no valid integer 'iat' for freshness check")
        age = time.time() - iat
        if age > max_age_seconds:
            raise ValueError(
                f"record is stale: iat is {int(age)}s old, exceeds max_age_seconds="
                f"{max_age_seconds}"
            )

    # Freshness: bind to a caller-supplied nonce when provided.
    if expected_nonce is not None:
        actual_nonce = record.get("runtime", {}).get("nonce")
        if not isinstance(actual_nonce, str) or not compare_digest(actual_nonce, expected_nonce):
            raise ValueError("record runtime.nonce does not match expected_nonce")

    # Canonical bytes: record without "signature" key
    record_no_sig = {k: v for k, v in record.items() if k != "signature"}
    msg = _canonical_bytes(record_no_sig)

    pub.verify(sig_bytes, msg)  # raises InvalidSignature on failure

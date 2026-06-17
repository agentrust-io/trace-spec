"""Signing utilities for TRACE Trust Records.

Produces a signed record dict with an embedded ``signature`` field --
Ed25519 over the canonical JSON of the record with the signature field absent.
This is the same convention used by cMCP RuntimeClaim and verified by
trace-tests TR-SIG at all conformance levels.
"""

from __future__ import annotations

import base64
import json
import os
import warnings
from typing import Any

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
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


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

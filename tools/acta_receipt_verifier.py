#!/usr/bin/env python3
"""Verify Acta decision receipts (draft-farley-acta-signed-receipts-03).

These are the checks ``tests/test_acta_fixtures.py`` applies to the fixtures in
``examples/action-receipts/acta/``, kept in one place so that the fixture tests,
the unit tests in ``tests/test_acta_receipt_verifier.py`` and anyone holding a
single receipt run the same code. A receipt is checked in this order:

1. Section 6.6: the envelope's ``payload`` must not carry a ``signature``
   member, whatever its value, because the signing input would then contain a
   signature. Code ``signature_in_signing_input``.
2. Sections 5.6 and 6.6: ``signature.sig`` is a PureEdDSA (Ed25519) signature
   over the RFC 8785 (JCS) bytes of ``payload``, with no pre-hash, under the key
   that an external key set resolves for ``signature.kid``. The key is never
   read from the receipt. Code ``signature_invalid``.
3. Section 9.2: when the key set gives the key a ``valid_from`` or
   ``valid_until``, ``payload.issued_at`` must fall inside the window, which
   includes ``valid_from`` and excludes ``valid_until``. Code
   ``key_outside_validity_window``.
4. Section 6.7: ``previousReceiptHash`` is ``"sha256:"`` followed by the
   lowercase hex SHA-256 of the JCS bytes of the whole predecessor envelope. A
   prefix naming another algorithm is refused (code
   ``unsupported_chain_hash_algorithm``). The bare hex digest that revision 02
   used, and that fixtures 02 and 04 carry, is accepted, as Section 6.7 allows.
   When the predecessor is known, a link that does not name it, or a missing
   link, is refused (code ``chain_link_mismatch``).

Only the envelope shape of Section 6.6 is supported; a flat-shape receipt is
reported as undecidable. Key revocation (``revoked_at``) is not read: no
revision of the draft defines it.

Command line, one receipt per call::

    acta_receipt_verifier.py <receipt.json>

``AEV_RECEIPT_JWKS`` names a JWK Set holding the Ed25519 issuer keys (``kty``
``OKP``, ``crv`` ``Ed25519``). ``AEV_RECEIPT_CONTEXT``, when set, names a JSON
object whose ``chain`` lists the paths of the receipts before this one, first to
last. The answer is given twice and the two always agree: the exit status (0
valid, 1 invalid, 2 undecidable) and a last stdout line
``{"verdict": ..., "code": ...}``. Undecidable means the check could not run: no
key for the ``kid``, a key or algorithm other than Ed25519, or a receipt that is
not an Acta envelope.

Uses only dependencies this project already declares: rfc8785 and cryptography.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXIT_STATUS = {"valid": 0, "invalid": 1, "undecidable": 2}
CHAIN_HASH_PREFIX = "sha256:"

Verdict = tuple[str, str | None]


class Undecidable(Exception):
    """The receipt cannot be checked; the message is the reason code."""


@dataclass(frozen=True)
class IssuerKey:
    """An Ed25519 issuer key and the validity window its key set publishes."""

    public_key: Ed25519PublicKey
    valid_from: datetime | None = None
    valid_until: datetime | None = None


def jcs(obj: Any) -> bytes:
    """The RFC 8785 canonical bytes of ``obj``."""
    data = rfc8785.dumps(obj)
    return data if isinstance(data, bytes) else data.encode()


def envelope_hash(envelope: Any) -> str:
    """Lowercase hex SHA-256 over the JCS bytes of a whole envelope."""
    return hashlib.sha256(jcs(envelope)).hexdigest()


def signature_verifies(envelope: dict[str, Any], key: Ed25519PublicKey) -> bool:
    """Whether ``signature.sig`` is PureEdDSA over JCS(``payload``) under ``key``."""
    try:
        key.verify(bytes.fromhex(envelope["signature"]["sig"]), jcs(envelope["payload"]))
    except (InvalidSignature, ValueError):
        return False
    return True


def chain_link_matches(link: Any, predecessor: Any) -> bool:
    """Whether ``link`` names ``predecessor`` in either encoding Section 6.7 accepts."""
    digest = envelope_hash(predecessor)
    return link in (CHAIN_HASH_PREFIX + digest, digest)


def _instant(value: Any) -> datetime:
    if not isinstance(value, str):
        raise Undecidable("malformed")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Undecidable("malformed") from exc
    if instant.tzinfo is None:
        raise Undecidable("malformed")
    return instant


def _link_names_unknown_algorithm(link: Any) -> bool:
    """Whether ``link`` carries an algorithm prefix other than ``sha256:``."""
    return isinstance(link, str) and ":" in link and not link.startswith(CHAIN_HASH_PREFIX)


def _envelope_parts(envelope: Any) -> tuple[dict[str, Any], str]:
    """Return ``payload`` and ``kid``, or raise Undecidable if this is no Acta envelope."""
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise Undecidable("not_an_envelope")
    payload, signature = envelope["payload"], envelope["signature"]
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise Undecidable("not_an_envelope")
    if signature.get("alg") != "EdDSA":
        raise Undecidable("unsupported_algorithm")
    kid, sig = signature.get("kid"), signature.get("sig")
    if not isinstance(kid, str) or not isinstance(sig, str):
        raise Undecidable("malformed")
    return payload, kid


def verify_envelope(envelope: Any, key: IssuerKey, predecessor: Any = None) -> Verdict:
    """Return ``(verdict, code)`` for one envelope, its issuer key and its predecessor."""
    try:
        payload, _ = _envelope_parts(envelope)
        if "signature" in payload:
            return "invalid", "signature_in_signing_input"
        if not signature_verifies(envelope, key.public_key):
            return "invalid", "signature_invalid"
        if key.valid_from is not None or key.valid_until is not None:
            issued_at = _instant(payload.get("issued_at"))
            if key.valid_from is not None and issued_at < key.valid_from:
                return "invalid", "key_outside_validity_window"
            if key.valid_until is not None and issued_at >= key.valid_until:
                return "invalid", "key_outside_validity_window"
    except Undecidable as exc:
        return "undecidable", str(exc)

    link = payload.get("previousReceiptHash")
    if _link_names_unknown_algorithm(link):
        return "invalid", "unsupported_chain_hash_algorithm"
    if predecessor is not None and not chain_link_matches(link, predecessor):
        return "invalid", "chain_link_mismatch"
    return "valid", None


def issuer_key(jwks: Any, kid: str) -> IssuerKey:
    """Resolve ``kid`` in a JWK Set, with the key's validity window if it has one."""
    entries = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(entries, list):
        raise Undecidable("malformed_key_set")
    jwk = next((k for k in entries if isinstance(k, dict) and k.get("kid") == kid), None)
    if jwk is None:
        raise Undecidable("unknown_kid")
    x = jwk.get("x")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(x, str):
        raise Undecidable("unsupported_key")
    try:
        public = Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
        )
    except (binascii.Error, ValueError) as exc:
        raise Undecidable("malformed_key_set") from exc
    return IssuerKey(
        public_key=public,
        valid_from=_instant(jwk["valid_from"]) if "valid_from" in jwk else None,
        valid_until=_instant(jwk["valid_until"]) if "valid_until" in jwk else None,
    )


def _read_json(path: str | os.PathLike[str]) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise Undecidable("malformed") from exc


def _predecessor(context_path: str | None) -> Any:
    """The envelope just before this receipt in the presented chain, or None."""
    if not context_path:
        return None
    context = _read_json(context_path)
    chain = context.get("chain") if isinstance(context, dict) else None
    if not chain:
        return None
    if not isinstance(chain, list) or not isinstance(chain[-1], str):
        raise Undecidable("malformed_context")
    return _read_json(chain[-1])


def verify_file(receipt_path: str) -> Verdict:
    """Verify one receipt file, with the key set and context the environment names."""
    try:
        envelope = _read_json(receipt_path)
        _, kid = _envelope_parts(envelope)
        jwks_path = os.environ.get("AEV_RECEIPT_JWKS")
        if not jwks_path:
            raise Undecidable("no_key_set")
        key = issuer_key(_read_json(jwks_path), kid)
        predecessor = _predecessor(os.environ.get("AEV_RECEIPT_CONTEXT"))
    except Undecidable as exc:
        return "undecidable", str(exc)
    return verify_envelope(envelope, key, predecessor)


def main(argv: list[str]) -> int:
    verdict, code = verify_file(argv[0]) if len(argv) == 1 else ("undecidable", "usage")
    print(json.dumps({"verdict": verdict, "code": code}))
    return EXIT_STATUS[verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

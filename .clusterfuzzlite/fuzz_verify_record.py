#!/usr/bin/python3
"""Fuzz ``sign.verify_record``, the Trust Record verifier.

Input: one mode byte, then JSON text. The JSON is the record as a verifier
receives it. With mode bit 0 set, the record is first signed with the pinned
key, so the fuzzer reaches the checks that only run after the schema gate and
the signature (freshness, nonce, revocation, citation resolution) instead of
stopping at ``InvalidSignature`` every time.

Property: ``verify_record`` documents ``InvalidSignature`` for a bad signature
and ``ValueError`` for every other refusal. Anything else escaping is a caller
written against that contract crashing on untrusted bytes. A successful return
must carry the profile the verifier was configured to accept.
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agentrust_trace.sign import (
        DEFAULT_ACCEPTED_PROFILES,
        key_to_jwk,
        sign_record,
        verify_record,
    )

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TRUSTED_JWK = key_to_jwk(KEY)
NOW = 1_785_000_000


def _resolver(uri: str) -> bytes:
    if len(uri) % 3 == 0:
        raise OSError("unreachable")
    return uri.encode("utf-8", "surrogatepass")


def _revocation(identifier: str) -> bool:
    return identifier.startswith("revoked")


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, body = data[0], data[1:]
    try:
        record = json.loads(body)
    except (ValueError, RecursionError):
        # Parsing is the caller's step, not the verifier's.
        return
    if mode & 1 and isinstance(record, dict):
        try:
            record = sign_record(record, KEY)
        except ValueError:
            return
    try:
        result = verify_record(
            record,
            TRUSTED_JWK,
            now=NOW,
            max_age_seconds=None if mode & 2 else 86400 * 3650,
            expected_nonce="n-0" if mode & 4 else None,
            revocation=_revocation if mode & 8 else None,
            citation_resolver=_resolver if mode & 16 else None,
        )
    except (ValueError, InvalidSignature):
        return
    assert result.profile in DEFAULT_ACCEPTED_PROFILES, result.profile


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

#!/usr/bin/python3
"""Fuzz ``revocation.check_bundle``, the revocation-bundle consumer.

Input: one mode byte, then JSON text for the bundle. With mode bit 0 set the
bundle is signed with the pinned bundle key first, so the fuzzer reaches the
statement and time checks behind the signature.

Property: a bundle the verifier cannot use is reported as an outcome, never
raised, and the one documented raise is ``ValueError`` for a statement naming
the trusted key. Any other exception is a bundle crashing the verifier. A
``verified`` outcome must only be reachable through a bundle signed by the
trusted key.
"""

import base64
import json
import sys

import atheris

with atheris.instrument_imports():
    import rfc8785
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agentrust_trace.revocation import check_bundle
    from agentrust_trace.sign import jwk_thumbprint, key_to_jwk

BUNDLE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
BUNDLE_JWK = key_to_jwk(BUNDLE_KEY)
BUNDLE_KID = jwk_thumbprint(BUNDLE_JWK)
RECORD_KEY_ID = "record-key-1"
NOW = 1_785_000_000
OUTCOMES = {"verified", "unverified_for_revocation"}


def _sign(bundle: dict) -> dict:
    bundle = {**bundle, "bundle_key_id": BUNDLE_KID}
    unsigned = {k: v for k, v in bundle.items() if k != "sig"}
    value = base64.urlsafe_b64encode(BUNDLE_KEY.sign(rfc8785.dumps(unsigned)))
    return {**bundle, "sig": {"alg": "ed25519", "value": value.rstrip(b"=").decode()}}


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, body = data[0], data[1:]
    try:
        bundle = json.loads(body)
    except (ValueError, RecursionError):
        return
    signed = False
    if mode & 1 and isinstance(bundle, dict):
        try:
            bundle = _sign(bundle)
            signed = True
        except (ValueError, RecursionError):
            return
    try:
        check = check_bundle(
            bundle,
            trusted_key_identifiers=[RECORD_KEY_ID],
            trusted_bundle_keys=[BUNDLE_JWK],
            now=NOW,
            max_bundle_age_seconds=86400,
            max_future_skew_seconds=300,
        )
    except ValueError:
        return
    assert check.outcome in OUTCOMES, check.outcome
    if check.outcome == "verified":
        assert signed or bundle.get("bundle_key_id") == BUNDLE_KID, bundle
        json.dumps(check.evidence)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

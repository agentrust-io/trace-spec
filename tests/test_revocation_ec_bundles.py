"""Verification of ES256 (P-256) and ES384 (P-384) revocation bundles."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from agentrust_trace import verify_record
from agentrust_trace.revocation import check_bundle
from agentrust_trace.sign import jwk_thumbprint

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples" / "revocation-bundle"
SEED = hashlib.sha256(b"trace-spec revocation-bundle fixture key").digest()
NOW = 1785000000
MAX_AGE = 86400
SKEW = 300
LOG = "https://log.example/trace"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ec_key(label: str, crv: str) -> ec.EllipticCurvePrivateKey:
    if crv == "P-256":
        d = int.from_bytes(hashlib.sha256(SEED + b"|" + label.encode()).digest(), "big")
        return ec.derive_private_key(d, ec.SECP256R1())
    d = int.from_bytes(hashlib.sha384(SEED + b"|" + label.encode()).digest(), "big")
    return ec.derive_private_key(d, ec.SECP384R1())


def _ec_jwk(key: ec.EllipticCurvePrivateKey, crv: str) -> dict[str, str]:
    size = 32 if crv == "P-256" else 48
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": crv,
        "x": _b64u(numbers.x.to_bytes(size, "big")),
        "y": _b64u(numbers.y.to_bytes(size, "big")),
    }


def _sign_ec_bundle(
    body: dict[str, Any],
    key: ec.EllipticCurvePrivateKey,
    alg: str,
    *,
    der_encoded: bool = False,
) -> dict[str, Any]:
    size = 32 if alg == "ES256" else 48
    hash_alg: hashes.HashAlgorithm = (
        hashes.SHA256() if alg == "ES256" else hashes.SHA384()
    )
    der = key.sign(
        rfc8785.dumps(body), ec.ECDSA(hash_alg, deterministic_signing=True)
    )
    if der_encoded:
        sig_bytes = der
    else:
        r, s = utils.decode_dss_signature(der)
        sig_bytes = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    return {**body, "sig": {"alg": alg, "value": _b64u(sig_bytes)}}


def _load_vector(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((VECTORS / name).read_text(encoding="utf-8"))
    return data


def _fresh_ec_fixture(alg: str, crv: str) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    doc = _load_vector("01-fresh-well-inside-both-bounds.json")
    priv = _ec_key(f"bundler-{alg.lower()}", crv)
    pub_jwk = _ec_jwk(priv, crv)
    body = {
        "type": "TraceRevocationBundle/1.0",
        "log_id": LOG,
        "issued_at": NOW - 3600,
        "valid_until": NOW + MAX_AGE,
        "statements": [],
        "bundle_key_id": jwk_thumbprint(pub_jwk),
    }
    signed_bundle = _sign_ec_bundle(body, priv, alg)
    return doc, pub_jwk, signed_bundle


@pytest.mark.parametrize(
    ("alg", "crv", "vector_name"),
    [
        ("ES256", "P-256", "29-es256-bundle-verified.json"),
        ("ES384", "P-384", "30-es384-bundle-verified.json"),
    ],
)
def test_ec_bundles_verify_via_verify_record_and_check_bundle(
    alg: str, crv: str, vector_name: str
) -> None:
    doc, pub_jwk, signed_bundle = _fresh_ec_fixture(alg, crv)
    ctx = doc["context"]
    committed = VECTORS / vector_name
    if committed.is_file():
        vec = _load_vector(vector_name)
        assert vec["context"]["bundle"] == signed_bundle
        assert vec["context"]["trusted_bundle_keys"] == [pub_jwk]

    result = verify_record(
        doc["records"][0],
        ctx["trusted_key"],
        now=ctx["now"],
        max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
        max_future_skew_seconds=ctx["max_future_skew_seconds"],
        revocation_bundle=signed_bundle,
        trusted_bundle_keys=[pub_jwk],
    )
    assert result.revocation.outcome == "verified"
    assert result.revocation.cause is None
    assert result.revocation.evidence["statements_count"] == 0

    direct = check_bundle(
        signed_bundle,
        trusted_key_identifiers=[jwk_thumbprint(ctx["trusted_key"])],
        trusted_bundle_keys=[pub_jwk],
        now=ctx["now"],
        max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
        max_future_skew_seconds=ctx["max_future_skew_seconds"],
    )
    assert direct == result.revocation


@pytest.mark.parametrize(
    ("alg", "crv"),
    [
        ("ES256", "P-256"),
        ("ES384", "P-384"),
    ],
)
def test_ec_bundle_with_statement_naming_record_key_rejects_record(
    alg: str, crv: str
) -> None:
    doc = _load_vector("11-statement-names-trusted-key-by-thumbprint.json")
    ctx = doc["context"]
    ec_priv = _ec_key(f"revoking-{alg}", crv)
    ec_pub_jwk = _ec_jwk(ec_priv, crv)
    body = {k: v for k, v in ctx["bundle"].items() if k != "sig"}
    body["bundle_key_id"] = jwk_thumbprint(ec_pub_jwk)
    signed_bundle = _sign_ec_bundle(body, ec_priv, alg)

    with pytest.raises(ValueError, match="signing key is revoked"):
        verify_record(
            doc["records"][0],
            ctx["trusted_key"],
            now=ctx["now"],
            max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
            max_future_skew_seconds=ctx["max_future_skew_seconds"],
            revocation_bundle=signed_bundle,
            trusted_bundle_keys=[ec_pub_jwk],
        )

    with pytest.raises(ValueError, match="signing key is revoked"):
        check_bundle(
            signed_bundle,
            trusted_key_identifiers=[jwk_thumbprint(ctx["trusted_key"])],
            trusted_bundle_keys=[ec_pub_jwk],
            now=ctx["now"],
            max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
            max_future_skew_seconds=ctx["max_future_skew_seconds"],
        )


@pytest.mark.parametrize(
    ("alg", "crv"),
    [
        ("ES256", "P-256"),
        ("ES384", "P-384"),
    ],
)
def test_corrupted_tampered_or_der_ec_signatures_report_bundle_signature_invalid(
    alg: str, crv: str
) -> None:
    doc, pub_jwk, base_bundle = _fresh_ec_fixture(alg, crv)
    ctx = doc["context"]
    trusted_ids = [jwk_thumbprint(ctx["trusted_key"])]

    # 1. Flipped first character of sig.value.
    corrupted = copy.deepcopy(base_bundle)
    sig_val = corrupted["sig"]["value"]
    corrupted["sig"]["value"] = ("A" if sig_val[0] != "A" else "B") + sig_val[1:]

    # 2. Tampered payload (valid_until extended after signing).
    tampered = copy.deepcopy(base_bundle)
    tampered["valid_until"] += 3600

    # 3. ASN.1 DER signature instead of fixed-width IEEE P1363 r || s.
    ec_priv = _ec_key(f"bundler-{alg.lower()}", crv)
    unsigned_body = {k: v for k, v in base_bundle.items() if k != "sig"}
    der_bundle = _sign_ec_bundle(unsigned_body, ec_priv, alg, der_encoded=True)

    # 4. Wrong raw byte length (32 bytes instead of 64/96).
    short_sig = copy.deepcopy(base_bundle)
    short_sig["sig"]["value"] = _b64u(b"\x01" * 32)

    for candidate in (corrupted, tampered, der_bundle, short_sig):
        check = check_bundle(
            candidate,
            trusted_key_identifiers=trusted_ids,
            trusted_bundle_keys=[pub_jwk],
            now=NOW,
            max_bundle_age_seconds=MAX_AGE,
            max_future_skew_seconds=SKEW,
        )
        assert check.outcome == "unverified_for_revocation"
        assert check.cause == "bundle_signature_invalid"
        assert check.evidence["bundle_key_id"] == candidate["bundle_key_id"]


def test_key_algorithm_mismatches_report_bundle_signature_unsupported() -> None:
    doc01 = _load_vector("01-fresh-well-inside-both-bounds.json")
    _, p256_key, b29 = _fresh_ec_fixture("ES256", "P-256")
    _, p384_key, b30 = _fresh_ec_fixture("ES384", "P-384")

    okp_key = doc01["context"]["trusted_bundle_keys"][0]
    secp256k1_key = {**p256_key, "crv": "secp256k1"}

    cases: list[tuple[dict[str, Any], dict[str, str], str]] = [
        # OKP key paired with ES256 and ES384
        (b29, okp_key, "ES256"),
        (b30, okp_key, "ES384"),
        # P-256 key paired with ES384, and P-384 key paired with ES256
        (b30, p256_key, "ES384"),
        (b29, p384_key, "ES256"),
        # EC key paired with ed25519
        (doc01["context"]["bundle"], p256_key, "ed25519"),
        # Unsupported EC curve paired with ES256
        (b29, secp256k1_key, "ES256"),
    ]

    for template_bundle, mismatched_jwk, expected_alg in cases:
        b = copy.deepcopy(template_bundle)
        b["bundle_key_id"] = jwk_thumbprint(mismatched_jwk)
        check = check_bundle(
            b,
            trusted_key_identifiers=["issuer-key-2026"],
            trusted_bundle_keys=[mismatched_jwk],
            now=NOW,
            max_bundle_age_seconds=MAX_AGE,
            max_future_skew_seconds=SKEW,
        )
        assert check.outcome == "unverified_for_revocation"
        assert check.cause == "bundle_signature_unsupported"
        assert check.evidence["alg"] == expected_alg


def test_off_curve_and_malformed_ec_coordinates_report_bundle_signature_unsupported() -> None:
    _, valid_p256, b29 = _fresh_ec_fixture("ES256", "P-256")

    one_32 = _b64u((1).to_bytes(32, "big"))
    short_16 = _b64u((1).to_bytes(16, "big"))
    padded_coord = valid_p256["x"] + "="

    bad_keys = [
        # (1, 1) is not on P-256
        {"kty": "EC", "crv": "P-256", "x": one_32, "y": one_32},
        # Wrong byte length for x or y
        {"kty": "EC", "crv": "P-256", "x": short_16, "y": valid_p256["y"]},
        {"kty": "EC", "crv": "P-256", "x": valid_p256["x"], "y": short_16},
        # Non-canonical base64url in coordinate
        {"kty": "EC", "crv": "P-256", "x": padded_coord, "y": valid_p256["y"]},
    ]

    for bad_jwk in bad_keys:
        b = copy.deepcopy(b29)
        b["bundle_key_id"] = jwk_thumbprint(bad_jwk)
        check = check_bundle(
            b,
            trusted_key_identifiers=["issuer-key-2026"],
            trusted_bundle_keys=[bad_jwk],
            now=NOW,
            max_bundle_age_seconds=MAX_AGE,
            max_future_skew_seconds=SKEW,
        )
        assert check.outcome == "unverified_for_revocation"
        assert check.cause == "bundle_signature_unsupported"
        assert check.evidence["alg"] == "ES256"

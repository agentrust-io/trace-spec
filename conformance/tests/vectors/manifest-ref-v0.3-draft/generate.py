"""Regenerate the v0.3 draft manifest-reference fixtures (trace-spec#483) without importing the
verifier under test.

Shape under test: an optional signed top-level ``manifest {id, digest, media_type}`` naming the
agent manifest the record ran under. Records are v0.2 records signed embedded per §3.2.2:
Ed25519 over RFC 8785 of the record with ``signature`` absent, base64url without padding, key in
``cnf.jwk``. The signing key is a PUBLIC TEST KEY derived from a fixed seed; never use it for
anything else.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).parent
SEED = hashlib.sha256(b"trace-manifest-ref-v0 test key").digest()
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
MID = "urn:example:agent-manifest:payments-agent"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def digest(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def manifest(version: str, tools: list[str]) -> str:
    return json.dumps(
        {"manifest_id": MID, "version": version, "tools": tools, "model_id": "example-model-1"},
        separators=(",", ":"),
    )


# Two manifests served under the same id: the deployment the record ran under, and a later one.
M_RAN = manifest("1.4.0", ["refund", "lookup_payment"])
M_LATER = manifest("1.5.0", ["refund", "lookup_payment", "wire_transfer"])

BASE = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1785000000,
    "subject": "spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "example-provider", "model_id": "example-model-1"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(PUB)}},
}
REF = {"id": MID, "digest": digest(M_RAN.encode()), "media_type": "application/json"}


def sign(rec: dict) -> dict:
    r = copy.deepcopy(rec)
    r.pop("signature", None)
    r["signature"] = b64u(KEY.sign(rfc8785.dumps(r)))
    return r


def with_manifest(**extra) -> dict:
    return {**copy.deepcopy(BASE), "manifest": dict(REF), **extra}


def vectors() -> list[dict]:
    added_after = sign(BASE)
    added_after["manifest"] = dict(REF)
    cases = [
        (
            "01-digest-matches",
            sign(with_manifest()),
            {MID: M_RAN},
            "valid",
            "established",
            "the signed digest equals sha256 of the manifest bytes the verifier resolved",
        ),
        (
            "02-digest-mismatch",
            sign(with_manifest()),
            {MID: M_LATER},
            "valid",
            "manifest-digest-mismatch",
            "the id now resolves to a later deployment (1.5.0 adds wire_transfer); "
            "the record ran under 1.4.0",
        ),
        (
            "03-mismatch-with-asserted-result",
            sign(with_manifest(manifest_verification_result="verified")),
            {MID: M_LATER},
            "valid",
            "manifest-digest-mismatch",
            "the producer also signed manifest_verification_result=verified; "
            "the verifier recomputes and does not carry it",
        ),
        (
            "04-unresolvable",
            sign(with_manifest()),
            {},
            "valid",
            "manifest-unresolved",
            "not a pass, and not a reason to reject the record "
            "(the §3.1.2 rule 3 posture for pointers)",
        ),
        (
            "05-added-after-signing",
            added_after,
            {MID: M_RAN},
            "signature-invalid",
            "not-evaluated",
            "manifest is outside the signed bytes; §3.3 step 1 fails before any field is trusted",
        ),
        (
            "06-control-no-manifest",
            sign(BASE),
            {MID: M_RAN},
            "valid",
            "no-manifest-named",
            "a v0.2 record with no manifest object verifies as today and names no deployment",
        ),
    ]
    return [
        {
            "name": n,
            "status": "v0.3-draft",
            "proposal": "agentrust-io/trace-spec#483",
            "record": rec,
            "resolver": res,
            "expected": {"record": r, "manifest": m},
            "why": why,
        }
        for n, rec, res, r, m, why in cases
    ]


if __name__ == "__main__":
    for v in vectors():
        (HERE / f"{v['name']}.json").write_text(
            json.dumps(v, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline=""
        )

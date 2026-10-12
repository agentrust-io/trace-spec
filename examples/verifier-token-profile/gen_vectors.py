"""Independent deterministic fixture producer; no reference-verifier imports.

Test-only keys. All component appraisals are synthetic software observations.
The generator and consumer share cbor2/rfc8785/cryptography, not validation or
signing-envelope construction. This is not cross-language interoperability.
"""

from __future__ import annotations
import base64
import copy
import hashlib
import json
from pathlib import Path

import cbor2
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

P = Path(__file__).parent
PROFILE = "urn:agentrust:trace:verifier-token:experimental-v1"
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
HOLDER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
ROGUE = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
NOW = 1790683200


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_digest(value: object) -> str:
    return digest(rfc8785.dumps(value))


def envelope(
    payload: dict,
    key: Ed25519PrivateKey,
    *,
    headers: dict | None = None,
    raw: bytes | None = None,
    unprotected: dict | None = None,
) -> bytes:
    protected = cbor2.dumps(
        headers
        or {
            1: -19,
            2: ["trace-profile"],
            3: {
                "urn:agentrust:trace:holder-proof:experimental-v1": (
                    "application/trace-holder-proof+json"
                ),
                "urn:agentrust:trace:decision-receipt:experimental-v1": (
                    "application/trace-decision-receipt+json"
                ),
            }.get(payload["profile"], "application/trace-verifier-token+json"),
            4: hashlib.sha256(public(key)).digest(),
            "trace-profile": payload["profile"],
        },
        canonical=True,
    )
    data = rfc8785.dumps(payload) if raw is None else raw
    preimage = cbor2.dumps(["Signature1", protected, b"", data], canonical=True)
    return cbor2.dumps(
        cbor2.CBORTag(18, [protected, unprotected or {}, data, key.sign(preimage)]), canonical=True
    )


def base() -> dict:
    manifest = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://example.test/agent/one",
        "version": "0.2",
        "issuer": "spiffe://example.test/manifest-issuer",
        "issued_at": "2026-09-29T11:00:00Z",
        "expires_at": "2026-09-30T12:00:00Z",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": "sha256:" + "a" * 64},
            "policy_bundle": {"hash": "sha256:" + "b" * 64},
            "model_identity": {"version": "test-model", "deployment_type": "api"},
        },
    }
    raw = rfc8785.dumps(manifest)
    protected = cbor2.dumps(
        {
            1: -19,
            3: "application/agent-manifest+json",
            4: hashlib.sha256(public(ROGUE)).digest(),
            16: "application/agent-manifest+cose",
        },
        canonical=True,
    )
    signature = ROGUE.sign(cbor2.dumps(["Signature1", protected, b"", raw], canonical=True))
    manifest_bytes = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, raw, signature]), canonical=True)
    policy = {
        "id": "https://verifier.example.test/policy",
        "version": "1",
        "digest": "sha256:" + "c" * 64,
    }
    requirements = {"components": [], "bindings": [], "allow_warnings": False}
    components = []
    for cid, typ in [("runtime.cpu", "runtime"), ("runtime.accelerator.0", "accelerator")]:
        requirements["components"].append(
            {
                "component_id": cid,
                "component_type": typ,
                "required": True,
                "accepted_profiles": ["urn:example:software-evidence:v1"],
                "accepted_authorities": ["https://verifier.example.test"],
                "maximum_age_seconds": 120,
            }
        )
        components.append(
            {
                "component_id": cid,
                "component_type": typ,
                "profile": "urn:example:software-evidence:v1",
                "authority": "https://verifier.example.test",
                "instance": "instance-1",
                "status": "affirming",
                "appraised_at": NOW,
                "fresh_until": NOW + 120,
                "observed_digest": "sha256:" + "d" * 64,
                "reasons": [],
                "evidence_refs": [
                    {
                        "profile": "urn:example:software-evidence:v1",
                        "media_type": "application/example-software-evidence+json",
                        "digest": "sha256:" + "e" * 64,
                        "resolver": None,
                    }
                ],
            }
        )
    br = {
        "source": "runtime.cpu",
        "target": "runtime.accelerator.0",
        "relationship": "same-workload",
        "method": "same-instance-v1",
    }
    requirements["bindings"].append(br)
    binding = dict(
        br,
        status="affirming",
        fresh_until=NOW + 120,
        digest=canonical_digest(
            {"method": "same-instance-v1", "source": components[0], "target": components[1]}
        ),
    )
    token = {
        "profile": PROFILE,
        "iss": "https://verifier.example.test",
        "sub": "spiffe://example.test/agent/one",
        "instance": "instance-1",
        "iat": NOW,
        "exp": NOW + 120,
        "jti": "test-token-1",
        "aud": "spiffe://example.test/gateway/one",
        "cnf": {"kty": "OKP", "crv": "Ed25519", "x": b64(public(HOLDER))},
        "manifest": {
            "id": manifest["manifest_id"],
            "media_type": "application/agent-manifest+cose",
            "version": "0.2",
            "digest": digest(manifest_bytes),
        },
        "verification_context_hash": canonical_digest(
            {
                "purpose": "protected-action",
                "audience": "spiffe://example.test/gateway/one",
                "policy": policy,
                "requirements": requirements,
            }
        ),
        "appraisal_policy": policy,
        "components": components,
        "bindings": [binding],
        "composite_appraisal": {
            "status": "affirming",
            "required_components": sorted(c["component_id"] for c in components),
            "policy": policy,
            "fresh_until": NOW + 120,
        },
    }
    return {
        "token": token,
        "requirements": requirements,
        "manifest_b64": b64(manifest_bytes),
        "issuer_public_b64": b64(public(ISSUER)),
        "holder_public_b64": b64(public(HOLDER)),
        "manifest_public_b64": b64(public(ROGUE)),
        "now": NOW,
        "limits": "Synthetic software-only appraisals; no hardware or Cedar evaluation.",
    }


def write(name: str, value: dict) -> None:
    (P / name).write_bytes((json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode())


def generate() -> None:
    fixture = base()
    token = fixture["token"]
    fixture["envelope_b64"] = b64(envelope(token, ISSUER))
    fixture["canonical_payload_b64"] = b64(rfc8785.dumps(token))
    fixture["expected"] = "valid"
    write("01-valid.json", fixture)
    mutations = [
        ("02-wrong-audience.json", "audience_mismatch", lambda t: t.update(aud="wrong")),
        ("03-wrong-subject.json", "subject_or_instance_mismatch", lambda t: t.update(sub="other")),
        (
            "04-manifest-substitution.json",
            "manifest_mismatch",
            lambda t: t["manifest"].update(digest="sha256:" + "0" * 64),
        ),
        ("05-component-omitted.json", "composite_inconsistent", lambda t: t["components"].pop()),
        (
            "06-failed-as-affirming.json",
            "binding_digest_mismatch",
            lambda t: t["components"][1].update(status="unverifiable"),
        ),
        (
            "07-mixed-instance.json",
            "mixed_instance",
            lambda t: t["components"][1].update(instance="instance-2"),
        ),
        (
            "08-expiry-exceeds-evidence.json",
            "expiry_exceeds_evidence",
            lambda t: t.update(exp=NOW + 121),
        ),
        (
            "09-context-substitution.json",
            "context_mismatch",
            lambda t: t.update(verification_context_hash="sha256:" + "0" * 64),
        ),
        (
            "10-duplicate-component.json",
            "duplicate_component",
            lambda t: t["components"].append(copy.deepcopy(t["components"][0])),
        ),
        (
            "11-binding-substitution.json",
            "binding_digest_mismatch",
            lambda t: t["bindings"][0].update(digest="sha256:" + "0" * 64),
        ),
        (
            "12-signature-extension.json",
            "malformed_payload",
            lambda t: t.update(gateway_decision="allow"),
        ),
    ]
    for name, expected, change in mutations:
        modified = copy.deepcopy(token)
        change(modified)
        write(
            name,
            {
                "envelope_b64": b64(envelope(modified, ISSUER)),
                "expected": expected,
                "signature_valid": True,
            },
        )
    rogue = {
        "envelope_b64": b64(envelope(token, ROGUE)),
        "expected": "issuer_untrusted",
        "signature_valid": True,
    }
    write("13-untrusted-self-signer.json", rogue)
    write(
        "14-v02-as-verifier-token.json",
        {
            "envelope_b64": b64(
                envelope(dict(token, profile="tag:agentrust-io.com,2026:trace-v0.2"), ISSUER)
            ),
            "expected": "protected_headers",
            "signature_valid": True,
        },
    )


if __name__ == "__main__":
    generate()

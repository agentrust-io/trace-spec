"""Offline replay execution from externally pinned retained evidence.

The caller MUST supply the expected SHA-256 of MANIFEST.json out of band.
Never trust a self-supplied manifest checksum as an authority.
"""
import hashlib
import json
from pathlib import Path
from retained_evidence import inspect
from independent_verifier import verify as independent_verify
from agentrust_trace.sign import verify_record
from cryptography.exceptions import InvalidSignature

def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def run(directory, expected_manifest_digest):
    directory = Path(directory)
    if not isinstance(expected_manifest_digest, str) or not expected_manifest_digest.startswith("sha256:"):
        return {"status":"not-established", "reason":"missing-external-manifest-pin"}
    try:
        manifest_bytes = (directory / "MANIFEST.json").read_bytes()
        if sha256(manifest_bytes) != expected_manifest_digest:
            return {"status":"rejected", "reason":"manifest-pin-mismatch"}
        sound, why = inspect(directory)
        if not sound:
            return {"status":"rejected", "reason":why}
        manifest = json.loads(manifest_bytes)
        context = manifest["context"]
        if any(field not in context for field in ("verification_time", "max_age_seconds", "max_future_skew_seconds", "expected_nonce")):
            return {"status":"not-established", "reason":"missing-replay-options"}
        artifacts = {name: (directory / (name + ".bin")).read_bytes()
                     for name in ("record", "trusted_root", "policy", "revocation", "resolver")}
        record = json.loads(artifacts["record"])
        trusted_key = json.loads(artifacts["trusted_root"])
        revoked = json.loads(artifacts["revocation"])
        if not isinstance(revoked, list) or not all(isinstance(item,str) for item in revoked):
            return {"status":"not-established", "reason":"revocation-snapshot-invalid"}
        if record.get("policy", {}).get("bundle_hash") != sha256(artifacts["policy"]):
            return {"status":"rejected", "reason":"signed-policy-digest-mismatch"}
        # A complete replay must bind the exact policy and resolver semantics.
        # Older bundles remain testable as crypto/context only; never upgrade
        # them to a semantic acceptance claim.
        contract = context.get("semantic_contract")
        semantic_status = "not-established"
        if contract is not None:
            if not isinstance(contract, dict) or contract.get("version") != 1:
                return {"status":"not-established", "reason":"unsupported-semantic-contract"}
            if set(contract) != {"version", "enforcement_mode", "policy", "resolver"}:
                return {"status":"not-established", "reason":"incomplete-semantic-contract"}
            policy_semantics = json.loads(artifacts["policy"])
            resolver_semantics = json.loads(artifacts["resolver"])
            if not isinstance(policy_semantics, dict) or not isinstance(resolver_semantics, dict):
                return {"status":"not-established", "reason":"invalid-semantic-documents"}
            # Exact equality is intentional: a replay contract is a snapshot,
            # not a policy language interpreter with implicit defaults.
            if policy_semantics != contract["policy"]:
                return {"status":"rejected", "reason":"policy-semantic-drift"}
            if resolver_semantics != contract["resolver"]:
                return {"status":"rejected", "reason":"resolver-semantic-drift"}
            if record.get("policy", {}).get("enforcement_mode") != contract["enforcement_mode"]:
                return {"status":"rejected", "reason":"enforcement-mode-mismatch"}
            if contract["enforcement_mode"] != "enforce":
                return {"status":"not-established", "reason":"non-enforcing-policy"}
            semantic_status = "exact-snapshot-matched"
        options = {name:context[name] for name in ("verification_time", "max_age_seconds", "max_future_skew_seconds", "expected_nonce")}
        independently = independent_verify(record, trusted_key, **options, revoked_identifiers=revoked)
        try:
            verify_record(record, trusted_key, revocation=set(revoked), **options)
            reference = "verified"
        except (ValueError, InvalidSignature):
            reference = "rejected"
        independent = "verified" if independently.status == "verified-crypto" else independently.status
        if reference != independent:
            return {"status":"not-established", "reason":"verifier-disagreement",
                    "reference":reference, "independent":independent}
        return {"status":"crypto-and-context-verified" if reference == "verified" else "rejected",
                "reason":"matched-bounded-verifiers",
                "reference":reference, "independent":independent,
                "manifest_digest":expected_manifest_digest,
                "scope":"exact-snapshot-equality-only-not-external-authority",
                "semantic_status":semantic_status}
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"status":"not-established", "reason":"bundle-unreadable:" + type(exc).__name__}

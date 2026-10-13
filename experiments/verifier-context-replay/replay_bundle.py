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
                "scope":"not-a-policy-or-resolver-semantic-appraisal"}
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"status":"not-established", "reason":"bundle-unreadable:" + type(exc).__name__}

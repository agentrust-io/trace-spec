"""Fail-closed verifier-owned trust policy for offline simulated attestation.

The policy is OUTSIDE the producer bundle. It must be independently provisioned
and its SHA-256 pinned by the consuming verifier. There is deliberately no
"trust on first use" auto-enrollment or promotion to hardware assurance.
"""

import hashlib
import json
import time
from pathlib import Path

from replay_bundle import run as replay


def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(blob):
    return "sha256:" + hashlib.sha256(blob).hexdigest()


REQUIRED = {
    "format",
    "assurance",
    "source_commit",
    "host",
    "trace_root_digest",
    "policy_digest",
    "resolver_digest",
    "observer_public_digest",
    "ak_public_digest",
    "reference_pcr0",
    "allowed_challenge",
    "max_observation_age_seconds",
    "not_before_unix",
    "not_after_unix",
}


def verify_enrolled(
    bundle,
    manifest_pin,
    *,
    registry_path,
    registry_pin,
    checkquote,
    verification_time,
    operational_now=None,
):
    try:
        if type(verification_time) is not int or verification_time < 0:
            return {"status": "not-established", "reason": "invalid-verification-time"}
        if (
            not isinstance(registry_pin, str)
            or len(registry_pin) != 71
            or not registry_pin.startswith("sha256:")
        ):
            return {
                "status": "not-established",
                "reason": "missing-out-of-band-registry-pin",
            }
        registry_raw = Path(registry_path).read_bytes()
        if digest(registry_raw) != registry_pin:
            return {"status": "rejected", "reason": "verifier-registry-pin-mismatch"}
        registry = json.loads(registry_raw)
        if not isinstance(registry, dict) or set(registry) != REQUIRED:
            return {"status": "not-established", "reason": "invalid-verifier-registry"}
        if (
            registry["format"] != "frequency-verifier-policy-v1"
            or registry["assurance"] != "simulation-only"
        ):
            return {"status": "rejected", "reason": "hardware-claim-forbidden"}
        if (
            type(registry["not_before_unix"]) is not int
            or type(registry["not_after_unix"]) is not int
        ):
            return {"status": "not-established", "reason": "invalid-policy-validity"}
        if (
            not registry["not_before_unix"]
            <= verification_time
            <= registry["not_after_unix"]
        ):
            return {"status": "rejected", "reason": "policy-outside-validity"}
        if (
            type(registry["max_observation_age_seconds"]) is not int
            or not 0 <= registry["max_observation_age_seconds"] <= 3600
        ):
            return {"status": "not-established", "reason": "invalid-freshness-policy"}
        wall_time = int(time.time()) if operational_now is None else operational_now
        if (
            type(wall_time) is not int
            or not 0
            <= wall_time - verification_time
            <= registry["max_observation_age_seconds"]
        ):
            return {"status": "rejected", "reason": "operational-freshness-expired"}
        bundle = Path(bundle)
        manifest = json.loads((bundle / "MANIFEST.json").read_bytes())
        ctx = manifest["context"]
        simulation = ctx["simulation_contract"]
        tpm = simulation["tpm"]
        tee = simulation["tee"]
        record = json.loads((bundle / "record.bin").read_bytes())
        expected = {
            "source_commit": tee.get("expected_commit"),
            "host": tee.get("expected_host"),
            "trace_root_digest": digest((bundle / "trusted_root.bin").read_bytes()),
            "policy_digest": digest((bundle / "policy.bin").read_bytes()),
            "resolver_digest": digest((bundle / "resolver.bin").read_bytes()),
            "observer_public_digest": "sha256:"
            + tee.get("trusted_observer_digest", ""),
            "ak_public_digest": "sha256:" + tpm.get("expected_ak_digest", ""),
            "reference_pcr0": tpm.get("expected_pcr0"),
            "allowed_challenge": tee.get("expected_challenge"),
        }
        for name, value in expected.items():
            if registry[name] != value:
                return {
                    "status": "rejected",
                    "reason": "unauthorized-verifier-input:" + name,
                }
        if record.get("runtime", {}).get("platform") != "software-only":
            return {"status": "rejected", "reason": "unexpected-hardware-runtime"}
        if tee.get("max_age_seconds") > registry["max_observation_age_seconds"]:
            return {"status": "rejected", "reason": "freshness-policy-too-permissive"}
        if tee.get("verification_time") != verification_time:
            return {"status": "rejected", "reason": "verification-time-not-pinned"}
        result = replay(bundle, manifest_pin, tpm2_checkquote=checkquote)
        if result.get("status") != "simulated-evidence-validated":
            return {
                "status": "rejected",
                "reason": "underlying-replay-not-accepted",
                "underlying": result.get("status"),
                "detail": result.get("reason"),
            }
        return {
            "status": "simulation-enrolled-verified",
            "reason": "independent-verifier-policy-and-cryptography",
            "manifest_digest": manifest_pin,
            "registry_digest": registry_pin,
            "scope": "software-simulation-only",
        }
    except (
        OSError,
        TypeError,
        ValueError,
        KeyError,
        AttributeError,
        json.JSONDecodeError,
    ) as error:
        return {
            "status": "not-established",
            "reason": "incomplete-enrollment:" + type(error).__name__,
        }

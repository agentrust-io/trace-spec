"""Process-isolated *software* TEE simulation with explicit low-assurance provenance.

Uses the existing allowlisted captured_observer + Bubblewrap sandbox.
This is NOT SGX, TDX, SEV-SNP, a hardware enclave, or remote attestation.
"""

import hashlib
import time
from captured_observer import capture
from observer_receipt import verify as verify_receipt


def sha(b):
    return hashlib.sha256(b).hexdigest()


def capture_software_tee(
    *, argv, repository, expected_commit, signing_key, host_label, challenge, timeout=30
):
    receipt = capture(
        argv=argv,
        allowed_argv=argv,
        repository=repository,
        expected_commit=expected_commit,
        private_key=signing_key,
        host_label=host_label,
        timeout=timeout,
        isolate_network=True,
        challenge=challenge,
    )
    return {
        "profile": "frequency-software-tee-v1",
        "classification": "SIMULATED_TEE_NO_HARDWARE_ROOT",
        "receipt": receipt,
    }


def verify_software_tee(
    bundle,
    *,
    trusted_observer_public,
    trusted_observer_digest,
    expected_commit,
    expected_executable_digest,
    expected_host,
    expected_command,
    expected_challenge,
    expected_stdout_digest,
    expected_stderr_digest,
    verification_time=None,
    max_age_seconds=300,
):
    try:
        if (
            not isinstance(bundle, dict)
            or bundle.get("profile") != "frequency-software-tee-v1"
            or bundle.get("classification") != "SIMULATED_TEE_NO_HARDWARE_ROOT"
        ):
            return {"status": "rejected", "reason": "hardware-attestation-not-claimed"}
        if sha(trusted_observer_public) != trusted_observer_digest:
            return {"status": "rejected", "reason": "observer-key-not-pinned"}
        receipt = bundle["receipt"]
        if not verify_receipt(receipt, trusted_observer_public):
            return {"status": "rejected", "reason": "invalid-observer-signature"}
        observed = receipt["observation"]
        checks = {
            "commit": expected_commit,
            "executable_sha256": expected_executable_digest,
            "host": expected_host,
            "command": expected_command,
            "network_isolation_requested": True,
            "exit_code": 0,
        }
        if any(observed.get(k) != value for k, value in checks.items()):
            return {"status": "rejected", "reason": "execution-context-mismatch"}
        if (
            not isinstance(expected_challenge, str)
            or len(expected_challenge) < 16
            or observed.get("challenge") != expected_challenge
        ):
            return {"status": "rejected", "reason": "challenge-mismatch"}
        if type(max_age_seconds) is not int or max_age_seconds < 0:
            return {"status": "not-established", "reason": "invalid-freshness-bound"}
        now = int(time.time()) if verification_time is None else verification_time
        issued = observed.get("observed_at_unix")
        if (
            type(now) is not int
            or type(issued) is not int
            or not 0 <= now - issued <= max_age_seconds
        ):
            return {"status": "rejected", "reason": "stale-or-future-observation"}
        import re

        outputs = {
            "stdout_sha256": expected_stdout_digest,
            "stderr_sha256": expected_stderr_digest,
        }
        if any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in outputs.values()
        ):
            return {
                "status": "not-established",
                "reason": "missing-trusted-output-expectations",
            }
        if any(observed.get(name) != value for name, value in outputs.items()):
            return {"status": "rejected", "reason": "execution-output-digest-mismatch"}
        return {
            "status": "verified-simulation-only",
            "reason": "isolated-execution-observed",
            "commit": expected_commit,
            "executable_sha256": expected_executable_digest,
        }
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return {
            "status": "not-established",
            "reason": "invalid-simulation-evidence:" + type(exc).__name__,
        }

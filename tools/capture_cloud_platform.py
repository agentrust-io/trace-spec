"""Capture scoped fresh platform evidence on an isolated Linux confidential VM.

Requires the existing WCM SDK on PYTHONPATH. Does not issue an affirming TRACE:
platform signatures/nonce binding do not establish application launch binding.
Azure capture resets and extends PCR 23; use only a disposable dedicated VM.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path


def capture(platform, *, root_pem, root_sha256, measurement, output):
    from wcm import AzureSnpVtpmProvider, AzureSnpVtpmVerifier, ChallengeStore, TrustStore
    from wcm.tdx import verify_tdx_quote

    root = Path(root_pem).read_bytes()
    if hashlib.sha256(root).hexdigest() != root_sha256:
        raise ValueError("operator-pinned root hash mismatch")
    if (
        not measurement.startswith("sha256:")
        or len(measurement) != 71
        or any(c not in "0123456789abcdef" for c in measurement[7:])
    ):
        raise ValueError("approved SHA-256 measurement required")
    trust = TrustStore()
    trust.add_root_pem(root.decode("ascii"))
    challenge = ChallengeStore().issue()
    # Public random session binding; no production credential is used.
    channel = secrets.token_bytes(32)
    nonce = challenge.nonce
    wrong_nonce = secrets.token_hex(32)
    if platform == "azure-snp":
        evidence = AzureSnpVtpmProvider().cpu_quote(
            challenge, serving_image_measurement=measurement, transport_public_key=channel.hex()
        )
        raw = base64.b64decode(evidence.quote_b64, validate=True)
        verifier = AzureSnpVtpmVerifier(trust)

        def verify(candidate, nonce_, channel_, measurement_):
            return verifier.verify(
                base64.b64encode(candidate).decode(),
                expected_nonce=nonce_,
                channel_binding=channel_,
                expected_workload_measurement=measurement_,
            )

        negative_measurement = verify(raw, nonce, channel, "sha256:" + "0" * 64)
    else:
        directory = Path("/sys/kernel/config/tsm/report") / ("trace-" + secrets.token_hex(12))
        directory.mkdir()
        try:
            (directory / "inblob").write_bytes(
                hashlib.sha256(bytes.fromhex(nonce) + channel).digest() + bytes(32)
            )
            raw = (directory / "outblob").read_bytes()
        finally:
            directory.rmdir()

        def verify(candidate, nonce_, channel_, measurement_):
            return verify_tdx_quote(
                candidate, trust, expected_nonce=nonce_, channel_binding=channel_
            )

        negative_measurement = None  # No application measurement claim on this path.
    positive = verify(raw, nonce, channel, measurement)
    bad_nonce = verify(raw, wrong_nonce, channel, measurement)
    bad_channel = verify(raw, nonce, bytes(32), measurement)
    damaged = bytearray(raw)
    damaged[len(damaged) // 2] ^= 1
    try:
        tampered = verify(bytes(damaged), nonce, channel, measurement)
        tamper_rejected = not tampered.verified
    except (ValueError, KeyError, IndexError, TypeError):
        tamper_rejected = True
    results = {
        "signature_and_freshness": positive.verified,
        "wrong_nonce_rejected": not bad_nonce.verified,
        "wrong_channel_rejected": not bad_channel.verified,
        "tampering_rejected": tamper_rejected,
    }
    if negative_measurement is not None:
        results["wrong_pcr23_measurement_rejected"] = not negative_measurement.verified
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "evidence.bin").write_bytes(raw)
    record = {
        "kind": "trace-scoped-platform-checks/experimental-v1",
        "platform": platform,
        "captured_at": datetime.now(UTC).isoformat(),
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "trusted_root_pem_sha256": root_sha256,
        "nonce": nonce,
        "channel_binding_hex": channel.hex(),
        "approved_measurement": measurement if platform == "azure-snp" else None,
        "checks": results,
        "passed": all(results.values()),
        "positive_reason": positive.reason,
        "limits": [
            "No application execution or independently measured launch binding established.",
            "No complete TCB, revocation, QE identity or collateral appraisal asserted.",
            "Azure PCR 23 is resettable by the guest; it is not an immutable boot root.",
            "Does not prove physical-attack resistance or a CPU/GPU relationship.",
        ],
    }
    (output / "result.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["azure-snp", "gcp-tdx"], required=True)
    parser.add_argument("--root-pem", required=True)
    parser.add_argument("--root-sha256", required=True)
    parser.add_argument("--measurement", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    record = capture(
        args.platform,
        root_pem=args.root_pem,
        root_sha256=args.root_sha256,
        measurement=args.measurement,
        output=args.output,
    )
    print(json.dumps(record, indent=2))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

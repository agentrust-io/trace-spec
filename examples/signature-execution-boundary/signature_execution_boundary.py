"""Demonstrate what TRACE signature verification establishes and what it leaves unproven.

Run with --out DIR after installing the repository's development dependencies.
All keys and claims in this script are deterministic synthetic test material.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import warnings
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import jwk_thumbprint, key_to_jwk, sign_record, validate_json, verify_record

CANONICALIZATION = "example-only/jcs-safe-integers-v1"
TRANSCRIPT_FORMAT = "example-only/tool-transcript-v1"
NOW = 1791936000
MAX_AGE_SECONDS = 60
MAX_FUTURE_SKEW_SECONDS = 0


def canonical_bytes(value: Any) -> bytes:
    """Example-local subset: RFC 8785 JCS with all floats and unsafe integers refused."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float) or (type(item) is int and abs(item) > 9007199254740991):
            raise ValueError("unsupported numeric value in example canonicalization")
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return rfc8785.dumps(value)


def load_json(text: str) -> Any:
    """Parse JSON while refusing duplicate object members and unsupported numbers."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    value = json.loads(text, object_pairs_hook=unique)
    canonical_bytes(value)
    return value


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def commitment_status(value: Any, expected: str) -> str:
    """Compare retained evidence against an expected sha256 commitment."""
    if value is None:
        return "unavailable"
    try:
        actual = digest(value)
    except ValueError:
        return "unsupported"
    return "matched" if actual == expected else "mismatch"


def issuer_key() -> Ed25519PrivateKey:
    """Deterministic test key representing the configured trusted issuer."""
    seed = hashlib.sha256(
        b"TRACE signature-execution-boundary issuer example ONLY - not a secret"
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def wrong_issuer_key() -> Ed25519PrivateKey:
    """Distinct deterministic test key representing an untrusted or wrong issuer."""
    seed = hashlib.sha256(
        b"TRACE signature-execution-boundary wrong-issuer example ONLY - not a secret"
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def retained_transcript() -> dict[str, Any]:
    """Synthetic tool-call log retained outside the Trust Record."""
    return {
        "format": TRANSCRIPT_FORMAT,
        "canonicalization": CANONICALIZATION,
        "session_id": "synthetic-session-1",
        "calls": [
            {
                "call_index": 1,
                "tool": "catalog.lookup",
                "arguments": {"item_id": "widget-100"},
                "result": {"status": "ok", "quantity": 4},
            }
        ],
    }


def baseline_record() -> dict[str, Any]:
    """Signed Level 0 record whose transcript hash matches retained_transcript()."""
    transcript = retained_transcript()
    return sign_record(
        {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": NOW,
            "subject": "spiffe://example.org/agent/boundary-demo",
            "model": {"provider": "synthetic", "model_id": "demo-model-v1"},
            "runtime": {
                "platform": "software-only",
                "measurement": digest({"runtime": "synthetic-software-runtime-v1"}),
            },
            "policy": {
                "bundle_hash": digest({"policy": "synthetic-declared-policy-v1"}),
                "enforcement_mode": "declared",
            },
            "data_class": "internal",
            "build_provenance": {
                "slsa_level": 1,
                "digest": digest({"build": "synthetic-build-v1"}),
            },
            "appraisal": {
                "status": "none",
                "verifier": "https://verifier.example.org",
            },
            "tool_transcript": {
                "hash": digest(transcript),
                "call_count": len(transcript["calls"]),
            },
        },
        issuer_key(),
    )


def invented_execution_record() -> dict[str, Any]:
    """Signed by the same trusted issuer, but asserting unexecuted and invented claims.

    Signature verification succeeds because the trusted issuer key signed these exact
    bytes. Nothing in verify_record() executes the workload, evaluates policy, checks
    a hardware quote, or compares tool_transcript.hash against retained log bytes.
    """
    unretained_invented_transcript = {
        "format": TRANSCRIPT_FORMAT,
        "canonicalization": CANONICALIZATION,
        "session_id": "synthetic-session-1",
        "calls": [
            {
                "call_index": index,
                "tool": "payments.transfer",
                "arguments": {"amount_cents": 50000, "sequence": index},
                "result": {"status": "approved"},
            }
            for index in range(1, 13)
        ],
    }
    return sign_record(
        {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": NOW,
            "subject": "spiffe://example.org/agent/boundary-demo",
            "model": {"provider": "synthetic", "model_id": "demo-model-v1"},
            "runtime": {
                "platform": "software-only",
                "measurement": digest({"runtime": "invented-unmeasured-runtime"}),
            },
            "policy": {
                "bundle_hash": digest({"policy": "invented-enforced-policy"}),
                "enforcement_mode": "enforce",
            },
            "data_class": "confidential",
            "build_provenance": {
                "slsa_level": 3,
                "digest": digest({"build": "invented-slsa3-build"}),
            },
            "appraisal": {
                "status": "affirming",
                "verifier": "https://verifier.example.org",
            },
            "tool_transcript": {
                "hash": digest(unretained_invented_transcript),
                "call_count": len(unretained_invented_transcript["calls"]),
            },
        },
        issuer_key(),
    )


def artifacts() -> dict[str, dict[str, Any]]:
    trusted_jwk = key_to_jwk(issuer_key())
    wrong_jwk = key_to_jwk(wrong_issuer_key())
    assert jwk_thumbprint(trusted_jwk) != jwk_thumbprint(wrong_jwk)
    return {
        "baseline-record.trace.json": baseline_record(),
        "invented-execution-record.trace.json": invented_execution_record(),
        "verification-inputs.json": {
            "trusted_key": trusted_jwk,
            "wrong_trusted_key": wrong_jwk,
            "now": NOW,
            "max_age_seconds": MAX_AGE_SECONDS,
            "max_future_skew_seconds": MAX_FUTURE_SKEW_SECONDS,
            "retained_transcript": retained_transcript(),
        },
    }


def run_checks(bundle: dict[str, dict[str, Any]]) -> list[str]:
    """Run the four boundary checks and return deterministic summary lines."""
    baseline = bundle["baseline-record.trace.json"]
    invented = bundle["invented-execution-record.trace.json"]
    inputs = bundle["verification-inputs.json"]
    trusted_key = inputs["trusted_key"]
    wrong_key = inputs["wrong_trusted_key"]
    now = inputs["now"]
    lines: list[str] = []

    # 1. Correctly signed record verifies against a separately retained trusted key.
    validate_json(baseline)
    baseline_result = verify_record(
        baseline,
        public_key_or_jwk=trusted_key,
        allow_embedded_key=False,
        now=now,
        max_age_seconds=inputs["max_age_seconds"],
        max_future_skew_seconds=inputs["max_future_skew_seconds"],
    )
    assert baseline_result.trusted_key_thumbprint == jwk_thumbprint(trusted_key)
    lines.append(
        "PASS [1/4]: baseline record validates and verifies against separately retained "
        f"trusted key (revocation={baseline_result.revocation.outcome})"
    )

    # 2. Changing a signed field after signing causes signature verification to fail.
    tampered = copy.deepcopy(baseline)
    tampered["data_class"] = "public"
    validate_json(tampered)
    try:
        verify_record(
            tampered,
            public_key_or_jwk=trusted_key,
            allow_embedded_key=False,
            now=now,
            max_age_seconds=inputs["max_age_seconds"],
            max_future_skew_seconds=inputs["max_future_skew_seconds"],
        )
    except InvalidSignature:
        lines.append(
            "PASS [2/4]: tampered signed field (data_class changed after signing) "
            "rejected with InvalidSignature"
        )
    else:
        raise RuntimeError("expected tampered record to fail signature verification")

    # 3. Verification with the wrong issuer key fails closed.
    try:
        verify_record(
            baseline,
            public_key_or_jwk=wrong_key,
            allow_embedded_key=False,
            now=now,
            max_age_seconds=inputs["max_age_seconds"],
            max_future_skew_seconds=inputs["max_future_skew_seconds"],
        )
    except ValueError as exc:
        if "does not identify the trusted key" not in str(exc):
            raise
    else:
        raise RuntimeError("expected wrong trusted key to fail verification")

    rebound_key = copy.deepcopy(baseline)
    rebound_key["cnf"] = {"jwk": copy.deepcopy(wrong_key)}
    validate_json(rebound_key)
    try:
        verify_record(
            rebound_key,
            public_key_or_jwk=wrong_key,
            allow_embedded_key=False,
            now=now,
            max_age_seconds=inputs["max_age_seconds"],
            max_future_skew_seconds=inputs["max_future_skew_seconds"],
        )
    except InvalidSignature:
        pass
    else:
        raise RuntimeError("expected cnf.jwk substitution to fail signature verification")

    unsigned = {k: v for k, v in baseline.items() if k not in ("cnf", "signature")}
    forged_by_wrong_issuer = sign_record(unsigned, wrong_issuer_key())
    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always", UserWarning)
        embedded_result = verify_record(
            forged_by_wrong_issuer,
            public_key_or_jwk=None,
            allow_embedded_key=True,
            now=now,
            max_age_seconds=inputs["max_age_seconds"],
            max_future_skew_seconds=inputs["max_future_skew_seconds"],
        )
    assert caught_warnings, "expected UserWarning when allow_embedded_key=True"
    assert embedded_result.trusted_key_thumbprint == jwk_thumbprint(wrong_key)
    lines.append(
        "PASS [3/4]: wrong issuer key rejected with ValueError (cnf.jwk thumbprint "
        "mismatch); substituting cnf.jwk without re-signing rejected with "
        "InvalidSignature; allow_embedded_key=True warns and checks self-consistency only"
    )

    # 4. Trusted issuer can sign invented execution claims; signature verification alone
    # cannot establish that the claimed run occurred or match retained evidence.
    validate_json(invented)
    invented_result = verify_record(
        invented,
        public_key_or_jwk=trusted_key,
        allow_embedded_key=False,
        now=now,
        max_age_seconds=inputs["max_age_seconds"],
        max_future_skew_seconds=inputs["max_future_skew_seconds"],
    )
    assert invented_result.trusted_key_thumbprint == baseline_result.trusted_key_thumbprint
    baseline_match = commitment_status(
        inputs["retained_transcript"], baseline["tool_transcript"]["hash"]
    )
    invented_match = commitment_status(
        inputs["retained_transcript"], invented["tool_transcript"]["hash"]
    )
    missing_match = commitment_status(None, invented["tool_transcript"]["hash"])
    assert baseline_match == "matched"
    assert invented_match == "mismatch"
    assert missing_match == "unavailable"
    lines.append(
        "PASS [4/4]: invented execution claims signed by the trusted issuer also pass "
        "verify_record; external transcript commitment comparison separates "
        f"baseline={baseline_match}, invented={invented_match}, unretained={missing_match}"
    )
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="directory for generated JSON")
    directory = parser.parse_args().out
    directory.mkdir(parents=True, exist_ok=True)
    generated = artifacts()
    for name, value in generated.items():
        (directory / name).write_bytes(
            (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        )
    for line in run_checks(generated):
        print(line)


if __name__ == "__main__":
    main()

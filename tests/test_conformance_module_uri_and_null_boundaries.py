"""Boundary checks for conformance module URI, explicit-null, and string-digest predicates."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

_CONFORMANCE_SRC = str(Path(__file__).resolve().parents[1] / "conformance" / "src")
if sys.path[:1] != [_CONFORMANCE_SRC]:
    sys.path.insert(0, _CONFORMANCE_SRC)

from trace_tests.modules import (  # type: ignore[import-untyped] # noqa: E402
    tr_anc,
    tr_pol,
    tr_rte,
    tr_sca,
    tr_txn,
)
from trace_tests.result import Finding, Status  # type: ignore[import-untyped] # noqa: E402

_VALID_SHA256 = "sha256:" + "a" * 64


class _DigestCoercible:
    """Non-string object whose string conversion yields a valid SHA-256 digest."""

    def __str__(self) -> str:
        return _VALID_SHA256


def _by_code(findings: list[Finding]) -> dict[str, Finding]:
    return {finding.code: finding for finding in findings}


@pytest.mark.parametrize(
    "bad_rim_uri",
    [
        None,
        "https://",
        "https://ex ample.com/rim",
        "https://example.com/\x01",
    ],
    ids=["explicit-null", "empty-host", "whitespace", "control-char"],
)
def test_tr_rte_003_rejects_null_and_malformed_https_uris(bad_rim_uri: str | None) -> None:
    base_runtime: dict[str, Any] = {
        "platform": "amd-sev-snp",
        "measurement": _VALID_SHA256,
    }
    assert _by_code(tr_rte.check({"runtime": dict(base_runtime)}))["TR-RTE-003"].status is (
        Status.SKIP
    )
    assert (
        _by_code(
            tr_rte.check(
                {"runtime": {**base_runtime, "rim_uri": "https://example.org/rim/v1"}}
            )
        )["TR-RTE-003"].status
        is Status.PASS
    )

    findings = tr_rte.check({"runtime": {**base_runtime, "rim_uri": bad_rim_uri}})
    assert _by_code(findings)["TR-RTE-003"].status is Status.FAIL


@pytest.mark.parametrize(
    "bad_transparency",
    [
        "https://scitt.example.org/receipts/abc 123",
        "https://scitt.example.org/receipts/abc\n",
        "https://scitt.example.org/receipts/\x00",
    ],
    ids=["space", "newline", "nul"],
)
def test_tr_anc_001_rejects_https_uri_with_whitespace_or_control_chars(
    bad_transparency: str,
) -> None:
    findings = tr_anc.check({"transparency": bad_transparency})
    assert _by_code(findings)["TR-ANC-001"].status is Status.FAIL


def test_tr_txn_002_rejects_explicit_null_call_count() -> None:
    absent = tr_txn.check({"tool_transcript": {"hash": _VALID_SHA256}})
    assert _by_code(absent)["TR-TXN-002"].status is Status.SKIP

    explicit_null = tr_txn.check(
        {"tool_transcript": {"hash": _VALID_SHA256, "call_count": None}}
    )
    assert _by_code(explicit_null)["TR-TXN-002"].status is Status.FAIL


def test_tr_rte_002_rejects_non_string_digest_object() -> None:
    findings = tr_rte.check(
        {"runtime": {"platform": "amd-sev-snp", "measurement": _DigestCoercible()}}
    )
    assert _by_code(findings)["TR-RTE-002"].status is Status.FAIL


def test_tr_sca_002_rejects_non_string_digest_object() -> None:
    findings = tr_sca.check(
        {"build_provenance": {"slsa_level": 3, "digest": _DigestCoercible()}}
    )
    assert _by_code(findings)["TR-SCA-002"].status is Status.FAIL


def test_tr_txn_001_rejects_non_string_digest_object() -> None:
    findings = tr_txn.check({"tool_transcript": {"hash": _DigestCoercible()}})
    assert _by_code(findings)["TR-TXN-001"].status is Status.FAIL


def test_tr_pol_001_and_003_reject_non_string_digest_object() -> None:
    findings = tr_pol.check(
        {
            "policy": {
                "bundle_hash": _DigestCoercible(),
                "enforcement_mode": "enforce",
                "policy_uri": "https://policy.example.org/bundles/v1.json",
            }
        }
    )
    by_code = _by_code(findings)
    assert by_code["TR-POL-001"].status is Status.FAIL
    assert by_code["TR-POL-003"].status is Status.SKIP

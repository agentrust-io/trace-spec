"""The runner must not issue a conformance pass for a schema-invalid record."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trace_tests.result import Finding
from trace_tests.runner import _run_levels, run

from .conftest import _b64url, _build_signed_cmcp_record, _canonical_json


def _resign(record: dict[str, Any], key: Ed25519PrivateKey) -> None:
    body = _canonical_json({name: value for name, value in record.items() if name != "signature"})
    record["signature"] = _b64url(key.sign(body))


def _schema_findings(results: dict[str, list[Finding]]) -> list[Finding]:
    return [finding for finding in results["TR-ENV"] if finding.code == "TR-ENV-007"]


@pytest.mark.parametrize("level", [0, 1, 2])
@pytest.mark.parametrize(
    ("mutate", "expected_detail"),
    [
        (lambda trace: trace.pop("model"), "'model' is a required property"),
        (
            lambda trace: trace.__setitem__("unsigned_extension", True),
            "additionalProperties constraint",
        ),
    ],
    ids=["missing-required-member", "forbidden-additional-member"],
)
def test_validly_signed_schema_invalid_records_fail_every_level(
    level: int,
    mutate: Callable[[dict[str, Any]], object],
    expected_detail: str,
) -> None:
    record, key = _build_signed_cmcp_record()
    mutate(record["trace"])
    _resign(record, key)

    results = run(record, "cmcp-runtime", level)

    schema_findings = _schema_findings(results)
    assert schema_findings and all(finding.failed() for finding in schema_findings)
    assert any(expected_detail in finding.message for finding in schema_findings)
    assert all(finding.passed() for finding in results["TR-SIG"]), (
        "the malformed record must remain validly signed so this exercises the schema gate"
    )


def test_multilevel_report_path_carries_schema_failure_at_every_level() -> None:
    record, key = _build_signed_cmcp_record()
    record["trace"].pop("build_provenance")
    _resign(record, key)

    execution = _run_levels(record, "cmcp-runtime", (0, 1, 2))

    for results in execution.compatibility_results.values():
        assert any(finding.failed() for finding in _schema_findings(results))
    assert all(failures >= 1 for _level, failures, _unverified in execution.report_tallies)


def test_plain_signed_schema_invalid_record_fails_the_same_gate() -> None:
    envelope, key = _build_signed_cmcp_record()
    record = envelope["trace"]
    record["forbidden_extension"] = True
    body = _canonical_json(record)
    record["signature"] = _b64url(key.sign(body))

    results = run(record, "trace", 0)

    assert any(finding.failed() for finding in _schema_findings(results))
    signature = [finding for finding in results["TR-SIG"] if finding.code == "TR-SIG-005"]
    assert signature and all(finding.passed() for finding in signature)


def test_complete_signed_record_still_passes_schema_gate() -> None:
    record, _key = _build_signed_cmcp_record()

    results = run(record, "cmcp-runtime", 0)

    schema_findings = _schema_findings(results)
    assert len(schema_findings) == 1
    assert schema_findings[0].passed()


def test_schema_finding_does_not_copy_rejected_values() -> None:
    record, key = _build_signed_cmcp_record()
    secret = "do-not-copy-this-record-value"
    record["trace"][secret] = secret
    _resign(record, key)

    findings = _schema_findings(run(record, "cmcp-runtime", 0))

    assert findings and all(finding.failed() for finding in findings)
    assert all(secret not in finding.message for finding in findings)


def test_schema_finding_does_not_copy_nested_member_names() -> None:
    record, key = _build_signed_cmcp_record()
    confidential_member_name = "private-beneficiary-reference-83991"
    # Extra JWK members are permitted only when their values are canonicalizable.
    # The member name is record-supplied and can be sensitive even when the
    # rejected value itself is omitted from the diagnostic.
    record["trace"]["cnf"]["jwk"][confidential_member_name] = 1.5
    _resign(record, key)

    results = run(record, "cmcp-runtime", 0)

    schema_findings = _schema_findings(results)
    assert schema_findings and all(finding.failed() for finding in schema_findings)
    assert all(confidential_member_name not in finding.message for finding in schema_findings)
    assert all(finding.passed() for finding in results["TR-SIG"])

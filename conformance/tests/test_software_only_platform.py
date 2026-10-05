"""Tests for software-only platform handling in TR-RTE.

Spec note: trace-spec added `software-only` as a valid `runtime.platform`
value for development and CI use. It carries no hardware attestation evidence
and is therefore only acceptable at Level 0. Level 1+ must reject it with a
clear message that names the reason (development-mode, not hardware-attested)
rather than the generic "unknown platform" error.

Covers:
- software-only at Level 0 passes TR-RTE-001
- software-only at Level 1 fails TR-RTE-001 with a message mentioning "development-mode"
- software-only at Level 2 fails TR-RTE-001 with a message mentioning "development-mode"
- software-only is accepted by the JSON Schema (schema enum coverage)
"""

from __future__ import annotations

import copy

import jsonschema
import pytest

from trace_tests.modules import tr_rte
from trace_tests.result import Status

_SOFTWARE_ONLY_TRACE = {
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "a" * 64,
    }
}


@pytest.mark.parametrize("level", [1, 2])
def test_software_only_fails_at_level(level):
    """software-only must fail TR-RTE-001 at Level 1 and Level 2."""
    findings = tr_rte.check(_SOFTWARE_ONLY_TRACE, level=level)
    platform_findings = [f for f in findings if f.code == "TR-RTE-001"]
    assert platform_findings, "TR-RTE-001 finding expected"
    assert all(f.failed() for f in platform_findings), (
        f"software-only must fail TR-RTE-001 at Level {level}; got {platform_findings}"
    )


@pytest.mark.parametrize("level", [1, 2])
def test_software_only_failure_mentions_development_mode(level):
    """Failure message for software-only must mention 'development-mode', not 'unknown'."""
    findings = tr_rte.check(_SOFTWARE_ONLY_TRACE, level=level)
    fail_findings = [f for f in findings if f.code == "TR-RTE-001" and f.failed()]
    assert fail_findings, f"Expected TR-RTE-001 FAIL at Level {level}"
    messages = " ".join(f.message.lower() for f in fail_findings)
    assert "development-mode" in messages, (
        f"TR-RTE-001 failure at Level {level} must mention 'development-mode'; "
        f"got: {[f.message for f in fail_findings]}"
    )
    assert "unknown" not in messages, (
        f"TR-RTE-001 failure at Level {level} must not say 'unknown platform'; "
        f"got: {[f.message for f in fail_findings]}"
    )


def test_software_only_passes_at_level0():
    """software-only must pass TR-RTE-001 at Level 0."""
    findings = tr_rte.check(_SOFTWARE_ONLY_TRACE, level=0)
    platform_findings = [f for f in findings if f.code == "TR-RTE-001"]
    assert platform_findings, "TR-RTE-001 finding expected"
    assert all(f.passed() for f in platform_findings), (
        f"software-only must pass TR-RTE-001 at Level 0; got {platform_findings}"
    )


def test_software_only_default_level_passes():
    """check() with no level argument defaults to Level 0 and passes software-only."""
    findings = tr_rte.check(_SOFTWARE_ONLY_TRACE)
    platform_findings = [f for f in findings if f.code == "TR-RTE-001"]
    assert platform_findings, "TR-RTE-001 finding expected"
    assert all(f.passed() for f in platform_findings), (
        f"software-only must pass TR-RTE-001 at default level; got {platform_findings}"
    )


def test_software_only_accepted_by_schema(schema, valid_level0):
    """software-only must be a valid enum value in the JSON Schema."""
    record = copy.deepcopy(valid_level0)
    record["runtime"]["platform"] = "software-only"
    # Must not raise
    jsonschema.validate(record, schema)

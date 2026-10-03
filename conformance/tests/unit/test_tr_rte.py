"""Unit tests for TR-RTE module."""

import pytest

from trace_tests.modules.tr_rte import check

_VALID = {
    "runtime": {
        "platform": "amd-sev-snp",
        "measurement": "sha256:" + "a" * 64,
    }
}


def test_valid_runtime_passes():
    findings = check(_VALID)
    assert all(not f.failed() for f in findings), findings


def test_azure_cvm_platform_passes():
    """azure-cvm-sev-snp is a recognized hardware platform (vTPM-rooted SEV-SNP)."""
    trace = {
        "runtime": {
            "platform": "azure-cvm-sev-snp",
            "measurement": "sha384:" + "a" * 96,
            "nonce": "challenge",
        }
    }
    findings = check(trace, level=2, expected_nonce="challenge")
    assert all(not f.failed() for f in findings), findings


def test_invalid_platform_fails():
    trace = {"runtime": {**_VALID["runtime"], "platform": "unknown-tee"}}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-RTE-001" in codes


def test_invalid_measurement_format_fails():
    trace = {"runtime": {**_VALID["runtime"], "measurement": "notadigest"}}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-RTE-002" in codes


def test_sha384_measurement_passes():
    trace = {"runtime": {**_VALID["runtime"], "measurement": "sha384:" + "a" * 96}}
    findings = check(trace)
    assert all(not f.failed() for f in findings)


def test_missing_runtime_fails():
    findings = check({})
    assert any(f.failed() for f in findings)


def test_rim_uri_skip_when_absent():
    findings = check(_VALID)
    skipped = [f for f in findings if f.skipped()]
    assert any("rim_uri" in f.message for f in skipped)


def test_valid_rim_uri_passes():
    trace = {"runtime": {**_VALID["runtime"], "rim_uri": "https://example.org/rim/tdx-v1"}}
    findings = check(trace)
    assert all(not f.failed() for f in findings)


def test_invalid_rim_uri_fails():
    trace = {"runtime": {**_VALID["runtime"], "rim_uri": "ftp://bad"}}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-RTE-003" in codes


def test_http_rim_uri_fails():
    trace = {"runtime": {**_VALID["runtime"], "rim_uri": "http://example.org/rim/tdx-v1"}}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-RTE-003" in codes, "plain http rim_uri must be rejected; https only"


@pytest.mark.parametrize("level", [1, 2])
def test_attested_levels_require_expected_nonce(level):
    trace = {"runtime": {**_VALID["runtime"], "nonce": "record-chosen"}}
    codes = {f.code for f in check(trace, level=level) if f.failed()}
    assert "TR-RTE-004" in codes


def test_nonce_mismatch_fails_and_match_passes():
    trace = {"runtime": {**_VALID["runtime"], "nonce": "signed-nonce"}}
    mismatch = check(trace, level=1, expected_nonce="verifier-challenge")
    assert any(f.code == "TR-RTE-004" and f.failed() for f in mismatch)
    match = check(trace, level=1, expected_nonce="signed-nonce")
    assert any(f.code == "TR-RTE-004" and f.passed() for f in match)

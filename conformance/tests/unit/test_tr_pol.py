"""Unit tests for TR-POL module."""

from trace_tests.modules.tr_pol import check

_VALID = {
    "policy": {
        "bundle_hash": "sha256:" + "b" * 64,
        "enforcement_mode": "enforce",
    }
}


def test_valid_policy_passes():
    findings = check(_VALID)
    assert all(not f.failed() for f in findings), findings


def test_invalid_bundle_hash_format_fails():
    trace = {"policy": {**_VALID["policy"], "bundle_hash": "md5:abc123"}}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-POL-001" in codes


def test_invalid_enforcement_mode_fails():
    trace = {"policy": {**_VALID["policy"], "enforcement_mode": "strict"}}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-POL-002" in codes


def test_advisory_mode_passes():
    trace = {"policy": {**_VALID["policy"], "enforcement_mode": "advisory"}}
    findings = check(trace)
    assert all(not f.failed() for f in findings)


def test_silent_mode_passes():
    trace = {"policy": {**_VALID["policy"], "enforcement_mode": "silent"}}
    findings = check(trace)
    assert all(not f.failed() for f in findings)


def test_missing_policy_fails():
    findings = check({})
    assert any(f.failed() for f in findings)


def test_non_string_bundle_hash_with_digest_str_fails():
    class _DigestLike:
        def __str__(self) -> str:
            return "sha256:" + "b" * 64

    trace = {
        "policy": {
            "bundle_hash": _DigestLike(),
            "enforcement_mode": "enforce",
            "policy_uri": "https://policy.example.org/bundles/v1.json",
        }
    }
    by_code = {f.code: f for f in check(trace)}
    assert by_code["TR-POL-001"].failed()
    assert by_code["TR-POL-003"].skipped()

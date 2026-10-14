"""Unit tests for TR-ENV module."""

import time
import pytest
from trace_tests.modules.tr_env import check
from trace_tests.result import Status

_VALID = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": int(time.time()) - 600,  # fresh: 10 minutes old
    "subject": "spiffe://example.org/agent/test",
    "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "dGVzdA"}},
}


def test_all_pass_on_valid():
    findings = check(_VALID)
    assert all(f.passed() for f in findings), [f for f in findings if not f.passed()]


def test_wrong_eat_profile_fails():
    trace = {**_VALID, "eat_profile": "tag:wrong,2025:v1"}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-ENV-001" in codes


def test_missing_eat_profile_fails():
    trace = {k: v for k, v in _VALID.items() if k != "eat_profile"}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-ENV-001" in codes


def test_iat_too_small_fails():
    trace = {**_VALID, "iat": 100}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-ENV-002" in codes


@pytest.mark.parametrize("iat_Fn", [
    lambda now: float(now - 600),
    lambda _now: 1.785e9,
    lambda _now: 1_700_000_000,
    lambda _now: 1_700_000_000.0,
])
def test_iat_whole_float_passes(iat_Fn):
    now = int(time.time())
    iat = iat_Fn(now)
    trace = {**_VALID, "iat": iat}
    findings = check(trace, max_age_seconds=max(86400, abs(now - int(iat)) + 3600))
    assert all(f.passed() for f in findings), [f for f in findings if not f.passed()]


@pytest.mark.parametrize("iat", [9007199254740991, 9007199254740991.0])
def test_iat_at_safe_integer_upper_bound_reaches_future_check(iat):
    trace = {**_VALID, "iat": iat}
    failed = [f for f in check(trace) if f.code == "TR-ENV-002" and f.failed()]
    assert len(failed) == 1
    assert "is in the future" in failed[0].message


@pytest.mark.parametrize("bad_iat", [
    1_699_999_999,
    1_699_999_999.0,
    1785000000.5,
    True,
    False,
    "1785000000",
    9007199254740992,
    9007199254740992.0,
    1.0e21,
    -9007199254740992,
    float("nan"),
    float("inf"),
    float("-inf"),
])
def test_iat_non_integer_or_outside_safe_integer_range_fails(bad_iat):
    trace = {**_VALID, "iat": bad_iat}
    failed = [f for f in check(trace) if f.code == "TR-ENV-002" and f.failed()]
    assert len(failed) == 1
    assert "Unix timestamp integer" in failed[0].message


def test_iat_in_future_fails():
    trace = {**_VALID, "iat": int(time.time()) + 3600}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-ENV-002" in codes


def test_iat_older_than_default_max_age_fails():
    trace = {**_VALID, "iat": int(time.time()) - (25 * 3600)}  # 25 hours old
    failed = [f for f in check(trace) if f.failed()]
    assert any(f.code == "TR-ENV-002" and "stale" in f.message for f in failed), failed


def test_iat_within_custom_max_age_passes():
    trace = {**_VALID, "iat": int(time.time()) - (25 * 3600)}
    findings = check(trace, max_age_seconds=48 * 3600)
    assert all(f.passed() for f in findings), [f for f in findings if not f.passed()]


def test_iat_beyond_custom_max_age_fails():
    trace = {**_VALID, "iat": int(time.time()) - 7200}  # 2 hours old
    failed = [f for f in check(trace, max_age_seconds=3600) if f.failed()]
    assert any(f.code == "TR-ENV-002" for f in failed)


def test_did_subject_passes():
    trace = {**_VALID, "subject": "did:key:z6MkhaXgBZDvotzL8oCYaXeFuJArwvX6mDMsKTJVjtN7R"}
    findings = check(trace)
    assert all(f.passed() for f in findings), [f for f in findings if not f.passed()]


def test_did_mesh_subject_passes():
    trace = {**_VALID, "subject": "did:mesh:spiffe://factory.example/agent/material-movement/dev"}
    findings = check(trace)
    assert all(f.passed() for f in findings), [f for f in findings if not f.passed()]


def test_non_spiffe_non_did_subject_fails():
    trace = {**_VALID, "subject": "https://example.org/agent"}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-ENV-003" in codes


def test_missing_cnf_jwk_fails():
    trace = {**_VALID, "cnf": {}}
    codes = {f.code for f in check(trace) if f.failed()}
    assert "TR-ENV-004" in codes


# ---------------------------------------------------------------------------
# TR-ENV-005 (GHSA-vc4p-h84j-7qxj): cnf.jwk must carry the public half only.
# TR-ENV-004 checks that kty is present, so a record publishing the key that
# signed it passed the whole suite.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("member", ["d", "p", "q", "dp", "dq", "qi", "k"])
def test_private_key_material_in_cnf_jwk_fails(member):
    trace = {**_VALID, "cnf": {"jwk": {**_VALID["cnf"]["jwk"], member: "SECRET"}}}

    findings = check(trace)
    codes = {f.code for f in findings if f.failed()}

    assert "TR-ENV-005" in codes
    # TR-ENV-004 still passes, which is exactly why 005 had to exist.
    assert "TR-ENV-004" not in codes


def test_private_material_finding_names_every_member_found():
    trace = {**_VALID, "cnf": {"jwk": {**_VALID["cnf"]["jwk"], "d": "S", "q": "S"}}}

    detail = next(f.message for f in check(trace) if f.code == "TR-ENV-005")

    assert "d" in detail and "q" in detail


def test_public_only_cnf_jwk_passes():
    findings = [f for f in check(_VALID) if f.code == "TR-ENV-005"]

    assert len(findings) == 1
    assert findings[0].passed()

"""Unit tests for TR-APR module."""

import time

import pytest

from trace_tests.modules.tr_apr import _MAX_FUTURE_SKEW_SECONDS, _not_absolute_uri, check
from trace_tests.modules.tr_pol import _not_absolute_uri as _tr_pol_not_absolute_uri
from trace_tests.result import Status

_VALID = {
    "appraisal": {
        "status": "affirming",
        "verifier": "https://verifier.example.org",
    }
}


def _by_code(findings):
    return {f.code: f for f in findings}


# --- the happy paths -------------------------------------------------------


def test_a_valid_appraisal_raises_nothing_at_level_zero():
    findings = check(_VALID, 0)
    assert all(not f.failed() for f in findings), findings


def test_a_valid_appraisal_raises_nothing_at_level_one():
    findings = check(_VALID, 1)
    assert all(not f.failed() for f in findings), findings


def test_every_optional_field_present_and_valid_passes():
    trace = {"appraisal": {**_VALID["appraisal"],
                           "policy_ref": "https://policies.example.org/appraisal/v3",
                           "timestamp": 1748000042}}
    codes = _by_code(check(trace, 1))
    assert codes["TR-APR-003"].status is Status.PASS
    assert codes["TR-APR-004"].status is Status.PASS


# --- TR-APR-001: status ----------------------------------------------------


@pytest.mark.parametrize("status", ["affirming", "warning", "contraindicated", "none"])
def test_every_schema_status_is_accepted(status):
    trace = {"appraisal": {**_VALID["appraisal"], "status": status}}
    assert _by_code(check(trace, 0))["TR-APR-001"].status is Status.PASS


@pytest.mark.parametrize("status", ["verified", "AFFIRMING", "pass", 7, None, True, ["affirming"]])
def test_a_status_outside_the_enum_fails(status):
    trace = {"appraisal": {**_VALID["appraisal"], "status": status}}
    assert _by_code(check(trace, 0))["TR-APR-001"].status is Status.FAIL


def test_an_absent_status_fails():
    assert _by_code(check({"appraisal": {"verifier": "https://v.example"}}, 0))[
        "TR-APR-001"].status is Status.FAIL


def test_an_absent_appraisal_is_a_single_finding():
    findings = check({}, 0)
    assert len(findings) == 1
    assert findings[0].code == "TR-APR-001"
    assert findings[0].status is Status.FAIL


@pytest.mark.parametrize("appraisal", ["affirming", 7, [], True, 1.5])
def test_a_non_object_appraisal_is_a_single_finding(appraisal):
    findings = check({"appraisal": appraisal}, 0)
    assert len(findings) == 1
    assert findings[0].code == "TR-APR-001"
    assert findings[0].status is Status.FAIL


# --- TR-APR-002: verifier --------------------------------------------------


def test_an_absent_verifier_fails():
    assert _by_code(check({"appraisal": {"status": "none"}}, 0))["TR-APR-002"].status is Status.FAIL


@pytest.mark.parametrize("verifier", [
    "nvidia-openshell/0.3.0",          # no scheme: a relative reference
    "https://v.example/ a",            # a space
    "https://v.example/\x01",          # a control character
    "1https://v.example",              # a scheme RFC 3986 does not admit
    "",                                # empty
])
def test_a_verifier_that_is_not_an_absolute_uri_fails(verifier):
    trace = {"appraisal": {**_VALID["appraisal"], "verifier": verifier}}
    assert _by_code(check(trace, 0))["TR-APR-002"].status is Status.FAIL


@pytest.mark.parametrize("verifier", [7, None, [], {}, True])
def test_a_non_string_verifier_fails(verifier):
    trace = {"appraisal": {**_VALID["appraisal"], "verifier": verifier}}
    assert _by_code(check(trace, 0))["TR-APR-002"].status is Status.FAIL


# --- TR-APR-003: policy_ref, optional --------------------------------------


def test_an_absent_policy_ref_skips_rather_than_passing():
    """Absence is not a pass. The field is optional, so nothing was checked."""
    assert _by_code(check(_VALID, 0))["TR-APR-003"].status is Status.SKIP


@pytest.mark.parametrize("policy_ref", ["./policies/v1", "ht tp://x", "policies/v1", 7, None])
def test_a_malformed_policy_ref_fails(policy_ref):
    trace = {"appraisal": {**_VALID["appraisal"], "policy_ref": policy_ref}}
    assert _by_code(check(trace, 0))["TR-APR-003"].status is Status.FAIL


# --- TR-APR-004: timestamp, optional ---------------------------------------


def test_an_absent_timestamp_skips_rather_than_passing():
    assert _by_code(check(_VALID, 0))["TR-APR-004"].status is Status.SKIP


def test_a_future_timestamp_fails():
    trace = {"appraisal": {**_VALID["appraisal"], "timestamp": int(time.time()) + 3600}}
    assert _by_code(check(trace, 0))["TR-APR-004"].status is Status.FAIL


def test_a_past_timestamp_passes():
    trace = {"appraisal": {**_VALID["appraisal"], "timestamp": int(time.time()) - 3600}}
    assert _by_code(check(trace, 0))["TR-APR-004"].status is Status.PASS


def test_a_timestamp_inside_the_skew_window_passes():
    """The tolerance exists because producer and checker clocks differ."""
    trace = {"appraisal": {**_VALID["appraisal"],
                           "timestamp": int(time.time()) + _MAX_FUTURE_SKEW_SECONDS - 5}}
    assert _by_code(check(trace, 0))["TR-APR-004"].status is Status.PASS


@pytest.mark.parametrize("timestamp", ["1748000042", 1748000042.0, None, True, False, []])
def test_a_non_integer_timestamp_fails(timestamp):
    """`bool` is an `int` subclass in Python; a JSON `true` is not epoch seconds."""
    trace = {"appraisal": {**_VALID["appraisal"], "timestamp": timestamp}}
    assert _by_code(check(trace, 0))["TR-APR-004"].status is Status.FAIL


def test_the_skew_matches_the_one_tr_env_applies_to_a_future_iat():
    """Held equal to `tr_env.py:36` by reading the source, not by restating it.

    The tolerance there is an inline literal rather than a named constant, so
    there is nothing to import. Reading it is what keeps the two from drifting
    apart silently.
    """
    import pathlib
    import re
    source = (pathlib.Path(__file__).resolve().parents[2]
              / "src" / "trace_tests" / "modules" / "tr_env.py").read_text(encoding="utf-8")
    match = re.search(r"if iat > now \+ (\d+):", source)
    assert match, "the future-iat comparison in tr_env.py has changed shape"
    assert int(match.group(1)) == _MAX_FUTURE_SKEW_SECONDS


# --- TR-APR-005: affirming from Level 1 ------------------------------------


def test_the_affirming_requirement_skips_at_level_zero():
    """docs/levels.md's own minimum conformant Level 0 record carries "none"."""
    trace = {"appraisal": {**_VALID["appraisal"], "status": "none"}}
    assert _by_code(check(trace, 0))["TR-APR-005"].status is Status.SKIP


@pytest.mark.parametrize("level", [1, 2])
@pytest.mark.parametrize("status", ["none", "warning", "contraindicated"])
def test_a_non_affirming_status_fails_from_level_one(status, level):
    trace = {"appraisal": {**_VALID["appraisal"], "status": status}}
    assert _by_code(check(trace, level))["TR-APR-005"].status is Status.FAIL


@pytest.mark.parametrize("level", [1, 2])
def test_an_affirming_status_passes_from_level_one(level):
    assert _by_code(check(_VALID, level))["TR-APR-005"].status is Status.PASS


# --- the duplicated predicate ----------------------------------------------


#: Inputs chosen to reach every branch of both copies rather than to be
#: exhaustive: each rule, each rejection reason, and the accepting case.
_URI_CASES = [
    "https://verifier.example.org",
    "https://v.example/appraisal/v3?q=1#f",
    "did:example:123",
    "urn:uuid:01926b4c-1234-7abc-9def-000000000001",
    "./policies/v1",
    "policies/v1",
    "",
    "https://v.example/ a",
    "ht tp://x",
    "https://v.example/\x01",
    "https://v.example/\x7f",
    "\thttps://v.example",
    "1http://x",
    "+http://x",
    "-http://x",
    "http+s://x",
    "HTTPS://V.EXAMPLE",
]


@pytest.mark.parametrize("value", _URI_CASES, ids=[repr(v) for v in _URI_CASES])
def test_the_duplicated_uri_predicate_agrees_with_the_one_in_tr_pol(value):
    """The twins, held equal.

    `tr_apr._not_absolute_uri` is duplicated from `tr_pol._not_absolute_uri`
    rather than imported: no module in this tree imports another, and a
    cross-module import would be a structural change this module has no mandate
    to make. Duplication without a guard is how two copies of one rule drift, so
    this is the guard — the same shape `test_enum_parity` uses for the enums.
    """
    assert _not_absolute_uri(value) == _tr_pol_not_absolute_uri(value)


# --- never raises ----------------------------------------------------------


@pytest.mark.parametrize("junk", ["!!!", "AAAA", 123, None, "", [1], {}, {"status": {}}, 1.5, True])
def test_no_shape_of_appraisal_raises(junk):
    """`test_modules_never_raise` fuzzes `appraisal` too; this is the local half."""
    for level in (0, 1, 2):
        assert isinstance(check({"appraisal": junk}, level), list)

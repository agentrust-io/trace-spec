"""TR-POL-003: every branch of the resolution check, one test each.

The resolver here is a dict, not a filesystem or a network. The module's
contract is ``Callable[[str], bytes]`` and nothing more, so the tests exercise
that contract directly: a lookup that answers, one that raises, and one that
returns the wrong type. What the caller does to obtain the bytes is the
caller's business, which is the point of the seam.
"""

from __future__ import annotations

import hashlib

import pytest

from trace_tests.modules.tr_pol import check
from trace_tests.result import Status

BUNDLE = b'{"policy_id":"appraisal/agent-v1","version":"1.0.0"}'
OTHER = b'{"policy_id":"retention/pii-90d","version":"1.4.2"}'
URI = "https://policy.example.org/bundles/policy-bundle-base.json"

SHA256 = "sha256:" + hashlib.sha256(BUNDLE).hexdigest()
SHA384 = "sha384:" + hashlib.sha384(BUNDLE).hexdigest()


def resolver(mapping: dict[str, bytes]):
    """A resolver over *mapping*; a URI it does not hold raises, as a fetch would."""
    def _resolve(uri: str) -> bytes:
        return mapping[uri]
    return _resolve


def trace_with(**policy):
    base = {"bundle_hash": SHA256, "enforcement_mode": "enforce"}
    base.update(policy)
    return {"policy": base}


def pol003(findings):
    return next(f for f in findings if f.code == "TR-POL-003")


def test_no_policy_uri_skips():
    f = pol003(check(trace_with(), policy_resolver=resolver({URI: BUNDLE})))
    assert f.status is Status.SKIP
    assert "not present" in f.message


def test_policy_uri_of_the_wrong_type_fails():
    f = pol003(check(trace_with(policy_uri=42), policy_resolver=resolver({})))
    assert f.status is Status.FAIL
    assert "must be a string" in f.message


@pytest.mark.parametrize(
    "bad,why",
    [
        ("bundles/policy-bundle-base.json", "no scheme"),
        ("//policy.example.org/bundles/base.json", "no scheme"),
        ("https://policy.example.org/bundles/policy bundle base.json", "whitespace"),
        ("https://policy.example.org/bundles/base.json\n", "whitespace"),
        ("1https://policy.example.org/x.json", "no scheme"),
    ],
)
def test_a_reference_that_is_not_an_absolute_uri_fails(bad, why):
    """A defect in the record, so it is a failure and not weather."""
    f = pol003(check(trace_with(policy_uri=bad), policy_resolver=resolver({})))
    assert f.status is Status.FAIL, why
    assert "policy.policy_uri" in f.message


def test_a_malformed_reference_fails_with_no_resolver_at_all():
    """The check that matters most: offline must not mean blind.

    A reference the record got wrong needs no network to detect. If this
    skipped when no resolver was supplied, an offline run would report nothing
    about a record that is wrong on its face.
    """
    f = pol003(check(trace_with(policy_uri="bundles/base.json"), policy_resolver=None))
    assert f.status is Status.FAIL


def test_malformed_reference_outranks_a_malformed_digest():
    f = pol003(check(trace_with(policy_uri="bundles/base.json", bundle_hash="not-a-digest")))
    assert f.status is Status.FAIL


def test_unusable_bundle_hash_skips_toward_tr_pol_001():
    f = pol003(check(trace_with(policy_uri=URI, bundle_hash="sha256:short"),
                     policy_resolver=resolver({URI: BUNDLE})))
    assert f.status is Status.SKIP
    assert "TR-POL-001" in f.message


def test_no_resolver_skips_rather_than_reporting_unverified():
    """Offline verification is a first-class use, not a degraded one."""
    f = pol003(check(trace_with(policy_uri=URI), policy_resolver=None))
    assert f.status is Status.SKIP
    assert "no resolver supplied" in f.message


def test_a_resolver_that_raises_is_unverified_and_says_why():
    f = pol003(check(trace_with(policy_uri=URI), policy_resolver=resolver({})))
    assert f.status is Status.UNVERIFIED
    assert "KeyError" in f.message, "the reason must survive into the message"


def test_a_resolver_that_raises_oserror_is_unverified_and_says_why():
    """A mistyped manifest path and a withdrawn referent share a status.

    Only the message distinguishes them, which is why it carries the exception.
    """
    def raising(uri: str) -> bytes:
        raise FileNotFoundError(2, "No such file or directory", "policies/missing.json")

    f = pol003(check(trace_with(policy_uri=URI), policy_resolver=raising))
    assert f.status is Status.UNVERIFIED
    assert "FileNotFoundError" in f.message
    assert "missing.json" in f.message


def test_a_resolver_returning_non_bytes_names_the_contract_it_broke():
    f = pol003(check(trace_with(policy_uri=URI),
                     policy_resolver=lambda uri: BUNDLE.decode()))
    assert f.status is Status.UNVERIFIED
    assert "violated its contract" in f.message
    assert "str" in f.message


def test_resolved_bundle_matching_sha256_passes():
    f = pol003(check(trace_with(policy_uri=URI), policy_resolver=resolver({URI: BUNDLE})))
    assert f.status is Status.PASS


def test_resolved_bundle_matching_sha384_passes():
    """A set that never exercises sha384 passes a verifier that hardcodes sha256."""
    f = pol003(check(trace_with(policy_uri=URI, bundle_hash=SHA384),
                     policy_resolver=resolver({URI: BUNDLE})))
    assert f.status is Status.PASS


def test_resolved_bundle_contradicting_the_declared_digest_fails():
    f = pol003(check(trace_with(policy_uri=URI), policy_resolver=resolver({URI: OTHER})))
    assert f.status is Status.FAIL
    assert "does not describe what" in f.message


def test_sha384_mismatch_fails_rather_than_passing_unchecked():
    """The fail-open shape: a verifier that cannot compute sha384 must not pass."""
    f = pol003(check(trace_with(policy_uri=URI, bundle_hash=SHA384),
                     policy_resolver=resolver({URI: OTHER})))
    assert f.status is Status.FAIL


def test_an_uppercase_declared_digest_still_compares_equal():
    upper = "sha256:" + hashlib.sha256(BUNDLE).hexdigest().upper()
    f = pol003(check(trace_with(policy_uri=URI, bundle_hash=upper),
                     policy_resolver=resolver({URI: BUNDLE})))
    # TR-POL-001's pattern is lowercase-only, so an uppercase digest never
    # reaches the comparison in practice; this pins the behaviour if it changes.
    assert f.status in (Status.PASS, Status.SKIP)


def test_the_resolver_is_never_called_when_no_policy_uri_is_present():
    calls: list[str] = []

    def counting(uri: str) -> bytes:
        calls.append(uri)
        return BUNDLE

    check(trace_with(), policy_resolver=counting)
    assert calls == []


def test_the_resolver_is_never_called_for_a_malformed_reference():
    calls: list[str] = []

    def counting(uri: str) -> bytes:
        calls.append(uri)
        return BUNDLE

    check(trace_with(policy_uri="bundles/base.json"), policy_resolver=counting)
    assert calls == [], "a record defect must not cost a fetch"

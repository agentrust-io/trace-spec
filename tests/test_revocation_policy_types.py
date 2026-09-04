"""Regression tests for revocation-bundle freshness policy primitive boundaries."""

from __future__ import annotations

import time

import pytest

from agentrust_trace import generate_key, key_to_jwk, sign_record, verify_record
from agentrust_trace.revocation import check_bundle


def _record() -> dict:
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": int(time.time()),
        "subject": "did:mesh:spiffe://factory.example/agent/payments/prod",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + "0" * 64,
        },
        "policy": {
            "bundle_hash": "sha256:" + "a" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "confidential",
        "build_provenance": {
            "slsa_level": 0,
            "digest": "sha256:" + "b" * 64,
        },
        "appraisal": {
            "status": "affirming",
            "verifier": "https://agt.example.org/verifier",
        },
        "transparency": "https://rekor.sigstore.dev/api/v1/log/entries/example",
        "tool_transcript": {
            "hash": "sha256:" + "c" * 64,
            "call_count": 3,
        },
    }


def _check_bundle(**overrides):
    kwargs = {
        "trusted_key_identifiers": [],
        "trusted_bundle_keys": [],
        "now": 1_785_000_000,
        "max_bundle_age_seconds": 86_400,
        "max_future_skew_seconds": 300,
    }
    kwargs.update(overrides)
    return check_bundle({}, **kwargs)


@pytest.mark.parametrize("bad", [True, False])
def test_check_bundle_refuses_boolean_now(bad: bool) -> None:
    with pytest.raises(ValueError, match="now must be an integer"):
        _check_bundle(now=bad)


@pytest.mark.parametrize("bad", [True, False])
def test_check_bundle_refuses_boolean_max_bundle_age(bad: bool) -> None:
    with pytest.raises(ValueError, match="max_bundle_age_seconds must be an integer"):
        _check_bundle(max_bundle_age_seconds=bad)


@pytest.mark.parametrize("bad", [True, False])
def test_check_bundle_refuses_boolean_future_skew(bad: bool) -> None:
    with pytest.raises(ValueError, match="max_future_skew_seconds must be an integer"):
        _check_bundle(max_future_skew_seconds=bad)


@pytest.mark.parametrize("bad", [True, False])
def test_verify_record_refuses_boolean_bundle_age_when_bundle_is_checked(bad: bool) -> None:
    key = generate_key()
    record = sign_record(_record(), key)
    with pytest.raises(ValueError, match="max_bundle_age_seconds must be an integer"):
        verify_record(
            record,
            key_to_jwk(key),
            revocation_bundle={},
            max_bundle_age_seconds=bad,
            now=record["iat"],
        )


def test_integer_policy_controls_reach_bundle_validation() -> None:
    result = _check_bundle()
    assert result.outcome == "unverified_for_revocation"
    assert result.cause == "bundle_malformed"


def test_verify_record_integer_bundle_age_control_still_reports_bundle_shape() -> None:
    key = generate_key()
    record = sign_record(_record(), key)
    result = verify_record(
        record,
        key_to_jwk(key),
        revocation_bundle={},
        max_bundle_age_seconds=86_400,
        now=record["iat"],
    )
    assert result.revocation.outcome == "unverified_for_revocation"
    assert result.revocation.cause == "bundle_malformed"

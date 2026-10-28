"""Paired controls for option ordering and one-shot key materialization (#562)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest

from agentrust_trace import verify_record


ROOT = Path(__file__).resolve().parents[1]


def _vector() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(
            (ROOT / "examples/revocation-bundle/01-fresh-well-inside-both-bounds.json").read_text(
                encoding="utf-8"
            )
        ),
    )


def test_one_shot_bundle_keys_preserve_successful_signed_bundle_verification() -> None:
    doc = _vector()
    ctx = doc["context"]
    kwargs = {
        "now": ctx["now"],
        "revocation_bundle": ctx["bundle"],
        "max_bundle_age_seconds": ctx["max_bundle_age_seconds"],
        "max_future_skew_seconds": ctx["max_future_skew_seconds"],
    }
    control = verify_record(
        doc["records"][0],
        ctx["trusted_key"],
        trusted_bundle_keys=ctx["trusted_bundle_keys"],
        **kwargs,
    )
    one_shot = (key for key in ctx["trusted_bundle_keys"])
    actual = verify_record(
        doc["records"][0],
        ctx["trusted_key"],
        trusted_bundle_keys=one_shot,
        **kwargs,
    )
    assert control.revocation.outcome == "verified"
    assert actual == control
    assert list(one_shot) == []
    assert "bundle_digest" in actual.revocation.evidence


@pytest.mark.parametrize(
    ("options", "name"),
    [
        ({"now": -1}, "now"),
        ({"max_age_seconds": -1}, "max_age_seconds"),
        ({"max_age_seconds": True}, "max_age_seconds"),
        ({"expected_nonce": 123}, "expected_nonce"),
        ({"trusted_bundle_keys": [123]}, "trusted_bundle_keys"),
        ({"max_bundle_age_seconds": -1}, "max_bundle_age_seconds"),
        ({"max_future_skew_seconds": -1}, "max_future_skew_seconds"),
        ({"accepted_profiles": []}, "accepted_profiles"),
    ],
)
def test_invalid_options_on_valid_record_never_invoke_callbacks(
    options: dict[str, Any],
    name: str,
) -> None:
    doc = _vector()
    ctx = doc["context"]
    revocation, citation, platform = Mock(return_value=False), Mock(), Mock()
    kwargs = {"now": ctx["now"], **options}
    with pytest.raises(ValueError, match=name):
        verify_record(
            doc["records"][0],
            ctx["trusted_key"],
            revocation=revocation,
            citation_resolver=citation,
            platform_appraiser=platform,
            **kwargs,
        )
    revocation.assert_not_called()
    citation.assert_not_called()
    platform.assert_not_called()


@pytest.mark.parametrize("bad_revocation", [{"kty": "OKP"}, [123]])
def test_malformed_revocation_on_valid_record_suppresses_resolvers(
    bad_revocation: Any,
) -> None:
    doc = _vector()
    ctx = doc["context"]
    citation, platform = Mock(), Mock()
    with pytest.raises(ValueError, match="^revocation must"):
        verify_record(
            doc["records"][0],
            ctx["trusted_key"],
            now=ctx["now"],
            revocation=bad_revocation,
            citation_resolver=citation,
            platform_appraiser=platform,
        )
    citation.assert_not_called()
    platform.assert_not_called()


def test_valid_bundle_keys_without_bundle_do_not_claim_revocation_check() -> None:
    doc = _vector()
    ctx = doc["context"]
    result = verify_record(
        doc["records"][0],
        ctx["trusted_key"],
        now=ctx["now"],
        trusted_bundle_keys=(key for key in ctx["trusted_bundle_keys"]),
    )
    assert result.revocation.outcome == "no_check_performed"


def test_zero_timestamp_is_accepted_with_explicit_future_skew_budget() -> None:
    doc = _vector()
    record, key = doc["records"][0], doc["context"]["trusted_key"]
    verify_record(record, key, now=0, max_future_skew_seconds=record["iat"])
    with pytest.raises(ValueError, match="^record is dated"):
        verify_record(record, key, now=0, max_future_skew_seconds=record["iat"] - 1)


def test_valid_options_reach_revocation_and_platform_callbacks() -> None:
    doc = _vector()
    ctx = doc["context"]
    revocation = Mock(return_value=False)
    platform = Mock(side_effect=RuntimeError("test appraiser"))
    result = verify_record(
        doc["records"][0],
        ctx["trusted_key"],
        now=ctx["now"],
        revocation=revocation,
        platform_appraiser=platform,
    )
    assert revocation.call_count > 0
    platform.assert_called_once()
    assert result.revocation.outcome == "verified"

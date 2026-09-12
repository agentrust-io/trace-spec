from __future__ import annotations

import pytest

from agentrust_trace.intent_bridge import digest_jcs
from agentrust_trace.successor_observation import (
    SuccessorObservationError,
    evaluate_successor_observation,
)


def _after(
    observation: dict | None = None,
    *,
    observer: str = "observer-1",
    observed_at: int = 150,
) -> dict:
    return {
        "observation": observation or {"commit": "abc123", "reachable": True},
        "observer": observer,
        "observed_at": observed_at,
    }


def _evaluate(
    after: dict | None,
    *,
    expected: str | None = None,
    trusted: set[str] | None = None,
    executor_id: str | None = "executor-1",
    independence_required: bool = True,
    now: int = 160,
    max_age_seconds: int = 30,
    predicate=lambda obs: obs.get("reachable") is True,
):
    if expected is None:
        expected = digest_jcs(after) if after is not None else "sha256:" + "0" * 64
    return evaluate_successor_observation(
        after,
        expected_successor_digest=expected,
        trusted_observers=trusted or {"observer-1"},
        executor_id=executor_id,
        independence_required=independence_required,
        now=now,
        max_age_seconds=max_age_seconds,
        predicate=predicate,
    )


def test_trusted_bound_successor_can_establish_transition() -> None:
    outcome = _evaluate(_after())
    assert outcome.status == "established"


def test_trusted_bound_successor_can_contradict_transition() -> None:
    after = _after({"commit": "abc123", "reachable": False})
    outcome = _evaluate(after, predicate=lambda obs: obs.get("reachable") is True)
    assert outcome.status == "contradicted"


def test_missing_successor_is_not_established() -> None:
    outcome = _evaluate(None)
    assert outcome.status == "not-established"
    assert "absent" in outcome.reason


def test_substituted_successor_fails_the_binding() -> None:
    original = _after()
    expected = digest_jcs(original)
    substituted = _after({"commit": "def456", "reachable": True})
    with pytest.raises(SuccessorObservationError, match="expected digest binding"):
        _evaluate(substituted, expected=expected)


def test_observer_metadata_is_inside_the_binding() -> None:
    original = _after(observer="observer-1")
    expected = digest_jcs(original)
    relabelled = _after(observer="trusted-observer")
    with pytest.raises(SuccessorObservationError, match="expected digest binding"):
        _evaluate(relabelled, expected=expected, trusted={"trusted-observer"})


def test_observation_time_is_inside_the_binding() -> None:
    original = _after(observed_at=150)
    expected = digest_jcs(original)
    retimed = _after(observed_at=159)
    with pytest.raises(SuccessorObservationError, match="expected digest binding"):
        _evaluate(retimed, expected=expected)


@pytest.mark.parametrize(
    "observation",
    [
        {"value": 2**60},
        {"value": float("nan")},
    ],
)
def test_uncanonicalizable_successor_is_malformed(observation: dict) -> None:
    after = _after(observation)
    with pytest.raises(SuccessorObservationError, match="canonical form"):
        _evaluate(after, expected="sha256:" + "0" * 64)


def test_stale_successor_is_not_established() -> None:
    outcome = _evaluate(_after(observed_at=100), now=160, max_age_seconds=30)
    assert outcome.status == "not-established"
    assert "stale" in outcome.reason


def test_untrusted_successor_is_not_established() -> None:
    outcome = _evaluate(_after(observer="observer-2"), trusted={"observer-1"})
    assert outcome.status == "not-established"
    assert "not trusted" in outcome.reason


def test_self_observation_does_not_close_when_independence_is_required() -> None:
    after = _after(observer="executor-1")
    outcome = _evaluate(after, trusted={"executor-1"}, independence_required=True)
    assert outcome.status == "not-established"
    assert "observer is the executor" in outcome.reason


def test_self_observation_can_close_when_policy_does_not_require_independence() -> None:
    after = _after(observer="executor-1")
    outcome = _evaluate(after, trusted={"executor-1"}, independence_required=False)
    assert outcome.status == "established"


def test_missing_executor_identity_blocks_required_independence() -> None:
    outcome = _evaluate(_after(), executor_id=None, independence_required=True)
    assert outcome.status == "not-established"
    assert "executor identity is unavailable" in outcome.reason


def test_indeterminate_predicate_is_not_established() -> None:
    outcome = _evaluate(_after(), predicate=lambda obs: None)
    assert outcome.status == "not-established"
    assert "cannot decide" in outcome.reason


def test_predicate_must_return_three_state_value() -> None:
    with pytest.raises(SuccessorObservationError, match="True, False, or None"):
        _evaluate(_after(), predicate=lambda obs: "yes")

"""Experimental successor-observation evaluation for PIC/TRACE bridge review.

This module is intentionally not wired into the v1 bridge schema. It isolates the
semantics proposed in #338 so reviewers can falsify the conclusion rules before any
wire-format decision is made.
"""

from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass
from hmac import compare_digest
from typing import Any, Literal

from agentrust_trace.intent_bridge import IntentBridgeError, digest_jcs
from agentrust_trace.sign import JCS_SAFE_INTEGER

SuccessorStatus = Literal["established", "contradicted", "not-established"]


class SuccessorObservationError(ValueError):
    """The successor artifact or its binding is malformed or inconsistent."""


@dataclass(frozen=True)
class SuccessorOutcome:
    """What the verifier may conclude from a bound successor observation."""

    status: SuccessorStatus
    reason: str


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise SuccessorObservationError(f"{field} must be a sha256 digest")
    tail = value[7:]
    if len(tail) != 64 or any(c not in "0123456789abcdef" for c in tail):
        raise SuccessorObservationError(
            f"{field} must contain 64 lowercase hexadecimal characters"
        )
    return value


def _not_established(reason: str) -> SuccessorOutcome:
    return SuccessorOutcome("not-established", reason)


def evaluate_successor_observation(
    after: dict[str, Any] | None,
    *,
    expected_successor_digest: str,
    trusted_observers: Collection[str],
    executor_id: str | None,
    independence_required: bool,
    now: int,
    max_age_seconds: int,
    predicate: Callable[[dict[str, Any]], bool | None],
) -> SuccessorOutcome:
    """Evaluate a successor observation without conflating binding with closure.

    `expected_successor_digest` is supplied by the caller to represent whatever
    binding mechanism the profile eventually chooses. This prototype deliberately
    does not decide whether that digest belongs in the signed authorization, the
    transcript, or a detached observation artifact.

    The predicate is application-defined and returns True when the requested
    transition is established by the observation, False when trusted evidence
    contradicts it, and None when the observation itself does not decide it.
    """

    expected = _digest(expected_successor_digest, "expected_successor_digest")
    if not isinstance(independence_required, bool):
        raise SuccessorObservationError("independence_required must be boolean")
    for field, value in (("now", now), ("max_age_seconds", max_age_seconds)):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            or value > JCS_SAFE_INTEGER
        ):
            raise SuccessorObservationError(
                f"{field} must be a non-negative integer within the JCS safe-integer range"
            )

    if after is None:
        return _not_established("successor observation is absent")
    if not isinstance(after, dict):
        raise SuccessorObservationError("successor observation envelope must be an object")

    required = {"observation", "observer", "observed_at"}
    missing = required - set(after)
    unknown = set(after) - required
    if missing:
        raise SuccessorObservationError(
            f"successor observation is missing fields: {sorted(missing)}"
        )
    if unknown:
        raise SuccessorObservationError(
            f"successor observation contains unknown fields: {sorted(unknown)}"
        )

    observation = after["observation"]
    if not isinstance(observation, dict):
        raise SuccessorObservationError("successor observation must be an object")

    observer = after["observer"]
    if not isinstance(observer, str) or not observer:
        raise SuccessorObservationError("successor observer must be a non-empty string")

    observed_at = after["observed_at"]
    if (
        not isinstance(observed_at, int)
        or isinstance(observed_at, bool)
        or observed_at < 0
        or observed_at > JCS_SAFE_INTEGER
    ):
        raise SuccessorObservationError(
            "successor observed_at must be a non-negative integer within the JCS safe-integer range"
        )

    try:
        actual = digest_jcs(after)
    except IntentBridgeError as exc:
        raise SuccessorObservationError(
            f"successor envelope has no RFC 8785 canonical form: {exc}"
        ) from exc
    if not compare_digest(expected, actual):
        raise SuccessorObservationError(
            "successor envelope does not match the expected digest binding"
        )

    if observer not in trusted_observers:
        return _not_established("successor observer is not trusted by verifier policy")
    if observed_at > now:
        return _not_established("successor observation is dated in the future")
    if now - observed_at > max_age_seconds:
        return _not_established("successor observation is stale")

    if independence_required:
        if executor_id is None:
            return _not_established(
                "independent observation is required but executor identity is unavailable"
            )
        if observer == executor_id:
            return _not_established(
                "independent observation is required but observer is the executor"
            )

    result = predicate(observation)
    if result is True:
        return SuccessorOutcome(
            "established",
            "trusted bound successor evidence satisfies the transition predicate",
        )
    if result is False:
        return SuccessorOutcome(
            "contradicted",
            "trusted bound successor evidence contradicts the transition predicate",
        )
    if result is None:
        return _not_established("transition predicate cannot decide from this observation")
    raise SuccessorObservationError("transition predicate must return True, False, or None")

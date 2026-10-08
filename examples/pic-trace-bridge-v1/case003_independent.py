"""Bounded successor checks, independent of TRACE and the fixture generator.

Only the case-003 profile opts in. Existing corpus semantics stay frozen.
"""

from __future__ import annotations

import hashlib
import re
from hmac import compare_digest
from typing import Any

import rfc8785


def binding(after: Any, expected: Any) -> str | None:
    if not isinstance(expected, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", expected) is None:
        raise ValueError("case-003 requires a signed successor digest")
    if not isinstance(after, dict) or set(after) != {"observation", "observer", "observed_at"}:
        return "transcript_after_invalid"
    if not isinstance(after["observation"], dict):
        return "transcript_after_invalid"
    if not isinstance(after["observer"], str) or not after["observer"]:
        raise ValueError("invalid observer identity")
    timestamp = after["observed_at"]
    if type(timestamp) is not int or not 0 <= timestamp <= 9007199254740991:
        raise ValueError("invalid observation timestamp")
    actual = "sha256:" + hashlib.sha256(rfc8785.dumps(after)).hexdigest()
    if not compare_digest(expected, actual):
        return "successor_envelope_digest_mismatch"
    return None


def outcome(
    after: dict[str, Any], policy: dict[str, Any], inputs: dict[str, Any]
) -> tuple[str, str]:
    observer = after["observer"]
    age = inputs["now"] - after["observed_at"]
    if observer not in policy["trusted_observers"]:
        return "not-established", "successor_observer_untrusted"
    if age < 0:
        return "not-established", "successor_observation_future"
    if age > policy["max_age_seconds"]:
        return "not-established", "successor_observation_stale"
    if policy["independence_required"]:
        if policy["executor_id"] is None:
            return "not-established", "successor_executor_unknown"
        if observer == policy["executor_id"]:
            return "not-established", "successor_observer_not_independent"
    if policy["predicate"] != "invoice-sent-v1":
        raise ValueError("unknown case-003 predicate")
    observation = after["observation"]
    invoice = inputs["tool_call"]["arguments"]["invoice_id"]
    if observation.get("invoice_id") != invoice:
        return "not-established", "successor_predicate_undecidable"
    if observation.get("status") == "sent":
        return "established", "successor_predicate_satisfied"
    if observation.get("status") == "failed":
        return "contradicted", "successor_predicate_contradicted"
    return "not-established", "successor_predicate_undecidable"


def finish(
    runtime: dict[str, Any], inputs: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    result = dict(runtime)
    result.update(
        pic_authorization_bound=None,
        successor_envelope_bound=False,
        successor_outcome=None,
        successor_reason=None,
    )
    if runtime["classification"] != "accepted":
        if runtime["codes"] in (
            ["transcript_after_invalid"],
            ["successor_envelope_digest_mismatch"],
        ):
            result["pic_authorization_bound"] = True
        return result
    status, reason = outcome(inputs["transcript"]["after"], policy, inputs)
    result["result"] = {k: v for k, v in runtime["result"].items() if k != "transcript_bound"}
    result.update(
        pic_authorization_bound=True,
        successor_envelope_bound=True,
        successor_outcome=status,
        successor_reason=reason,
    )
    return result

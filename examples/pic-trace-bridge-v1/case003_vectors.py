"""Declared case-003 expectations; never infer targets from either verifier."""

from __future__ import annotations

import copy
from typing import Any

PROFILE = "trace.pic-trace-bridge.case003.v1"
REFERENCE_COMMIT = "cd92e16dde6658eedbe1058c903f3fce92bb3a58"


def build(legacy: Any, variant: str = "established") -> dict[str, Any]:
    inputs = legacy._base_inputs()
    observation = {"invoice_id": "INV-7", "status": "sent"}
    if variant == "empty-observation":
        observation = {}
    elif variant == "unrelated-observation":
        observation = {"unrelated": True}
    after = {"observation": observation, "observer": "invoice-observer", "observed_at": 149}
    if variant == "empty-after":
        after = {}
    inputs["transcript"]["after"] = after
    # Even the malformed envelope has a correctly signed matching digest: an
    # absent signature/digest cannot mask the intended envelope-field refusal.
    inputs["bridge"]["authorization"]["successor_observation_digest"] = legacy._digest(after)
    legacy._resign(inputs)
    policy = {
        "trusted_observers": ["invoice-observer"],
        "executor_id": "invoice-executor",
        "independence_required": True,
        "max_age_seconds": 10,
        "predicate": "invoice-sent-v1",
    }
    refused = variant == "empty-after"
    status = "established" if variant == "established" else "not-established"
    runtime = {
        "classification": "mismatch" if refused else "accepted",
        "codes": ["transcript_after_invalid"] if refused else [],
        "result": None
        if refused
        else {
            "authorization_id": "auth-206",
            "tool": "send_invoice",
            "impact": "external-side-effect",
        },
        "pic_authorization_bound": True,
        "successor_envelope_bound": not refused,
        "successor_outcome": None if refused else status,
        "successor_reason": None
        if refused
        else (
            "successor_predicate_satisfied"
            if status == "established"
            else "successor_predicate_undecidable"
        ),
    }
    case = legacy._case(
        slug="accepted-bound-successor" if variant == "established" else variant,
        description={
            "established": "Trusted fresh independent evidence establishes the fixture transition.",
            "empty-after": "Literal after {} is refused for missing successor-envelope fields.",
            "empty-observation": "A bound empty observation does not establish the transition.",
            "unrelated-observation": (
                "A bound unrelated observation does not establish the transition."
            ),
        }[variant],
        inputs=inputs,
        bridge_schema_valid=True,
        runtime=runtime,
        rule="transcript_after_invalid" if refused else None,
        variant=variant.replace("-", "_"),
        declared_defect="missing_successor_fields_accepted" if refused else None,
    )
    case["profile"] = PROFILE
    case["successor_policy"] = policy
    case["reproducibility"]["successor_observation_digest"] = legacy._material(
        after, not_object="successor_not_object", not_jcs="successor_not_jcs"
    )
    return copy.deepcopy(case)


def companions(legacy: Any) -> list[dict[str, Any]]:
    return [
        {"id": f"TRACE-PIC-BRIDGE-003{suffix}", **build(legacy, variant)}
        for suffix, variant in (
            ("a", "empty-after"),
            ("b", "empty-observation"),
            ("c", "unrelated-observation"),
        )
    ]

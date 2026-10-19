"""Binding resolution and endpoint validation in manifest requirements combination."""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from typing import Any

import pytest

from prototype import verifier_token as v
from prototype.manifest_requirements import combine_requirements
from tests.test_verifier_token_profile import (
    context as _raw_context,
    fixture,
    g,
    rebind as _raw_rebind,
)

__all__ = ["fixture"]


def context(f: dict[str, Any]) -> v.VerificationContext:
    ctx: v.VerificationContext = _raw_context(f)  # type: ignore[no-untyped-call]
    return ctx


def rebind(token: dict[str, Any]) -> None:
    _raw_rebind(token)  # type: ignore[no-untyped-call]


@dataclass(frozen=True)
class DeclaredComponent:
    component_id: str
    component_type: str
    required: bool
    accepted_profiles: tuple[str, ...]
    accepted_appraisal_authorities: tuple[str, ...]
    maximum_age_seconds: int
    expected_observed_digest: str | None = None


@dataclass(frozen=True)
class DeclaredBinding:
    source: str
    target: str
    relationship: str
    accepted_methods: tuple[str, ...]


@dataclass(frozen=True)
class DeclaredRequirements:
    combination_policy_ref: str
    components: tuple[DeclaredComponent, ...]
    required_bindings: tuple[DeclaredBinding, ...]


@dataclass(frozen=True)
class VerifiedEnvelope:
    requirements: DeclaredRequirements


def make_verified(
    local: v.Requirements,
    policy: v.Policy,
    bindings: list[DeclaredBinding],
) -> VerifiedEnvelope:
    components = tuple(
        DeclaredComponent(
            component_id=c.component_id,
            component_type=c.component_type,
            required=c.required,
            accepted_profiles=tuple(c.accepted_profiles),
            accepted_appraisal_authorities=tuple(c.accepted_authorities),
            maximum_age_seconds=c.maximum_age_seconds,
            expected_observed_digest=c.expected_observed_digest,
        )
        for c in local.components
    )
    return VerifiedEnvelope(
        requirements=DeclaredRequirements(
            combination_policy_ref=policy.id,
            components=components,
            required_bindings=tuple(bindings),
        )
    )


def test_multi_method_accepted_methods_emits_single_binding_and_verifies(
    fixture: dict[str, Any],
) -> None:
    ctx = context(fixture)
    local_without_bindings = ctx.requirements.model_copy(update={"bindings": []})
    verified = make_verified(
        local_without_bindings,
        ctx.policy,
        [
            DeclaredBinding(
                source="runtime.cpu",
                target="runtime.accelerator.0",
                relationship="same-workload",
                accepted_methods=("same-instance-v1", "same-evidence-v1"),
            )
        ],
    )
    merged = combine_requirements(verified, local_without_bindings, ctx.policy)
    assert len(merged.bindings) == 1
    assert merged.bindings[0] == v.BindingRequirement(
        source="runtime.cpu",
        target="runtime.accelerator.0",
        relationship="same-workload",
        method="same-evidence-v1",
    )

    token_payload = copy.deepcopy(fixture["token"])
    token_payload["bindings"][0]["method"] = "same-evidence-v1"
    rebind(token_payload)
    question = v.canonical_digest(
        {
            "purpose": "protected-action",
            "audience": token_payload["aud"],
            "policy": ctx.policy.model_dump(),
            "requirements": merged.model_dump(),
        }
    )
    token_payload["verification_context_hash"] = question
    raw = g.envelope(token_payload, g.ISSUER)
    verified_token = v.verify_token(
        raw,
        replace(ctx, requirements=merged, question_digest=question),
        g.NOW,
    )
    assert [b.method for b in verified_token.bindings] == ["same-evidence-v1"]


def test_manifest_tightens_local_same_instance_binding_to_same_evidence(
    fixture: dict[str, Any],
) -> None:
    ctx = context(fixture)
    assert [b.method for b in ctx.requirements.bindings] == ["same-instance-v1"]
    verified = make_verified(
        ctx.requirements,
        ctx.policy,
        [
            DeclaredBinding(
                source="runtime.cpu",
                target="runtime.accelerator.0",
                relationship="same-workload",
                accepted_methods=("same-evidence-v1",),
            )
        ],
    )
    merged = combine_requirements(verified, ctx.requirements, ctx.policy)
    assert [b.model_dump() for b in merged.bindings] == [
        {
            "source": "runtime.cpu",
            "target": "runtime.accelerator.0",
            "relationship": "same-workload",
            "method": "same-evidence-v1",
        }
    ]


def test_manifest_cannot_weaken_local_same_evidence_binding(
    fixture: dict[str, Any],
) -> None:
    ctx = context(fixture)
    local_strong = ctx.requirements.model_copy(
        update={
            "bindings": [
                v.BindingRequirement(
                    source="runtime.cpu",
                    target="runtime.accelerator.0",
                    relationship="same-workload",
                    method="same-evidence-v1",
                )
            ]
        }
    )
    verified = make_verified(
        local_strong,
        ctx.policy,
        [
            DeclaredBinding(
                source="runtime.cpu",
                target="runtime.accelerator.0",
                relationship="same-workload",
                accepted_methods=("same-instance-v1",),
            )
        ],
    )
    with pytest.raises(v.ProfileError, match="^manifest_requirement_untrusted$"):
        combine_requirements(verified, local_strong, ctx.policy)


@pytest.mark.parametrize(
    "source,target",
    [
        ("runtime.unconfigured", "runtime.accelerator.0"),
        ("runtime.cpu", "runtime.unconfigured"),
    ],
)
def test_unconfigured_binding_endpoint_raises_profile_error(
    fixture: dict[str, Any], source: str, target: str
) -> None:
    ctx = context(fixture)
    verified = make_verified(
        ctx.requirements,
        ctx.policy,
        [
            DeclaredBinding(
                source=source,
                target=target,
                relationship="same-workload",
                accepted_methods=("same-instance-v1",),
            )
        ],
    )
    with pytest.raises(v.ProfileError, match="^manifest_component_unconfigured$"):
        combine_requirements(verified, ctx.requirements, ctx.policy)


@pytest.mark.parametrize(
    "source,target,relationship",
    [
        ("runtime.cpu", "runtime.cpu", "same-workload"),
        ("runtime.cpu", "runtime.accelerator.0", "different-workload"),
    ],
)
def test_self_or_unsupported_relationship_binding_raises_binding_endpoint(
    fixture: dict[str, Any], source: str, target: str, relationship: str
) -> None:
    ctx = context(fixture)
    verified = make_verified(
        ctx.requirements,
        ctx.policy,
        [
            DeclaredBinding(
                source=source,
                target=target,
                relationship=relationship,
                accepted_methods=("same-instance-v1",),
            )
        ],
    )
    with pytest.raises(v.ProfileError, match="^binding_endpoint$"):
        combine_requirements(verified, ctx.requirements, ctx.policy)


@pytest.mark.parametrize(
    "accepted_methods",
    [
        ("unknown-method",),
        ("same-instance-v1", "unknown-method"),
        (),
    ],
)
def test_unknown_or_empty_binding_methods_raise_profile_error(
    fixture: dict[str, Any], accepted_methods: tuple[str, ...]
) -> None:
    ctx = context(fixture)
    verified = make_verified(
        ctx.requirements,
        ctx.policy,
        [
            DeclaredBinding(
                source="runtime.cpu",
                target="runtime.accelerator.0",
                relationship="same-workload",
                accepted_methods=accepted_methods,
            )
        ],
    )
    with pytest.raises(v.ProfileError, match="^manifest_requirement_untrusted$"):
        combine_requirements(verified, ctx.requirements, ctx.policy)

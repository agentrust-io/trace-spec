"""RFC-0003 bridge: signed intent can tighten, never authorize, local policy."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from pydantic import ValidationError

from . import verifier_token as v

_METHOD_STRENGTH: dict[str, int] = {
    "same-instance-v1": 1,
    "same-evidence-v1": 2,
}


class _DeclaredComponent(Protocol):
    @property
    def component_id(self) -> str: ...
    @property
    def component_type(self) -> str: ...
    @property
    def required(self) -> bool: ...
    @property
    def accepted_profiles(self) -> Sequence[str]: ...
    @property
    def accepted_appraisal_authorities(self) -> Sequence[str]: ...
    @property
    def maximum_age_seconds(self) -> int: ...
    @property
    def expected_observed_digest(self) -> str | None: ...


class _DeclaredBinding(Protocol):
    @property
    def source(self) -> str: ...
    @property
    def target(self) -> str: ...
    @property
    def relationship(self) -> str: ...
    @property
    def accepted_methods(self) -> Sequence[str]: ...


class _DeclaredRequirements(Protocol):
    @property
    def combination_policy_ref(self) -> str: ...
    @property
    def components(self) -> Sequence[_DeclaredComponent]: ...
    @property
    def required_bindings(self) -> Sequence[_DeclaredBinding]: ...


class _VerifiedRequirements(Protocol):
    @property
    def requirements(self) -> _DeclaredRequirements: ...


def combine_requirements(
    verified: _VerifiedRequirements, local: v.Requirements, policy: v.Policy
) -> v.Requirements:
    """Intersect profile/authority permissions and retain both required sets.

    `verified` must come from Agent Manifest's verify_evidence_manifest, never an
    unverified payload or token. Manifest declarations do not add trust anchors.
    Components absent from local configuration cannot become trusted by declaration.
    """
    if verified.requirements.combination_policy_ref != policy.id:
        raise v.ProfileError("manifest_combination_policy_mismatch")
    local_by_id = {c.component_id: c for c in local.components}
    merged = {c.component_id: c.model_dump() for c in local.components}
    for declared in verified.requirements.components:
        trusted = local_by_id.get(declared.component_id)
        if trusted is None:
            raise v.ProfileError("manifest_component_unconfigured")
        if declared.component_type != trusted.component_type:
            raise v.ProfileError("manifest_component_type_mismatch")
        profiles = sorted(set(trusted.accepted_profiles) & set(declared.accepted_profiles))
        authorities = sorted(
            set(trusted.accepted_authorities) & set(declared.accepted_appraisal_authorities)
        )
        if not profiles or not authorities:
            raise v.ProfileError("manifest_requirement_untrusted")
        if (
            declared.expected_observed_digest is not None
            and trusted.expected_observed_digest is not None
            and declared.expected_observed_digest != trusted.expected_observed_digest
        ):
            raise v.ProfileError("manifest_observation_requirement_mismatch")
        merged[declared.component_id].update(
            required=trusted.required or declared.required,
            accepted_profiles=profiles,
            accepted_authorities=authorities,
            maximum_age_seconds=min(trusted.maximum_age_seconds, declared.maximum_age_seconds),
            expected_observed_digest=(
                trusted.expected_observed_digest or declared.expected_observed_digest
            ),
        )
    bindings_by_pair: dict[tuple[str, str, str], str] = {}
    for existing in local.bindings:
        pair: tuple[str, str, str] = (existing.source, existing.target, existing.relationship)
        previous = bindings_by_pair.get(pair)
        if previous is None or _METHOD_STRENGTH[existing.method] > _METHOD_STRENGTH[previous]:
            bindings_by_pair[pair] = existing.method
    declared_by_pair: dict[tuple[str, str, str], set[str]] = {}
    for declared_binding in verified.requirements.required_bindings:
        if (
            declared_binding.source not in local_by_id
            or declared_binding.target not in local_by_id
        ):
            raise v.ProfileError("manifest_component_unconfigured")
        if (
            declared_binding.source == declared_binding.target
            or declared_binding.relationship != "same-workload"
        ):
            raise v.ProfileError("binding_endpoint")
        accepted = [
            m
            for m in declared_binding.accepted_methods
            if isinstance(m, str) and m in _METHOD_STRENGTH
        ]
        if not accepted or len(accepted) != len(declared_binding.accepted_methods):
            raise v.ProfileError("manifest_requirement_untrusted")
        pair = (
            declared_binding.source,
            declared_binding.target,
            declared_binding.relationship,
        )
        if pair in declared_by_pair:
            declared_by_pair[pair] &= set(accepted)
        else:
            declared_by_pair[pair] = set(accepted)
        if not declared_by_pair[pair]:
            raise v.ProfileError("manifest_requirement_untrusted")
    for pair, accepted_set in declared_by_pair.items():
        local_method = bindings_by_pair.get(pair)
        min_strength = 0 if local_method is None else _METHOD_STRENGTH[local_method]
        compatible = [m for m in accepted_set if _METHOD_STRENGTH[m] >= min_strength]
        if not compatible:
            raise v.ProfileError("manifest_requirement_untrusted")
        bindings_by_pair[pair] = max(compatible, key=lambda m: _METHOD_STRENGTH[m])
    bindings = {
        (source, target, relationship, method): {
            "source": source,
            "target": target,
            "relationship": relationship,
            "method": method,
        }
        for (source, target, relationship), method in bindings_by_pair.items()
    }
    try:
        return v.Requirements.model_validate(
            {
                "components": [merged[k] for k in sorted(merged)],
                "bindings": [bindings[k] for k in sorted(bindings)],
                "allow_warnings": local.allow_warnings,
            }
        )
    except ValidationError as exc:
        raise v.ProfileError("input_invalid") from exc

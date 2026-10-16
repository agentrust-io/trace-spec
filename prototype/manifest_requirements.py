"""RFC-0003 bridge: signed intent can tighten, never authorize, local policy."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_manifest.evidence_requirements import VerifiedRequirements

from . import verifier_token as v


def combine_requirements(
    verified: "VerifiedRequirements", local: v.Requirements, policy: v.Policy
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
    bindings = {
        (b.source, b.target, b.relationship, b.method): b.model_dump() for b in local.bindings
    }
    for declared in verified.requirements.required_bindings:
        for method in declared.accepted_methods:
            key = (declared.source, declared.target, declared.relationship, method)
            bindings[key] = {
                "source": declared.source,
                "target": declared.target,
                "relationship": declared.relationship,
                "method": method,
            }
    return v.Requirements.model_validate(
        {
            "components": [merged[k] for k in sorted(merged)],
            "bindings": [bindings[k] for k in sorted(bindings)],
            "allow_warnings": local.allow_warnings,
        }
    )

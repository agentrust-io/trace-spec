"""Signed requirements cannot weaken or replace independent relying-party trust."""

import copy
from unittest.mock import patch

import pytest

pytest.importorskip("agent_manifest.evidence_requirements", reason="needs Agent Manifest")

from prototype import verifier_token as v
from prototype.manifest_requirements import combine_requirements
from tests.test_verifier_token_profile import context, fixture, g, unb64
from tools.run_verifier_token_poc import FixtureClock

am = pytest.importorskip("agent_manifest")
verify_evidence_manifest = pytest.importorskip(
    "agent_manifest.evidence_requirements"
).verify_evidence_manifest

__all__ = ["fixture"]


def signed_packet(f, modify=lambda manifest: None):
    manifest_key = am.Ed25519KeyPair(g.ROGUE, g.ROGUE.public_key())
    keys = {manifest_key.key_id: manifest_key.public_b64url()}
    manifest = am.verify_cose_manifest(unb64(f["manifest_b64"]), keys).manifest
    manifest["profile"] = "evidence-requirements-experimental-v1"
    manifest["artifacts"]["system_prompt"].update(
        version="1", classification="public", bound_at=manifest["issued_at"]
    )
    manifest["artifacts"]["policy_bundle"].update(
        version="1",
        policy_language="cedar",
        enforcement_mode="enforce",
        bound_at=manifest["issued_at"],
    )
    manifest["artifacts"]["model_identity"].update(
        provider="test",
        model_id="test-model",
        model_attestation_type="provider-asserted",
        bound_at=manifest["issued_at"],
    )
    requirements = f["requirements"]
    components = []
    for component in requirements["components"]:
        declared = dict(component)
        declared["accepted_appraisal_authorities"] = declared.pop("accepted_authorities")
        components.append(declared)
    manifest["evidence_requirements"] = {
        "components": components,
        "required_bindings": [
            {
                "source": b["source"],
                "target": b["target"],
                "relationship": b["relationship"],
                "accepted_methods": [b["method"]],
            }
            for b in requirements["bindings"]
        ],
        "combination_policy_ref": f["token"]["appraisal_policy"]["id"],
    }
    modify(manifest)
    am.Manifest.model_validate(manifest)
    raw = am.sign_cose_sign1(manifest, manifest_key)
    ctx = am.VerificationContext(
        system_prompt_hash="sha256:" + "a" * 64,
        policy_bundle_hash=manifest["artifacts"]["policy_bundle"]["hash"],
        model_version="test-model",
        tool_catalog_hash=manifest["artifacts"].get("tool_manifest", {}).get("catalog_hash"),
        enforcement_mode="enforce",
        trusted_keys=keys,
        trusted_key_issuers={manifest_key.key_id: [manifest["issuer"]]},
    )
    with patch("agent_manifest._verify.datetime", FixtureClock):
        verified = verify_evidence_manifest(raw, ctx, am.RevocationStore())
    return raw, verified


def test_verified_signed_intent_drives_token_requirements(fixture):
    raw, verified = signed_packet(fixture)
    ctx = context(fixture)
    requirements = combine_requirements(verified, ctx.requirements, ctx.policy)
    assert {c.component_id: c for c in requirements.components} == {
        c.component_id: c for c in ctx.requirements.components
    }
    assert requirements.bindings == ctx.requirements.bindings
    assert requirements.allow_warnings == ctx.requirements.allow_warnings
    assert verified.manifest_digest == v.digest(raw)
    assert dict(verified.artifact_results)["system_prompt"] == "MATCH"


@pytest.mark.parametrize("change", ["profiles", "authority", "policy", "type", "unconfigured"])
def test_signed_declarations_cannot_supply_trust(fixture, change):
    def modify(manifest):
        block = manifest["evidence_requirements"]
        component = block["components"][0]
        if change == "profiles":
            component["accepted_profiles"] = ["urn:unknown:evidence"]
        elif change == "authority":
            component["accepted_appraisal_authorities"] = ["https://untrusted.example"]
        elif change == "policy":
            block["combination_policy_ref"] = "urn:other:policy"
        elif change == "type":
            component["component_type"] = "code"
        else:
            added = copy.deepcopy(component)
            added["component_id"] = "runtime.extra"
            block["components"].append(added)

    _, verified = signed_packet(fixture, modify)
    ctx = context(fixture)
    with pytest.raises(v.ProfileError):
        combine_requirements(verified, ctx.requirements, ctx.policy)


def test_local_required_and_freshness_bounds_survive_weaker_manifest(fixture):
    def weaken(manifest):
        for component in manifest["evidence_requirements"]["components"]:
            component["required"] = False
            component["maximum_age_seconds"] = 1000
        manifest["evidence_requirements"]["required_bindings"] = []

    _, verified = signed_packet(fixture, weaken)
    ctx = context(fixture)
    merged = combine_requirements(verified, ctx.requirements, ctx.policy)
    assert {c.component_id: c for c in merged.components} == {
        c.component_id: c for c in ctx.requirements.components
    }
    assert merged.bindings == ctx.requirements.bindings
    assert merged.allow_warnings == ctx.requirements.allow_warnings


def test_manifest_can_tighten_local_optional_requirement(fixture):
    _, verified = signed_packet(fixture)
    ctx = context(fixture)
    local = ctx.requirements.model_copy(deep=True)
    local.components[0] = local.components[0].model_copy(
        update={"required": False, "maximum_age_seconds": 200}
    )
    merged = combine_requirements(verified, local, ctx.policy)
    cpu = next(c for c in merged.components if c.component_id == "runtime.cpu")
    assert cpu.required and cpu.maximum_age_seconds == 120


def test_signed_observation_cannot_override_local_pin(fixture):
    def pin(manifest):
        manifest["evidence_requirements"]["components"][0]["expected_observed_digest"] = (
            "sha256:" + "a" * 64
        )

    _, verified = signed_packet(fixture, pin)
    ctx = context(fixture)
    local = ctx.requirements.model_copy(deep=True)
    local.components[0] = local.components[0].model_copy(
        update={"expected_observed_digest": "sha256:" + "b" * 64}
    )
    with pytest.raises(v.ProfileError, match="manifest_observation_requirement_mismatch"):
        combine_requirements(verified, local, ctx.policy)


@pytest.mark.parametrize("observation", [None, "sha256:" + "f" * 64])
def test_missing_or_substituted_observation_is_rejected(fixture, observation):
    from dataclasses import replace
    from tests.test_verifier_token_profile import rebind

    ctx = context(fixture)
    requirements = ctx.requirements.model_copy(deep=True)
    requirements.components[0] = requirements.components[0].model_copy(
        update={"expected_observed_digest": fixture["token"]["components"][0]["observed_digest"]}
    )
    token = copy.deepcopy(fixture["token"])
    token["components"][0]["observed_digest"] = observation
    rebind(token)
    with pytest.raises(v.ProfileError, match="component_observation_mismatch"):
        v.verify_token(g.envelope(token, g.ISSUER), replace(ctx, requirements=requirements), g.NOW)

"""Stage 4 on real Azure SEV-SNP packets: same-evidence-v1 and delegated appraisal.

The application.code component comes from `azure_execution_binding.execution_component`
and the runtime.cpu component from `snp_collateral.tcb_component`. Both cite the
canonical digest of the packet they appraised, so a same-evidence-v1 binding between
them holds only when both were derived from the same packet. Keys, the manifest and
the verification question are test inputs; the packets and CRLs are the saved captures.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prototype import azure_execution_binding as x
from prototype import snp_collateral as s
from prototype import verifier_token as v
from tests.test_azure_execution_binding import AUTHORITY, ISSUED
from tests.test_azure_execution_binding import FIXTURES as EXEC
from tests.test_azure_execution_binding import component as code_component
from tests.test_snp_collateral import FIXTURES as SNP
from tests.test_snp_collateral import NOW as COLLATERAL_NOW
from tests.test_snp_collateral import SB_3016
from tests.test_snp_collateral import policy as collateral_policy

ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
HOLDER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
APPRAISER = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
COLLATERAL_AUTHORITY = "https://collateral-appraiser.example.test"
MANIFEST = b"stage-4 test manifest bytes"
QUESTION = "sha256:" + "5" * 64
POLICY = v.Policy(
    id="https://verifier.example.test/policy", version="1", digest="sha256:" + "c" * 64
)
PACKETS = {
    "b1": EXEC / "b1-approved-packet.json",
    "b2": EXEC / "b2-substituted-relabel-packet.json",
    "milan": SNP / "live-milan-packet.json",
}


def packet(name: str) -> dict[str, Any]:
    return json.loads(PACKETS[name].read_text())


def cpu_component(
    name: str, instance: str, *, authority: str = AUTHORITY, floor: s.TcbFloor | None = None
) -> v.Component:
    """runtime.cpu from the collateral appraisal of the named packet."""
    pol = collateral_policy()
    if floor is not None:
        pol = collateral_policy(floors={"Milan": floor, "Genoa": floor})
    result = s.appraise_collateral(packet(name), pol, now=COLLATERAL_NOW)
    return s.tcb_component(result, packet(name), instance=instance, authority=authority, now=ISSUED)


def requirements(method: str = "same-evidence-v1", cpu_authority: str = AUTHORITY):
    return v.Requirements(
        components=[
            v.Requirement(
                component_id="application.code",
                component_type="code",
                required=True,
                accepted_profiles=[x.PROFILE],
                accepted_authorities=[AUTHORITY],
                maximum_age_seconds=300,
            ),
            v.Requirement(
                component_id="runtime.cpu",
                component_type="runtime",
                required=True,
                accepted_profiles=[s.PROFILE],
                accepted_authorities=[cpu_authority],
                maximum_age_seconds=300,
            ),
        ],
        bindings=[
            v.BindingRequirement(
                source="runtime.cpu",
                target="application.code",
                relationship="same-workload",
                method=method,
            )
        ],
        allow_warnings=False,
    )


def token_for(
    code: v.Component, cpu: v.Component, reqs: v.Requirements, status: str = "affirming"
) -> v.Token:
    # As the verifier sees them: every member the issuer signs is present on the wire.
    code, cpu = (v.Component.model_validate(c.model_dump(mode="json")) for c in (code, cpu))
    method = reqs.bindings[0].method
    binding = v.Binding(
        source="runtime.cpu",
        target="application.code",
        relationship="same-workload",
        method=method,
        status="affirming",
        digest=v.binding_digest(cpu, code, method),
        fresh_until=ISSUED + 300,
    )
    token = v.Token(
        profile=v.PROFILE,
        iss=AUTHORITY,
        sub="spiffe://example.test/agent/one",
        instance=code.instance,
        iat=ISSUED,
        exp=ISSUED + 120,
        jti="stage4-token",
        aud="spiffe://example.test/gateway/one",
        cnf=v.holder_key(HOLDER),
        manifest=v.ManifestRef(
            id="stage4-manifest",
            media_type="application/agent-manifest+cose",
            version="0.2",
            digest=v.digest(MANIFEST),
        ),
        verification_context_hash=QUESTION,
        appraisal_policy=POLICY,
        components=[code, cpu],
        bindings=[binding],
        composite_appraisal=v.Composite(
            status=status,
            required_components=["application.code", "runtime.cpu"],
            policy=POLICY,
            fresh_until=ISSUED + 120,
        ),
    )
    return token


def context(reqs: v.Requirements, appraisers=None) -> v.VerificationContext:
    issuer = v.TrustedIssuer(AUTHORITY, ISSUER.public_key(), ISSUED - 1, ISSUED + 300)
    return v.VerificationContext(
        audience="spiffe://example.test/gateway/one",
        subject="spiffe://example.test/agent/one",
        instance=code_component("b1-approved").instance,
        manifest_bytes=MANIFEST,
        manifest_id="stage4-manifest",
        manifest_valid_until=ISSUED + 300,
        question_digest=QUESTION,
        policy=POLICY,
        requirements=reqs,
        trusted_issuers={(AUTHORITY, v.key_id(ISSUER)): issuer},
        status_check=lambda token, now: True,
        trusted_appraisers=appraisers or {},
    )


def verify(token: v.Token, ctx: v.VerificationContext) -> v.Token:
    return v.verify_token(v.sign_payload(token, ISSUER), ctx, ISSUED + 1)


def test_code_and_cpu_from_one_real_packet_cite_one_evidence_digest():
    code = code_component("b1-approved")
    cpu = cpu_component("b1", code.instance)
    digest = v.canonical_digest(packet("b1"))
    assert [e.digest for e in code.evidence_refs] == [digest]
    assert [e.digest for e in cpu.evidence_refs] == [digest]
    # Two appraisal profiles over one evidence object: only the digest is shared.
    assert code.evidence_refs[0].profile != cpu.evidence_refs[0].profile


def test_same_evidence_binding_holds_on_the_b1_packet():
    code = code_component("b1-approved")
    cpu = cpu_component("b1", code.instance)
    # The honest verdict under the AMD-SB-3016 floor is contraindicated.
    assert cpu.status == "contraindicated"
    token = verify(
        token_for(code, cpu, requirements(), status="contraindicated"), context(requirements())
    )
    assert token.bindings[0].method == "same-evidence-v1"
    assert token.composite_appraisal.status == "contraindicated"


def test_same_evidence_binding_affirms_when_the_platform_meets_the_configured_floor():
    # A counterfactual relying-party floor the Genoa platform meets (TCB[SNP] 0x17),
    # not a claim that it meets AMD-SB-3016. It shows the affirming path end to end.
    code = code_component("b1-approved")
    cpu = cpu_component("b1", code.instance, floor=s.TcbFloor(snp=0x17, source=SB_3016))
    assert cpu.status == "affirming"
    token = verify(token_for(code, cpu, requirements()), context(requirements()))
    assert token.composite_appraisal.status == "affirming"


@pytest.mark.parametrize("other", ["b2", "milan"])
def test_cpu_from_another_packet_is_evidence_disjoint(other):
    code = code_component("b1-approved")
    cpu = cpu_component(other, code.instance)
    assert cpu.evidence_refs[0].digest != code.evidence_refs[0].digest
    token = token_for(code, cpu, requirements(), status="contraindicated")
    with pytest.raises(v.ProfileError, match="^binding_evidence_disjoint$"):
        verify(token, context(requirements()))
    # The same pair under same-instance-v1 is accepted: that method asserts, it does not
    # bind the two appraisals to one evidence object.
    weaker = requirements("same-instance-v1")
    accepted = verify(token_for(code, cpu, weaker, status="contraindicated"), context(weaker))
    assert accepted.bindings[0].method == "same-instance-v1"


def test_same_instance_binding_does_not_satisfy_a_same_evidence_requirement():
    code = code_component("b1-approved")
    cpu = cpu_component("b1", code.instance)
    weaker = token_for(code, cpu, requirements("same-instance-v1"), status="contraindicated")
    with pytest.raises(v.ProfileError, match="^undeclared_binding$"):
        verify(weaker, context(requirements()))


# ------------------------------- delegated collateral appraiser on real data


def appraiser(**changes) -> dict:
    entry = v.TrustedAppraiser(
        authority=COLLATERAL_AUTHORITY,
        key=APPRAISER.public_key(),
        profiles=frozenset({s.PROFILE}),
        component_types=frozenset({"runtime"}),
        valid_from=ISSUED - 1,
        valid_until=ISSUED + 300,
    )
    entry = replace(entry, **changes)
    return {(entry.authority, v.key_id(entry.key)): entry}


def delegated_cpu(code: v.Component, **floor) -> v.Component:
    """The collateral appraiser signs runtime.cpu; the verifier only carries it."""
    cpu = cpu_component("b1", code.instance, authority=COLLATERAL_AUTHORITY, **floor)
    signed = v.ComponentAppraisal(
        profile=v.APPRAISAL_PROFILE, iss=COLLATERAL_AUTHORITY, component=cpu
    )
    envelope = v.sign_payload(signed, APPRAISER)
    text = base64.urlsafe_b64encode(envelope).decode().rstrip("=")
    return cpu.model_copy(update={"appraisal": text})


def test_delegated_collateral_appraisal_and_same_evidence_on_real_data():
    code = code_component("b1-approved")
    cpu = delegated_cpu(code, floor=s.TcbFloor(snp=0x17, source=SB_3016))
    reqs = requirements(cpu_authority=COLLATERAL_AUTHORITY)
    token = verify(token_for(code, cpu, reqs), context(reqs, appraiser()))
    assert token.components[1].authority == COLLATERAL_AUTHORITY
    assert token.composite_appraisal.status == "affirming"
    # Without the configured appraiser the same token is honestly unverifiable.
    with pytest.raises(v.ProfileError, match="^composite_inconsistent$"):
        verify(token_for(code, cpu, reqs), context(reqs))
    honest = verify(token_for(code, cpu, reqs, status="unverifiable"), context(reqs))
    assert honest.composite_appraisal.status == "unverifiable"


def test_carrier_cannot_upgrade_the_delegated_verdict():
    code = code_component("b1-approved")
    cpu = delegated_cpu(code)  # AMD-SB-3016 floor: the appraiser signed contraindicated
    assert cpu.status == "contraindicated"
    upgraded = cpu.model_copy(update={"status": "affirming", "reasons": []})
    reqs = requirements(cpu_authority=COLLATERAL_AUTHORITY)
    with pytest.raises(v.ProfileError, match="^component_appraisal_mismatch$"):
        verify(token_for(code, upgraded, reqs), context(reqs, appraiser()))


@pytest.mark.parametrize(
    "grant",
    [
        {"component_types": frozenset({"accelerator"})},
        {"profiles": frozenset({x.PROFILE})},
        {"valid_from": ISSUED + 2, "valid_until": ISSUED + 300},
    ],
)
def test_out_of_grant_appraisal_is_unverifiable(grant):
    code = code_component("b1-approved")
    cpu = delegated_cpu(code, floor=s.TcbFloor(snp=0x17, source=SB_3016))
    reqs = requirements(cpu_authority=COLLATERAL_AUTHORITY)
    ctx = context(reqs, appraiser(**grant))
    token = verify(token_for(code, cpu, reqs, status="unverifiable"), ctx)
    assert token.composite_appraisal.status == "unverifiable"


@pytest.mark.parametrize(
    "field,value",
    [
        ("authority", ""),
        ("profiles", frozenset()),
        ("profiles", {s.PROFILE}),
        ("component_types", frozenset({"hypervisor"})),
        ("valid_until", ISSUED - 1),
        ("key", b"not a key"),
    ],
)
def test_appraiser_configuration_refuses_malformed_fields(field, value):
    with pytest.raises(v.ProfileError, match="^appraiser_configuration_invalid$"):
        appraiser(**{field: value})


def test_appraiser_mapping_must_match_its_entry():
    entry = next(iter(appraiser().values()))
    reqs = requirements()
    for mapping in (
        {("https://other.example.test", v.key_id(APPRAISER)): entry},
        {(COLLATERAL_AUTHORITY, v.key_id(ISSUER)): entry},
        {(COLLATERAL_AUTHORITY, v.key_id(APPRAISER)): "not an appraiser"},
    ):
        with pytest.raises(v.ProfileError, match="^context_configuration_invalid$"):
            context(reqs, mapping)

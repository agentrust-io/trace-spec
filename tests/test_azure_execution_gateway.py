"""Real Azure execution evidence through the production cMCP builder, offline.

The code component comes from the saved on-hardware packets through
execution_component(), or for the legacy case through WCM's PCR 23 verifier;
no hardware result is synthesized. The holder keys never left the VMs, so the
token's cnf is a local stand-in. execution_component() refuses that pairing at
the issuer (token_holder_mismatch, tested below); the gateway cannot see it,
because a component carries no holder. What this isolates is the gateway's
reaction to the component's profile and signer.
"""

import asyncio
import copy
import json
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("httpx", reason="cross-repository gateway test")
pytest.importorskip("cmcp_runtime.manifest_catalog", reason="needs cMCP TRACE gate")
pytest.importorskip("agent_manifest.evidence_requirements", reason="needs Agent Manifest")
import httpx  # noqa: E402

from prototype import azure_execution_binding as x
from prototype import verifier_token as v
from prototype.cmcp_bootstrap import build_protected_server
from cmcp_runtime.manifest_catalog import manifest_catalog_binding
from tests.test_azure_execution_binding import AUTHORITY, genoa_trust, real, real_policy
from tests.test_cmcp_trace_gate import deployment, holder_proof
from tests.test_manifest_requirements_bridge import am, signed_packet
from tests.test_verifier_token_profile import fixture, g
from tools.run_verifier_token_poc import FixtureClock

__all__ = ["deployment", "fixture"]

LEGACY = "urn:wcm:azure-snp-vtpm-pcr23:legacy"
AGENT = "sha256:" + real_policy().required_application
AGE = 120


def azure_component():
    packet, challenge = real("b1-approved")
    return x.execution_component(
        packet,
        genoa_trust(),
        real_policy(),
        expected_challenge=challenge,
        expected_holder=bytes.fromhex(packet["holder_public_hex"]),
        authority=AUTHORITY,
        now=g.NOW,
        max_age=AGE,
    )


def legacy_component():
    """What a PCR 23 issuer mints for the substituted agent: it claims the approved digest."""
    import wcm

    packet, challenge = real("b2-substituted-relabel")
    trust = genoa_trust()
    result = wcm.AzureSnpVtpmVerifier(trust).verify(
        packet["legacy_wcm_pcr23_bundle_b64"],
        expected_nonce=challenge,
        channel_binding=bytes.fromhex(packet["holder_public_hex"]),
        expected_workload_measurement=AGENT,
    )
    assert result.verified, result.reason
    x.authenticate_ak(packet, trust, now=datetime.fromtimestamp(g.NOW, UTC))
    return v.Component(
        component_id="application.code",
        component_type="code",
        profile=LEGACY,
        authority=AUTHORITY,
        instance="azure-vm/" + x._runtime_claims(packet)["vm_id"],
        status="affirming",
        appraised_at=g.NOW,
        fresh_until=g.NOW + AGE,
        evidence_refs=[
            v.EvidenceRef(
                profile=LEGACY,
                media_type="application/vnd.agentrust.azure-snp-pcr23+json",
                digest=v.canonical_digest(packet),
            )
        ],
        observed_digest=AGENT,
        reasons=[],
    )


def code_requirement(profiles):
    return v.Requirement(
        component_id="application.code",
        component_type="code",
        required=True,
        accepted_profiles=profiles,
        accepted_authorities=[AUTHORITY],
        maximum_age_seconds=AGE,
        expected_observed_digest=AGENT,
    )


def protected_server(d, fixture, tmp_path, profiles, extra=(), bindings=()):
    """The operator path: signed manifest, pinned requirements, cMCP's builder."""
    from cmcp_runtime.audit.store import SqliteAuditStore
    from cmcp_runtime.startup import RuntimeContext

    catalog = d["proxy"]._catalog
    projection = manifest_catalog_binding(catalog)
    local = [
        code_requirement(profiles),
        v.Requirement(
            component_id="tools.catalog",
            component_type="tool-catalog",
            required=True,
            accepted_profiles=["urn:cmcp:approved-catalog:experimental-v1"],
            accepted_authorities=[AUTHORITY],
            maximum_age_seconds=AGE,
            expected_observed_digest=catalog.catalog_hash,
        ),
        *extra,
    ]

    def declare(manifest):
        manifest["artifacts"]["policy_bundle"]["hash"] = d["evaluator"].bundle_hash
        manifest["artifacts"]["tool_manifest"] = dict(
            projection,
            allow_dynamic_registration=False,
            rug_pull_policy="deny-and-alert",
            bound_at=manifest["issued_at"],
        )
        declared = []
        for requirement in local:
            item = requirement.model_dump()
            item["accepted_appraisal_authorities"] = item.pop("accepted_authorities")
            if item["component_type"] == "tool-catalog":
                item["artifact_ref"] = "artifacts.tool_manifest"
            declared.append(item)
        manifest["evidence_requirements"]["components"] = declared
        manifest["evidence_requirements"]["required_bindings"] = [
            {
                "source": b.source,
                "target": b.target,
                "relationship": b.relationship,
                "accepted_methods": [b.method],
            }
            for b in bindings
        ]

    raw, verified = signed_packet(fixture, declare)
    key = am.Ed25519KeyPair(g.ROGUE, g.ROGUE.public_key())
    manifest_context = am.VerificationContext(
        system_prompt_hash="sha256:" + "a" * 64,
        policy_bundle_hash="sha256:" + "b" * 64,
        model_version="test-model",
        enforcement_mode="enforce",
        trusted_keys={key.key_id: key.public_b64url()},
        trusted_key_issuers={key.key_id: ["spiffe://example.test/manifest-issuer"]},
    )
    context = replace(
        d["gate"].context,
        instance=azure_component().instance,
        manifest_bytes=raw,
        manifest_id=verified.manifest_id,
        subject=verified.agent_id,
        policy=v.Policy.model_validate(fixture["token"]["appraisal_policy"]),
        requirements=v.Requirements(
            components=local, bindings=list(bindings), allow_warnings=False
        ),
    )
    d["cfg"].bearer_token = "test-bearer"
    report = MagicMock()
    report.provider = "software-only"
    report.attestation_generated_at = datetime.now(UTC)
    report.attestation_validity_seconds = 86400
    runtime = RuntimeContext(
        config=d["cfg"],
        tee_provider=MagicMock(),
        attestation_report=report,
        signing_key=MagicMock(),
        policy_bundle=d["evaluator"]._store,
        catalog=catalog,
        audit_store=SqliteAuditStore(tmp_path / "audit.sqlite"),
    )
    with patch("agent_manifest._verify.datetime", FixtureClock):
        return build_protected_server(
            runtime,
            manifest_bytes=raw,
            manifest_context=manifest_context,
            manifest_revocations=am.RevocationStore(),
            token_context=context,
            database=tmp_path / "gate.sqlite",
            gateway_key=d["key"],
            gateway_issuer="spiffe://example.test/gateway",
            clock=lambda: g.NOW,
        )


def token(server, fixture, code, *, status="affirming", signer=g.ISSUER, extra=()):
    gate = server._proxy._trace_gate
    payload = copy.deepcopy(fixture["token"])
    payload["instance"] = code.instance
    payload["manifest"]["digest"] = v.digest(gate.context.manifest_bytes)
    payload["appraisal_policy"] = gate.context.policy.model_dump()
    catalog = copy.deepcopy(payload["components"][0])
    catalog.update(
        component_id="tools.catalog",
        component_type="tool-catalog",
        profile="urn:cmcp:approved-catalog:experimental-v1",
        instance=code.instance,
        observed_digest=server._proxy._catalog.catalog_hash,
        evidence_refs=[
            {
                "profile": "urn:cmcp:approved-catalog:experimental-v1",
                "media_type": "application/json",
                "digest": v.canonical_digest(manifest_catalog_binding(server._proxy._catalog)),
                "resolver": None,
            }
        ],
    )
    payload["components"] = [code.model_dump(), catalog, *(c.model_dump() for c in extra)]
    payload["bindings"] = [
        {
            "source": b.source,
            "target": b.target,
            "relationship": b.relationship,
            "method": b.method,
            "status": "affirming",
            "digest": v.binding_digest(
                *(
                    v.Component.model_validate(c)
                    for i in (b.source, b.target)
                    for c in payload["components"]
                    if c["component_id"] == i
                ),
                b.method,
            ),
            "fresh_until": payload["exp"],
        }
        for b in gate.context.requirements.bindings
    ]
    payload["composite_appraisal"] = {
        "status": status,
        "required_components": sorted(
            {r.component_id for r in gate.context.requirements.components if r.required}
        ),
        "policy": gate.context.policy.model_dump(),
        "fresh_until": payload["exp"],
    }
    return g.envelope(payload, signer)


async def exercise(server, raw):
    """Admission then one tools/call over HTTP; returns status codes and upstream calls."""
    gate = server._proxy._trace_gate
    sent, codes = [], {}

    async def upstream(request):
        sent.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": sent[-1]["id"], "result": {"content": []}},
        )

    async def no_drift(entry):
        return False

    with pytest.MonkeyPatch.context() as mp:
        async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as upstream_client:
            mp.setattr(server._proxy, "_client_for_upstream", lambda entry: upstream_client)
            mp.setattr(server._proxy, "_check_upstream_drift", no_drift)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server.app),
                base_url="https://gateway.test",
                headers={"Authorization": "Bearer test-bearer"},
            ) as client:
                encoded = gate._encode(raw)
                response = await client.post(
                    "/trace/challenge", json={"token": encoded, "purpose": "admission"}
                )
                codes["challenge"] = response.status_code
                if response.status_code != 200:
                    return codes, sent
                admitted = await client.post(
                    "/trace/admit",
                    json={"token": encoded, "credentials": holder_proof(response.json(), raw)},
                )
                codes["admit"] = admitted.status_code
                challenge = (
                    await client.post(
                        "/trace/challenge",
                        json={
                            "token": encoded,
                            "purpose": "call",
                            "tool_name": "read",
                            "arguments": {},
                        },
                    )
                ).json()
                call = await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "read",
                            "arguments": {},
                            "_cmcp": {
                                "trace": {
                                    "call_id": challenge["call_id"],
                                    "credentials": holder_proof(challenge, raw),
                                }
                            },
                        },
                    },
                )
                codes["call"] = call.status_code
                codes["call_error"] = "error" in call.json()
    return codes, sent


def admission_reason(server, raw):
    """The gate's own refusal code; the HTTP layer reports only TRACE_ADMISSION_REFUSED."""
    gate = server._proxy._trace_gate
    action = {"domain": "cmcp:trace-admission:experimental-v1", "session_id": "session-1"}
    challenge = gate.challenge(raw, session_id="session-1", action=action)
    with pytest.raises(v.ProfileError) as caught:
        gate.admit(raw, holder_proof(challenge, raw), session_id="session-1")
    return str(caught.value)


def test_real_azure_component_is_admitted_and_reaches_transport(deployment, fixture, tmp_path):
    server = protected_server(deployment, fixture, tmp_path, [x.PROFILE])
    raw = token(server, fixture, azure_component())
    codes, sent = asyncio.run(exercise(server, raw))
    assert codes == {"challenge": 200, "admit": 200, "call": 200, "call_error": False}
    assert len(sent) == 1
    asyncio.run(deployment["client"].aclose())


def test_legacy_pcr23_component_for_the_substituted_agent_gets_no_transport(
    deployment, fixture, tmp_path
):
    server = protected_server(deployment, fixture, tmp_path, [x.PROFILE])
    raw = token(server, fixture, legacy_component(), status="unverifiable")
    codes, sent = asyncio.run(exercise(server, raw))
    assert codes["admit"] == 403
    assert codes["call_error"] is True
    assert sent == []
    assert admission_reason(server, raw) == "appraisal_not_acceptable"
    # An issuer that calls the legacy component affirming contradicts the gateway's derivation.
    lying = token(server, fixture, legacy_component(), status="affirming")
    assert asyncio.run(exercise(server, lying)) == ({"challenge": 403}, [])
    asyncio.run(deployment["client"].aclose())


def test_accepting_the_legacy_profile_admits_the_substituted_agent(deployment, fixture, tmp_path):
    """Causal counterexample: the profile requirement alone kept the relabeled agent out."""
    server = protected_server(deployment, fixture, tmp_path, [x.PROFILE, LEGACY])
    raw = token(server, fixture, legacy_component())
    codes, sent = asyncio.run(exercise(server, raw))
    assert codes == {"challenge": 200, "admit": 200, "call": 200, "call_error": False}
    assert len(sent) == 1
    asyncio.run(deployment["client"].aclose())


def test_substituted_packet_cannot_yield_an_azure_component():
    packet, challenge = real("b2-substituted-relabel")
    with pytest.raises(x.ExecutionDenied, match="^unapproved_execution$"):
        x.execution_component(
            packet,
            genoa_trust(),
            real_policy(),
            expected_challenge=challenge,
            expected_holder=bytes.fromhex(packet["holder_public_hex"]),
            authority=AUTHORITY,
            now=g.NOW,
        )


def test_issuer_refuses_the_stand_in_holder():
    packet, challenge = real("b1-approved")
    with pytest.raises(x.ExecutionDenied, match="^token_holder_mismatch$"):
        x.execution_component(
            packet,
            genoa_trust(),
            real_policy(),
            expected_challenge=challenge,
            expected_holder=v.public_bytes(g.HOLDER),
            authority=AUTHORITY,
            now=g.NOW,
        )


def test_attacker_signed_real_component_fails_issuer_trust(deployment, fixture, tmp_path):
    server = protected_server(deployment, fixture, tmp_path, [x.PROFILE])
    raw = token(server, fixture, azure_component(), signer=g.ROGUE)
    with pytest.raises(v.ProfileError, match="^issuer_untrusted$"):
        v.verify_token(raw, server._proxy._trace_gate.context, g.NOW)
    assert asyncio.run(exercise(server, raw)) == ({"challenge": 403}, [])
    asyncio.run(deployment["client"].aclose())


# ------------------------------------------- platform collateral at the gateway


def platform(floor_snp):
    """The b1 Genoa host's collateral verdict (SNP 23) against a given floor."""
    from tests.test_snp_collateral import FLOOR, NOW, policy
    from prototype import snp_collateral as s

    packet, _ = real("b1-approved")
    floor = replace(FLOOR, snp=floor_snp, os_mitigation_bit=None)
    appraisal = s.appraise_collateral(packet, policy(floors={"Genoa": floor}), now=NOW)
    return s.tcb_component(
        appraisal,
        packet,
        instance=azure_component().instance,
        authority=AUTHORITY,
        now=g.NOW,
        max_age=AGE,
    )


CPU = v.Requirement(
    component_id="runtime.cpu",
    component_type="runtime",
    required=True,
    accepted_profiles=["amd-snp-collateral-experimental-v1"],
    accepted_authorities=[AUTHORITY],
    maximum_age_seconds=AGE,
)
SAME = v.BindingRequirement(
    source="runtime.cpu",
    target="application.code",
    relationship="same-workload",
    method="same-instance-v1",
)


@pytest.mark.parametrize("floor,expected", [(0x1B, "contraindicated"), (23, "affirming")])
def test_platform_below_the_tcb_floor_gets_no_transport(
    deployment, fixture, tmp_path, floor, expected
):
    cpu = platform(floor)
    assert cpu.status == expected
    server = protected_server(
        deployment, fixture, tmp_path, [x.PROFILE], extra=[CPU], bindings=[SAME]
    )
    raw = token(server, fixture, azure_component(), status=expected, extra=[cpu])
    codes, sent = asyncio.run(exercise(server, raw))
    if expected == "affirming":
        assert codes == {"challenge": 200, "admit": 200, "call": 200, "call_error": False}
        assert len(sent) == 1
    else:
        assert codes["admit"] == 403 and sent == []
        assert admission_reason(server, raw) == "appraisal_not_acceptable"
    asyncio.run(deployment["client"].aclose())

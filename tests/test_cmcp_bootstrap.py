"""Verify signed intent before wiring the production cMCP composition path."""

from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("httpx", reason="cross-repository gateway test")
pytest.importorskip("cmcp_runtime.manifest_catalog", reason="needs cMCP TRACE gate")
pytest.importorskip("agent_manifest.evidence_requirements", reason="needs Agent Manifest")

from prototype import verifier_token as v
from prototype.cmcp_bootstrap import build_protected_server
from cmcp_runtime.manifest_catalog import manifest_catalog_binding
from tests.test_cmcp_trace_gate import deployment, holder_proof
from tests.test_manifest_requirements_bridge import am, signed_packet
from tests.test_verifier_token_profile import fixture, g
from tools.run_verifier_token_poc import FixtureClock

__all__ = ["deployment", "fixture"]


@pytest.mark.parametrize("substitution", ["identity", "policy", "boolean-type"])
def test_decoded_fields_cannot_replace_authenticated_payload(fixture, substitution):
    from cmcp_runtime.agent_manifest import verify_agent_manifest_signature
    from cmcp_runtime.errors import ConfigError

    raw, _ = signed_packet(fixture)
    key = am.Ed25519KeyPair(g.ROGUE, g.ROGUE.public_key())
    decoded = am.verify_cose_manifest(raw, {key.key_id: key.public_b64url()}).manifest
    if substitution == "identity":
        decoded["agent_id"] = "spiffe://substituted.test/agent"
    elif substitution == "policy":
        decoded["artifacts"]["policy_bundle"]["hash"] = "sha256:" + "f" * 64
    else:
        decoded["evidence_requirements"]["components"][0]["required"] = 1
    with pytest.raises(ConfigError, match="Decoded manifest does not match authenticated COSE"):
        verify_agent_manifest_signature(decoded, {key.key_id: key.public_bytes}, envelope=raw)


@pytest.mark.parametrize(
    "failure", [None, "identity", "policy", "bearer", "catalog", "description"]
)
def test_production_composition_requires_verified_manifest(
    deployment, fixture, tmp_path, failure, monkeypatch
):
    from cmcp_runtime.audit.store import SqliteAuditStore
    from cmcp_runtime.startup import RuntimeContext

    d = deployment
    catalog = d["proxy"]._catalog
    projection = manifest_catalog_binding(catalog)
    local_catalog = v.Requirement(
        component_id="tools.catalog",
        component_type="tool-catalog",
        required=True,
        accepted_profiles=["urn:cmcp:approved-catalog:experimental-v1"],
        accepted_authorities=[fixture["token"]["iss"]],
        maximum_age_seconds=120,
        expected_observed_digest=catalog.catalog_hash,
    )

    def add_catalog(manifest):
        manifest["artifacts"]["policy_bundle"]["hash"] = d["evaluator"].bundle_hash
        manifest["artifacts"]["tool_manifest"] = dict(
            projection,
            allow_dynamic_registration=False,
            rug_pull_policy="deny-and-alert",
            bound_at=manifest["issued_at"],
        )
        component = local_catalog.model_dump()
        component["accepted_appraisal_authorities"] = component.pop("accepted_authorities")
        component["artifact_ref"] = "artifacts.tool_manifest"
        manifest["evidence_requirements"]["components"].append(component)

    raw, verified = signed_packet(fixture, add_catalog)
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
        manifest_bytes=raw,
        manifest_id=verified.manifest_id,
        subject=verified.agent_id,
        policy=v.Policy.model_validate(fixture["token"]["appraisal_policy"]),
        requirements=d["gate"].context.requirements.model_copy(
            update={"components": d["gate"].context.requirements.components + [local_catalog]}
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
        catalog=d["proxy"]._catalog,
        audit_store=SqliteAuditStore(tmp_path / "audit.sqlite"),
    )
    if failure == "identity":
        context = replace(context, subject="spiffe://other.test/agent")
    elif failure == "policy":
        runtime.policy_bundle.bundle.bundle_hash = "sha256:" + "f" * 64
    elif failure == "bearer":
        runtime.config.bearer_token = None
    elif failure == "catalog":
        runtime.catalog.catalog_hash = "sha256:" + "f" * 64
    elif failure == "description":
        runtime.catalog.entries["read"].approved_definition.description = "substituted description"
    with patch("agent_manifest._verify.datetime", FixtureClock):
        if failure:
            with pytest.raises(v.ProfileError):
                build_protected_server(
                    runtime,
                    manifest_bytes=raw,
                    manifest_context=manifest_context,
                    manifest_revocations=am.RevocationStore(),
                    token_context=context,
                    database=tmp_path / "production-gate.sqlite",
                    gateway_key=d["key"],
                    gateway_issuer="spiffe://example.test/gateway",
                    clock=lambda: g.NOW,
                )
        else:
            from cmcp_runtime.agent_manifest import verify_agent_manifest_binding

            decoded = am.verify_cose_manifest(raw, manifest_context.trusted_keys).manifest
            binding = verify_agent_manifest_binding(
                decoded,
                {key.key_id: key.public_bytes},
                authenticated_subject=verified.agent_id,
                policy_bundle_hash=d["evaluator"].bundle_hash,
                tool_catalog_hash=catalog.catalog_hash,
                runtime_catalog=catalog,
                envelope=raw,
                enforcement_mode=d["cfg"].attestation.enforcement_mode,
                now=datetime.fromtimestamp(g.NOW, UTC),
            )
            assert binding.tool_catalog_hash == catalog.catalog_hash
            assert binding.tool_catalog_hash != projection["catalog_hash"]
            assert binding.issuer_key_id == key.key_id
            runtime.agent_manifest = binding
            server = build_protected_server(
                runtime,
                manifest_bytes=raw,
                manifest_context=manifest_context,
                manifest_revocations=am.RevocationStore(),
                token_context=context,
                database=tmp_path / "production-gate.sqlite",
                gateway_key=d["key"],
                gateway_issuer="spiffe://example.test/gateway",
                clock=lambda: g.NOW,
            )
            assert server._proxy._trace_gate.context.manifest_bytes == raw
            assert server._proxy._trace_gate.context.subject == verified.agent_id
            assert (
                server._proxy._trace_gate.context.policy.digest
                != server._proxy._trace_gate._gateway_policy_digest
            )
            import asyncio

            asyncio.run(exercise_built_server(server, fixture, raw, d, monkeypatch))


async def exercise_built_server(server, fixture, manifest_bytes, d, monkeypatch):
    import copy
    import json
    import httpx

    gate = server._proxy._trace_gate
    payload = copy.deepcopy(fixture["token"])
    payload["manifest"]["digest"] = v.digest(manifest_bytes)
    payload["appraisal_policy"] = gate.context.policy.model_dump()
    payload["composite_appraisal"]["policy"] = gate.context.policy.model_dump()
    catalog = copy.deepcopy(payload["components"][0])
    catalog.update(
        component_id="tools.catalog",
        component_type="tool-catalog",
        profile="urn:cmcp:approved-catalog:experimental-v1",
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
    payload["components"].append(catalog)
    payload["composite_appraisal"]["required_components"] = sorted(
        c.component_id for c in gate.context.requirements.components if c.required
    )
    token = g.envelope(payload, g.ISSUER)
    sent = []

    async def upstream(request):
        sent.append(json.loads(request.content))
        assert gate.receipts()
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": sent[-1]["id"],
                "result": {"content": [{"type": "text", "text": "builder path reached"}]},
            },
        )

    async def no_drift(entry):
        return False

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as upstream_client:
        monkeypatch.setattr(server._proxy, "_client_for_upstream", lambda entry: upstream_client)
        monkeypatch.setattr(server._proxy, "_check_upstream_drift", no_drift)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server.app),
            base_url="https://gateway.test",
            headers={"Authorization": "Bearer test-bearer"},
        ) as client:
            challenge = (
                await client.post(
                    "/trace/challenge", json={"token": gate._encode(token), "purpose": "admission"}
                )
            ).json()
            admitted = await client.post(
                "/trace/admit",
                json={"token": gate._encode(token), "credentials": holder_proof(challenge, token)},
            )
            assert admitted.status_code == 200, admitted.text
            challenge = (
                await client.post(
                    "/trace/challenge",
                    json={
                        "token": gate._encode(token),
                        "purpose": "call",
                        "tool_name": "read",
                        "arguments": {},
                    },
                )
            ).json()
            response = await client.post(
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
                                "credentials": holder_proof(challenge, token),
                            }
                        },
                    },
                },
            )
            assert response.status_code == 200, response.text
            assert len(sent) == 1
            receipt = v.authenticate(
                gate.receipts()[0], v.RECEIPT_PROFILE, d["key"].public_key(), v.Receipt
            )
            assert receipt.policy_digest == server._proxy._policy.bundle_hash
            assert receipt.policy_digest != payload["appraisal_policy"]["digest"]
    await d["client"].aclose()

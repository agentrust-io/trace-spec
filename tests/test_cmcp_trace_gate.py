"""Cross-repository contract tests through real cMCP HTTP/proxy/Cedar paths.

Run with the pinned sibling cMCP source on PYTHONPATH. Appraisal is synthetic;
the upstream is a controlled HTTP transport, not a business service.
"""

import copy
from dataclasses import replace

import pytest

pytest.importorskip("httpx", reason="cross-repository gateway test")
pytest.importorskip("cmcp_runtime.manifest_catalog", reason="needs cMCP TRACE gate")
import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytest.importorskip("cmcp_runtime", reason="cross-repository cMCP dependency required")
from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import Config
from cmcp_runtime.mcp.proxy import CMCPProxy
from cmcp_runtime.mcp.server import MCPServer
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from prototype import verifier_token as v
from prototype.cmcp_gate import CMCPTraceGate
from tests.test_verifier_token_profile import context, fixture, g

__all__ = ["fixture"]


def holder_proof(challenge, raw, *, holder=g.HOLDER):
    payload = {
        "profile": v.PROOF_PROFILE,
        "nonce": challenge["nonce"],
        "token_digest": v.digest(raw),
        "token_id": challenge["token_id"],
        "audience": challenge["audience"],
        "session_id": challenge["session_id"],
        "action_digest": challenge["action_digest"],
        "issued_at": challenge["issued_at"],
        "expires_at": challenge["expires_at"],
    }
    return {
        "nonce": challenge["nonce"],
        "proof": CMCPTraceGate._encode(g.envelope(payload, holder)),
    }


@pytest.fixture
def deployment(fixture, tmp_path, monkeypatch, request):
    cfg = Config()
    policy_text = getattr(request, "param", "permit(principal, action, resource);")
    policy_hash = v.digest(policy_text.encode())
    bundle = PolicyBundle(
        PolicyManifest("1", "2026-09-29", "test", "0" * 40),
        {"test.cedar": policy_text},
        "",
        policy_hash,
    )
    evaluator = PolicyEvaluator(bundle, cfg)
    payload = copy.deepcopy(fixture["token"])
    payload["appraisal_policy"]["digest"] = policy_hash
    payload["composite_appraisal"]["policy"]["digest"] = policy_hash
    raw = g.envelope(payload, g.ISSUER)
    ctx = replace(context(fixture), policy=v.Policy.model_validate(payload["appraisal_policy"]))
    clock = [g.NOW]
    status = [True]
    ctx = replace(ctx, status_check=lambda token, now: status[0])
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
    gate = CMCPTraceGate(
        ctx,
        database=tmp_path / "gate.sqlite",
        gateway_key=key,
        gateway_issuer="spiffe://example.test/gateway",
        gateway_policy_digest=policy_hash,
        clock=lambda: clock[0],
    )
    entry = CatalogEntry(
        tool_name="read",
        server=ServerIdentity(
            display_name="Fixture",
            url="https://fixture.test/mcp",
            tls_fingerprint="SHA256:AAAA/BBBB==",
            transport="http-sse",
            rotation_mode="key-pinned",
            spiffe_id=None,
        ),
        approved_definition=ApprovedDefinition(
            description="read", input_schema={}, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-09-29T00:00:00Z",
        approved_by="test",
    )
    catalog = ToolCatalog(entries={"read": entry}, catalog_hash="sha256:" + "1" * 64)
    session = SessionState(session_id="session-1")
    audit = AuditChain(session.session_id)
    proxy = CMCPProxy(
        catalog,
        evaluator,
        session,
        audit,
        cfg,
        attestation_platform="software-only",
        trace_gate=gate,
    )
    calls = []

    async def upstream(request):
        import json

        body = json.loads(request.content)
        # A transport callback sees the signed authorization already durable.
        assert any(
            v.authenticate(receipt, v.RECEIPT_PROFILE, key.public_key(), v.Receipt).call_id
            == body["id"]
            for receipt in gate.receipts()
        )
        calls.append(body)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"content": [{"type": "text", "text": "fixture result"}]},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    monkeypatch.setattr(proxy, "_client_for_upstream", lambda entry: client)

    async def no_drift(entry):
        return False

    monkeypatch.setattr(proxy, "_check_upstream_drift", no_drift)
    return {
        "raw": raw,
        "gate": gate,
        "proxy": proxy,
        "calls": calls,
        "clock": clock,
        "status": status,
        "key": key,
        "evaluator": evaluator,
        "client": client,
        "audit": audit,
        "cfg": cfg,
    }


def admit(d):
    action = {"domain": "cmcp:trace-admission:experimental-v1", "session_id": "session-1"}
    challenge = d["gate"].challenge(d["raw"], session_id="session-1", action=action)
    return d["gate"].admit(d["raw"], holder_proof(challenge, d["raw"]), session_id="session-1")


def credentials(d, call_id="call-1", arguments=None):
    action = d["proxy"].trace_action(call_id, "read", arguments or {})
    challenge = d["gate"].challenge(d["raw"], session_id="session-1", action=action)
    return holder_proof(challenge, d["raw"])


@pytest.mark.asyncio
async def test_real_proxy_allows_and_receipt_precedes_transport(deployment):
    d = deployment
    admit(d)
    credentials_ = credentials(d)
    result = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=credentials_)
    assert result.allowed
    assert len(d["calls"]) == 1
    receipt = v.authenticate(
        d["gate"].receipts()[0], v.RECEIPT_PROFILE, d["key"].public_key(), v.Receipt
    )
    assert receipt.decision == "allow"
    assert receipt.action_digest == v.canonical_digest(
        d["proxy"].trace_action("call-1", "read", {})
    )
    assert d["evaluator"].bundle_hash == receipt.policy_digest
    await d["client"].aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("deployment", ["forbid(principal, action, resource);"], indirect=True)
async def test_real_cedar_denies_affirming_trace_without_transport(deployment):
    d = deployment
    admit(d)
    result = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=credentials(d))
    assert not result.allowed
    assert d["calls"] == []
    receipt = v.authenticate(
        d["gate"].receipts()[0], v.RECEIPT_PROFILE, d["key"].public_key(), v.Receipt
    )
    assert receipt.decision == "deny"
    await d["client"].aclose()


@pytest.mark.asyncio
async def test_disabling_transport_recheck_admits_expired_call(deployment, monkeypatch):
    d = deployment
    admit(d)
    original = d["proxy"]._check_provenance

    async def expire(entry):
        result = await original(entry)
        d["clock"][0] += 120
        return result

    monkeypatch.setattr(d["proxy"], "_check_provenance", expire)
    proof = credentials(d)
    first = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=proof)
    assert not first.allowed and not d["calls"]
    d["clock"][0] = g.NOW
    proof = credentials(d, "call-2")
    monkeypatch.setattr(d["gate"], "recheck", lambda *args, **kwargs: None)
    second = await d["proxy"].call_tool("call-2", "read", {}, trace_credentials=proof)
    assert second.allowed and len(d["calls"]) == 1
    await d["client"].aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "missing",
        "replay",
        "expired",
        "revoked",
        "refresh",
        "mutated-action",
        "changed-policy",
        "storage-outage",
    ],
)
async def test_proxy_refuses_without_transport(deployment, monkeypatch, failure):
    d = deployment
    if failure == "missing":
        proof = None
    else:
        admit(d)
        proof = credentials(d)
    arguments = {}
    if failure == "replay":
        first = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=proof)
        assert first.allowed
        d["calls"].clear()
    elif failure == "expired":
        d["clock"][0] += 120
    elif failure == "revoked":
        d["status"][0] = False
    elif failure == "refresh":
        # Admission creates a new generation; the pending call's challenge
        # remains exact-token-bound, so identical token refresh is still valid.
        admit(d)
        d["status"][0] = False
    elif failure == "mutated-action":
        arguments = {"unexpected": "change"}
    elif failure == "changed-policy":
        d["evaluator"]._store.bundle.bundle_hash = "sha256:" + "f" * 64
    elif failure == "storage-outage":

        def fail_receipt(*args, **kwargs):
            raise OSError("synthetic receipt database unavailable")

        monkeypatch.setattr(d["gate"], "receipt", fail_receipt)
    if failure == "storage-outage":
        with pytest.raises(OSError):
            await d["proxy"].call_tool("call-1", "read", arguments, trace_credentials=proof)
    else:
        result = await d["proxy"].call_tool("call-1", "read", arguments, trace_credentials=proof)
        assert not result.allowed
    assert d["calls"] == []
    await d["client"].aclose()


@pytest.mark.asyncio
async def test_expiry_during_provenance_await_stops_actual_send(deployment, monkeypatch):
    d = deployment
    admit(d)
    proof = credentials(d)
    original = d["proxy"]._check_provenance

    async def expire(entry):
        result = await original(entry)
        d["clock"][0] += 120
        return result

    monkeypatch.setattr(d["proxy"], "_check_provenance", expire)
    result = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=proof)
    assert not result.allowed
    assert d["calls"] == []
    receipts = [
        v.authenticate(r, v.RECEIPT_PROFILE, d["key"].public_key(), v.Receipt)
        for r in d["gate"].receipts()
    ]
    assert [r.decision for r in receipts] == ["deny"]
    await d["client"].aclose()


@pytest.mark.asyncio
async def test_refresh_during_provenance_invalidates_pending_call(deployment, monkeypatch):
    d = deployment
    admit(d)
    proof = credentials(d)
    original = d["proxy"]._check_provenance

    async def refresh(entry):
        result = await original(entry)
        admit(d)
        return result

    monkeypatch.setattr(d["proxy"], "_check_provenance", refresh)
    result = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=proof)
    assert not result.allowed
    assert d["calls"] == []
    await d["client"].aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("substitution", ["server", "definition"])
async def test_catalog_substitution_after_proof_stops_transport(
    deployment, monkeypatch, substitution
):
    d = deployment
    admit(d)
    proof = credentials(d)
    original = d["proxy"]._check_provenance

    async def substitute(entry):
        result = await original(entry)
        if substitution == "server":
            entry.server.url = "https://substituted.test/mcp"
        else:
            entry.definition_hash = "sha256:" + "f" * 64
        return result

    monkeypatch.setattr(d["proxy"], "_check_provenance", substitute)
    result = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=proof)
    assert not result.allowed and d["calls"] == []
    await d["client"].aclose()


def sibling_gate(d):
    return CMCPTraceGate(
        d["gate"].context,
        database=d["gate"]._database,
        gateway_key=d["key"],
        gateway_issuer=d["gate"]._issuer,
        gateway_policy_digest=d["gate"]._gateway_policy_digest,
        clock=lambda: d["clock"][0],
    )


def test_workers_atomically_consume_one_proof(deployment):
    from concurrent.futures import ThreadPoolExecutor

    d = deployment
    admit(d)
    proof = credentials(d)
    action = d["proxy"].trace_action("call-1", "read", {})

    def begin(gate):
        try:
            gate.begin(
                proof,
                action=action,
                session_id="session-1",
                call_id="call-1",
                policy_digest=d["evaluator"].bundle_hash,
            )
            return "accepted"
        except v.ProfileError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(begin, [d["gate"], sibling_gate(d)])) == ["accepted", "refused"]
    assert begin(sibling_gate(d)) == "refused"


@pytest.mark.asyncio
async def test_expiry_during_receipt_commit_stops_transport(deployment, monkeypatch):
    d = deployment
    admit(d)
    proof = credentials(d)
    original = d["gate"].receipt

    def delayed_commit(*args, **kwargs):
        original(*args, **kwargs)
        d["clock"][0] += 120

    monkeypatch.setattr(d["gate"], "receipt", delayed_commit)
    result = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=proof)
    assert not result.allowed
    assert d["calls"] == []
    # Authorization preceded expiry; the terminal cMCP audit reports no execution.
    receipt = v.authenticate(
        d["gate"].receipts()[0], v.RECEIPT_PROFILE, d["key"].public_key(), v.Receipt
    )
    assert receipt.decision == "allow"
    await d["client"].aclose()


def test_fresh_proof_cannot_reuse_reserved_call(deployment):
    d = deployment
    admit(d)
    action = d["proxy"].trace_action("call-1", "read", {})
    kwargs = {
        "action": action,
        "session_id": "session-1",
        "call_id": "call-1",
        "policy_digest": d["evaluator"].bundle_hash,
    }
    d["gate"].begin(credentials(d), **kwargs)
    with pytest.raises(v.ProfileError, match="call_id_reused"):
        sibling_gate(d).begin(credentials(d), **kwargs)


def test_token_id_collision_survives_worker_restart(deployment):
    d = deployment
    admit(d)
    changed = v.read_payload(v.unpack(d["raw"], v.PROFILE)[1], v.Token).model_dump()
    changed["cnf"] = v.holder_key(g.ROGUE).model_dump()
    replacement = g.envelope(changed, g.ISSUER)
    with pytest.raises(v.ProfileError, match="token_id_collision"):
        sibling_gate(d).challenge(replacement, session_id="session-1", action={"tool": "read"})
    changed["jti"] = "replacement-token"
    assert sibling_gate(d).challenge(
        g.envelope(changed, g.ISSUER), session_id="session-1", action={"tool": "read"}
    )


def test_signed_receipts_link_across_worker_restarts(deployment):
    d = deployment
    admit(d)
    for number in range(2):
        call = f"call-{number}"
        action = d["proxy"].trace_action(call, "read", {})
        gate = sibling_gate(d)
        handle, _ = gate.begin(
            credentials(d, call),
            action=action,
            session_id="session-1",
            call_id=call,
            policy_digest=d["evaluator"].bundle_hash,
        )
        gate.receipt(handle, allowed=False, reason="policy_denied")
    envelopes = sibling_gate(d).receipts()
    records = [
        v.authenticate(raw, v.RECEIPT_PROFILE, d["key"].public_key(), v.Receipt)
        for raw in envelopes
    ]
    assert records[0].previous_receipt_hash is None
    assert records[1].previous_receipt_hash == v.digest(envelopes[0])


@pytest.mark.parametrize("bad_clock", [True, float("nan"), float("inf"), -1, "unavailable"])
def test_unusable_clock_fails_closed(deployment, bad_clock):
    deployment["clock"][0] = bad_clock
    with pytest.raises(v.ProfileError, match="clock_unavailable"):
        deployment["gate"].now()


@pytest.mark.asyncio
async def test_http_challenge_admission_and_call_require_auth(deployment):
    d = deployment
    server = MCPServer(
        d["proxy"], bearer_token="test-bearer", session=d["proxy"]._session, audit_chain=d["audit"]
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app), base_url="https://gateway.test"
    ) as client:
        body = {"token": CMCPTraceGate._encode(d["raw"]), "purpose": "admission"}
        assert (await client.post("/trace/challenge", json=body)).status_code == 401
        client.headers["Authorization"] = "Bearer test-bearer"
        challenge = (await client.post("/trace/challenge", json=body)).json()
        response = await client.post(
            "/trace/admit",
            json={"token": body["token"], "credentials": holder_proof(challenge, d["raw"])},
        )
        assert response.status_code == 200
        challenge = (
            await client.post(
                "/trace/challenge",
                json={
                    "token": body["token"],
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
                            "credentials": holder_proof(challenge, d["raw"]),
                        }
                    },
                },
            },
        )
        assert response.status_code == 200, response.text
        assert len(d["calls"]) == 1
    await d["client"].aclose()

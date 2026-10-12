"""Local cross-repository POC with real signatures, manifest verifier and Cedar.

Requires agent-manifest and cMCP on PYTHONPATH. Nothing is published or sent.
Platform appraisals and status responses are synthetic and explicitly labeled.
The forwarding sink is a local list, not a live MCP server or business action.
"""

from __future__ import annotations
import base64
import copy
import importlib.util
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import agent_manifest
from cmcp_runtime.policy.cedar import CedarBackend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prototype import verifier_token as v
from prototype.manifest_requirements import combine_requirements

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples/verifier-token-profile"
spec = importlib.util.spec_from_file_location("independent_fixture", VECTORS / "gen_vectors.py")
assert spec is not None and spec.loader is not None
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FixtureClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime.fromtimestamp(g.NOW, tz=tz or UTC)


def run() -> dict:
    fixture = json.loads((VECTORS / "01-valid.json").read_text(encoding="utf-8"))
    original = fixture["token"]
    manifest_bytes = decode(fixture["manifest_b64"])
    manifest_key_id = v.key_id(g.ROGUE).hex()
    trusted_manifest_keys = {manifest_key_id: fixture["manifest_public_b64"]}
    policy_text = 'permit(principal, action == Action::"Read", resource);'
    policy = v.Policy(
        id="https://example.test/cedar/read-only",
        version="1",
        digest=v.digest(policy_text.encode()),
    )
    manifest = agent_manifest.verify_cose_manifest(manifest_bytes, trusted_manifest_keys).manifest
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
    local = v.Requirements.model_validate(fixture["requirements"])
    components = []
    for item in local.components:
        declared = item.model_dump()
        declared["accepted_appraisal_authorities"] = declared.pop("accepted_authorities")
        components.append(declared)
    manifest["evidence_requirements"] = {
        "components": components,
        "required_bindings": [
            {
                "source": b.source,
                "target": b.target,
                "relationship": b.relationship,
                "accepted_methods": [b.method],
            }
            for b in local.bindings
        ],
        "combination_policy_ref": policy.id,
    }
    agent_manifest.Manifest.model_validate(manifest)
    manifest_bytes = agent_manifest.sign_cose_sign1(
        manifest, agent_manifest.Ed25519KeyPair(g.ROGUE, g.ROGUE.public_key())
    )
    manifest_context = agent_manifest.VerificationContext(
        system_prompt_hash="sha256:" + "a" * 64,
        policy_bundle_hash="sha256:" + "b" * 64,
        model_version="test-model",
        enforcement_mode="enforce",
        trusted_keys=trusted_manifest_keys,
        trusted_key_issuers={manifest_key_id: ["spiffe://example.test/manifest-issuer"]},
    )
    with patch("agent_manifest._verify.datetime", FixtureClock):
        from agent_manifest.evidence_requirements import verify_evidence_manifest

        verified_requirements = verify_evidence_manifest(
            manifest_bytes, manifest_context, agent_manifest.RevocationStore()
        )
        manifest_result = agent_manifest.verify_manifest(
            manifest_bytes, manifest_context, agent_manifest.RevocationStore()
        )
    if manifest_result.result.value != "VALID":
        raise RuntimeError("manifest POC prerequisite failed: " + str(manifest_result))
    decoded_manifest = agent_manifest.verify_cose_manifest(
        manifest_bytes, trusted_manifest_keys
    ).manifest
    if decoded_manifest.get("profile") == "composition-only":
        raise RuntimeError("composition-only is not a complete-agent appraisal")

    cedar = CedarBackend(policy_content=policy_text)
    issuer = v.TrustedIssuer(original["iss"], g.ISSUER.public_key(), g.NOW - 1, g.NOW + 600)
    requirements = combine_requirements(verified_requirements, local, policy)
    question = v.canonical_digest(
        {
            "purpose": "protected-action",
            "audience": original["aud"],
            "policy": policy.model_dump(),
            "requirements": requirements.model_dump(),
        }
    )
    context = v.VerificationContext(
        audience=original["aud"],
        subject=decoded_manifest["agent_id"],
        instance="instance-1",
        manifest_bytes=manifest_bytes,
        manifest_id=decoded_manifest["manifest_id"],
        manifest_valid_until=g.NOW + 600,
        question_digest=question,
        policy=policy,
        requirements=requirements,
        trusted_issuers={(issuer.issuer, v.key_id(issuer.key)): issuer},
        status_check=lambda token, now: True,
    )
    payload = copy.deepcopy(original)
    payload["manifest"]["digest"] = v.digest(manifest_bytes)
    payload["appraisal_policy"] = policy.model_dump()
    payload["composite_appraisal"]["policy"] = policy.model_dump()
    payload["verification_context_hash"] = question
    token_bytes = g.envelope(payload, g.ISSUER)
    gateway_key = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
    forwarded: list[dict] = []
    receipts: list[dict] = []
    results: list[dict] = []

    def scenario(name, *, tool="read", now=g.NOW, raw=token_bytes, ctx=context, holder=g.HOLDER):
        action = {"tool": tool, "args": {"id": "public-test"}}
        # Freeze the exact action sent to the local forwarding sink.
        action = json.loads(__import__("rfc8785").dumps(action))
        action_digest = v.canonical_digest(action)
        nonce = g.b64(__import__("hashlib").sha256(name.encode()).digest())
        rp = v.RelyingParty(ctx)
        expiry = min(now + 30, payload["exp"])
        # Expired-token test still carries a previously issued, cryptographically valid proof.
        issued = min(now, expiry - 1)
        rp.challenge(
            nonce=nonce,
            session_id="session-1",
            action_digest=action_digest,
            issued_at=issued,
            expires_at=expiry,
        )
        proof_payload = {
            "profile": v.PROOF_PROFILE,
            "nonce": nonce,
            "token_digest": v.digest(raw),
            "token_id": payload["jti"],
            "audience": context.audience,
            "session_id": "session-1",
            "action_digest": action_digest,
            "issued_at": issued,
            "expires_at": expiry,
        }
        proof_bytes = g.envelope(proof_payload, holder)
        before = len(forwarded)
        try:
            token, allowed = rp.authorize(
                raw,
                proof_bytes,
                nonce=nonce,
                action=action,
                session_id="session-1",
                now=now,
                policy=lambda token, snapshot: (
                    cedar.evaluate(
                        {
                            "agent_id": token.sub,
                            "tool_name": snapshot["tool"],
                            "trace": {
                                "issuer": token.iss,
                                "appraisal": token.composite_appraisal.status,
                            },
                        }
                    ).allowed
                ),
            )
            receipt = v.Receipt(
                profile=v.RECEIPT_PROFILE,
                issuer=context.audience,
                issued_at=now,
                session_id="session-1",
                call_id=name,
                trace_digest=v.digest(raw),
                trace_jti=token.jti,
                action_digest=action_digest,
                policy_digest=policy.digest,
                decision="allow" if allowed else "deny",
                reason="cedar_allow" if allowed else "cedar_deny",
            )
            receipt_bytes = v.sign_payload(receipt, gateway_key)
            # Offline receipt verification is independent of TRACE authentication.
            checked = v.authenticate(
                receipt_bytes, v.RECEIPT_PROFILE, gateway_key.public_key(), v.Receipt
            )
            assert checked.trace_digest == v.digest(raw) and checked.action_digest == action_digest
            receipts.append(
                {
                    "case": name,
                    "envelope_b64": g.b64(receipt_bytes),
                    "offline_signature_valid": True,
                    "decision": checked.decision,
                }
            )
            if allowed:
                forwarded.append(copy.deepcopy(action))
            outcome = "allow" if allowed else "policy_denied"
        except v.ProfileError as exc:
            outcome = str(exc)
        results.append(
            {"case": name, "outcome": outcome, "upstream_calls": len(forwarded) - before}
        )

    scenario("valid-allow")
    scenario("cedar-deny-despite-affirming-trace", tool="delete")
    scenario("expires-between-admission-and-call", now=g.NOW + 120)
    scenario("wrong-holder", holder=g.ROGUE)
    modified = copy.deepcopy(payload)
    modified["manifest"]["digest"] = "sha256:" + "0" * 64
    scenario("manifest-substitution", raw=g.envelope(modified, g.ISSUER))
    modified = copy.deepcopy(payload)
    modified["components"].pop()
    scenario("required-component-missing", raw=g.envelope(modified, g.ISSUER))
    scenario("revoked-after-admission", ctx=replace(context, status_check=lambda token, now: False))

    def outage(token, now):
        raise OSError("synthetic status service outage")

    scenario("status-outage", ctx=replace(context, status_check=outage))
    expected = [
        "allow",
        "policy_denied",
        "token_expired_or_future",
        "key_id_mismatch",
        "manifest_mismatch",
        "composite_inconsistent",
        "status_not_active",
        "status_unavailable",
    ]
    assert [r["outcome"] for r in results] == expected, results
    assert [r["upstream_calls"] for r in results] == [1, 0, 0, 0, 0, 0, 0, 0], results
    return {
        "manifest_result": manifest_result.result.value,
        "manifest_signature_verified": True,
        "manifest_digest": v.digest(manifest_bytes),
        "cedar_backend": str(
            Path(__import__("cmcp_runtime.policy.cedar", fromlist=["x"]).__file__)
        ),
        "manifest_sdk": str(Path(agent_manifest.__file__)),
        "results": results,
        "receipts": receipts,
        "gateway_public_b64": g.b64(v.public_bytes(gateway_key)),
        "limits": [
            "Controlled fixture clock and synthetic component appraisals/status source.",
            "Real Agent Manifest SDK and cMCP Cedar adapter; "
            "not production cMCP admission/forwarding.",
            "Signed manifest requirements intersect independent local appraisal policy; "
            "declarations add no trust.",
            "No hardware quote appraisal, live MCP endpoint, or production credentials.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))

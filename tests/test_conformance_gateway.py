"""Gateway and manifest-level checks for requirements the token corpus cannot carry.

Uses the real cMCP deployment fixture from test_cmcp_trace_gate.py and the signed
Agent Manifest helper from test_manifest_requirements_bridge.py.
"""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytest.importorskip("cmcp_runtime", reason="cross-repository cMCP dependency required")
pytest.importorskip("agent_manifest", reason="sibling Agent Manifest SDK required")

from prototype import verifier_token as v
from tests.test_cmcp_trace_gate import admit, credentials, deployment, holder_proof
from tests.test_manifest_requirements_bridge import signed_packet
from tests.test_verifier_token_profile import fixture, g

__all__ = ["deployment", "fixture"]

UNBOUND = [
    "tool_manifest",
    "rag_corpus",
    "memory_baseline",
    "decision_trace",
    "delegation_chain",
    "supply_chain",
    "hitl_record",
]


def test_composition_only_manifest_cannot_drive_requirements(fixture):
    """TR-VT-MAN-003: composition-only scope never yields complete signed requirements."""

    def composition_with_requirements(manifest):
        manifest["profile"] = "composition-only"
        manifest["unbound_artifacts"] = list(UNBOUND)

    with pytest.raises(ValueError, match="evidence_requirements needs its explicit"):
        signed_packet(fixture, composition_with_requirements)

    def composition_only(manifest):
        composition_with_requirements(manifest)
        manifest.pop("evidence_requirements")

    with pytest.raises(ValueError, match="^manifest appraisal not valid: INCOMPLETE$"):
        signed_packet(fixture, composition_only)
    # The full-binding control passes through the same helper.
    assert signed_packet(fixture)[1].manifest_digest.startswith("sha256:")


@pytest.mark.asyncio
async def test_receipt_binds_exact_trace_action_and_gateway_key(deployment):
    """TR-VT-REC-001: receipt verifies only under the gateway key and names exact inputs."""
    d = deployment
    admit(d)
    result = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=credentials(d))
    assert result.allowed
    signed = d["gate"].receipts()[0]
    receipt = v.authenticate(signed, v.RECEIPT_PROFILE, d["key"].public_key(), v.Receipt)
    # TRACE digest: exact presented token bytes, not a different token with the same claims.
    assert receipt.trace_digest == v.digest(d["raw"])
    other = v.read_payload(v.unpack(d["raw"], v.PROFILE)[1], v.Token).model_dump(mode="json")
    other["jti"] = "other-token"
    assert receipt.trace_digest != v.digest(g.envelope(other, g.ISSUER))
    # Action digest: the forwarded call, not a mutated one.
    assert receipt.action_digest == v.canonical_digest(
        d["proxy"].trace_action("call-1", "read", {})
    )
    assert receipt.action_digest != v.canonical_digest(
        d["proxy"].trace_action("call-1", "read", {"id": "2"})
    )
    # Unknown gateway key: neither the verifier nor a stranger key authenticates it.
    for key in (g.ISSUER, Ed25519PrivateKey.from_private_bytes(bytes(range(128, 160)))):
        with pytest.raises(v.ProfileError, match="^key_id_mismatch$"):
            v.authenticate(signed, v.RECEIPT_PROFILE, key.public_key(), v.Receipt)
    # The receipt is a separate object: it does not parse as a verifier token.
    with pytest.raises(v.ProfileError, match="^protected_headers$"):
        v.verify_token(signed, d["gate"].context, g.NOW)
    await d["client"].aclose()


@pytest.mark.asyncio
async def test_missing_or_cross_session_proof_is_refused(deployment):
    """TR-VT-CNF-002: no proof, or a proof made for another session, stops transport."""
    d = deployment
    admit(d)
    missing = await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=None)
    assert not missing.allowed
    action = d["proxy"].trace_action("call-2", "read", {})
    challenge = d["gate"].challenge(d["raw"], session_id="session-1", action=action)
    moved = copy.deepcopy(challenge)
    moved["session_id"] = "session-2"
    with pytest.raises(v.ProfileError, match="^holder_proof_binding$"):
        d["gate"].begin(
            holder_proof(moved, d["raw"]),
            action=action,
            session_id="session-1",
            call_id="call-2",
            policy_digest=d["evaluator"].bundle_hash,
        )
    assert d["calls"] == []
    await d["client"].aclose()

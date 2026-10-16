"""Explicit operator composition; experimental dependencies stay out of cMCP defaults."""

from __future__ import annotations

from dataclasses import replace
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if TYPE_CHECKING:
    from agent_manifest import RevocationStore, VerificationContext
    from cmcp_runtime.mcp.server import MCPServer
    from cmcp_runtime.startup import RuntimeContext

from . import verifier_token as v
from .cmcp_gate import CMCPTraceGate
from .gate_store import GateStore
from cmcp_runtime.manifest_catalog import manifest_catalog_binding
from .manifest_requirements import combine_requirements


def build_protected_server(
    runtime: RuntimeContext,
    *,
    manifest_bytes: bytes,
    manifest_context: VerificationContext,
    manifest_revocations: RevocationStore,
    token_context: v.VerificationContext,
    database: str | Path | None = None,
    store: GateStore | None = None,
    gateway_key: Ed25519PrivateKey,
    gateway_issuer: str,
    clock: Callable[[], float],
) -> MCPServer:
    """Verify signed intent and wire the gate through cMCP's production builder.

    All arguments are operator configuration, never client-supplied trust data.
    Pass ``database`` for the one-host SQLite store or ``store`` (for example
    ``RemoteGateStore``) when several gateway replicas share replay state.
    A deployment must supply a live status callback and trusted clock. This
    factory does not manufacture a hardware appraisal or inferred identity.
    """
    from agent_manifest.evidence_requirements import verify_evidence_manifest
    from cmcp_runtime.cli import build_server

    if not runtime.config.bearer_token:
        raise v.ProfileError("authenticated_transport_required")
    projection = manifest_catalog_binding(runtime.catalog)
    manifest_context = manifest_context.model_copy(
        update={
            "tool_catalog_hash": projection["catalog_hash"],
            "policy_bundle_hash": runtime.policy_bundle.bundle.bundle_hash,
        }
    )
    try:
        verified = verify_evidence_manifest(manifest_bytes, manifest_context, manifest_revocations)
    except ValueError as exc:
        raise v.ProfileError("manifest_appraisal_failed") from exc
    catalog_requirements = [
        c
        for c in verified.requirements.components
        if c.component_type == "tool-catalog"
        and c.required
        and c.artifact_ref == "artifacts.tool_manifest"
    ]
    if (
        not catalog_requirements
        or dict(verified.artifact_results).get("tool_manifest") != "MATCH"
        or any(
            c.expected_observed_digest != runtime.catalog.catalog_hash for c in catalog_requirements
        )
    ):
        raise v.ProfileError("signed_gateway_catalog_binding_required")
    if (
        token_context.manifest_bytes != manifest_bytes
        or token_context.manifest_id != verified.manifest_id
        or token_context.subject != verified.agent_id
        or (
            verified.agent_instance_id is not None
            and token_context.instance != verified.agent_instance_id
        )
    ):
        raise v.ProfileError("manifest_authenticated_identity_mismatch")
    requirements = combine_requirements(verified, token_context.requirements, token_context.policy)
    context = replace(
        token_context,
        requirements=requirements,
        manifest_valid_until=min(token_context.manifest_valid_until, verified.expires_at),
    )
    gate = CMCPTraceGate(
        context,
        database=database,
        store=store,
        gateway_key=gateway_key,
        gateway_issuer=gateway_issuer,
        gateway_policy_digest=runtime.policy_bundle.bundle.bundle_hash,
        clock=clock,
    )
    return build_server(runtime, trace_gate=gate)

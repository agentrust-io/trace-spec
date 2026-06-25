# Integration: AGT

[AGT (Agent Governance Toolkit)](https://github.com/microsoft/agent-governance-toolkit) is the most widely adopted agent governance framework (4,100+ stars, 100+ contributors). It provides Cedar policy enforcement, SPIFFE/SVID identity, and Merkle-chained audit logs for any agent framework.

AGT emits TRACE v0.1 Trust Records via `TRACEAuditSink` — see [ADR 0032](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/adr/0032-agt-emits-trace-v01-trust-records.md) for the full design.

## What AGT emits

AGT emits **Level 0 (software-only)** TRACE records. The record is signed with an Ed25519 key held in the operator's key store — not a TEE-bound key. For Level 2 hardware-rooted records, deploy AGT inside [cMCP](cmcp.md) or another TEE runtime.

| TRACE field | Source in AGT |
|---|---|
| `subject` | `agent_did` passed to `govern()` |
| `policy.bundle_hash` | SHA-256 of the Cedar policy bundle bytes at session start |
| `policy.enforcement_mode` | Always `enforce` (Phase 1) |
| `tool_transcript.hash` | SHA-256 of the canonical JSON of the Merkle `AuditEntry` list |
| `tool_transcript.call_count` | Count of `AuditEntry` items in the session |
| `runtime.platform` | `software-only` |
| `runtime.measurement` | SHA-256 of the Merkle chain tip |
| `appraisal.status` | `affirming` (Phase 1) |
| `model`, `data_class`, `build_provenance` | Injected from `TraceConfig` |

## Install

```bash
pip install agentmesh agentrust-trace
```

## Quick start: TraceAGTAdapter

`TraceAGTAdapter` eliminates the ~50-line field-mapping boilerplate. Install:

```bash
pip install agentrust-trace
```

One-liner upgrade path for any AGT-governed session:

```python
from agentrust_trace.adapters import TraceAGTAdapter, AGTSessionResult
from agentrust_trace import sign_record, generate_key

adapter = TraceAGTAdapter(
    model_provider="anthropic",
    model_id="claude-sonnet-4-6",
    model_version="20251001",
    build_provenance_digest="sha256:e5f6a7b8...",
    transparency="https://registry.agentrust.io/claim/...",
)

session = AGTSessionResult(
    agent_did="spiffe://trust.example.org/agent/my-agent",
    policy_bundle_bytes=Path("policy.cedar").read_bytes(),
    audit_entries=govern_fn.get_audit_entries(),
    merkle_chain_tip=govern_fn.chain_tip,
)

record = adapter.build_trust_record(session)
signed = sign_record(record, generate_key())  # or load_signing_key() for production
```

→ Full walkthrough: [TraceAGTAdapter tutorial](../tutorials/agt-adapter.md)

## Manual wiring (legacy)

The following is the raw field-mapping approach — kept for reference. Prefer `TraceAGTAdapter` for new integrations.

```python
from agentmesh.governance import govern, GovernanceConfig
from agentmesh.governance.trace_sink import TraceConfig

trace_config = TraceConfig(
    output_path="session.trace.json",
    model_provider="anthropic",
    model_id="claude-sonnet-4-6",
    model_version="20251001",
    data_class="confidential",
    build_provenance_slsa_level=2,
    build_provenance_digest="sha256:e5f6a7b8...",
)

config = GovernanceConfig(
    policy_path="policy.cedar",
    trace=trace_config,
)

governed_fn = govern(
    my_tool,
    agent_did="spiffe://trust.example.org/agent/my-agent",
    config=config,
)

result = governed_fn(input)
path = governed_fn.close_session()
print(f"Trust Record written to: {path}")
```

## Key management

Key material is managed entirely by `agentrust_trace.load_signing_key()`. AGT does not hold keys directly.

```bash
# Set the signing key path via environment variable
export AGENTRUST_TRACE_KEY_PATH=/run/secrets/trace-signing-key.pem
```

For production, store the key in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secret) and inject via environment variable or volume mount.

## Verifying the emitted record

```bash
agentrust-trace verify session.trace.json --pubkey trace-key.pem.pub
```

## Upgrading to Level 2 (hardware-rooted)

Deploy your AGT-governed agent inside cMCP. The cMCP runtime:

1. Measures the Cedar policy bundle into the TEE before any code runs
2. Generates a TEE-bound key for the TRACE record
3. Emits a Level 2 record that supersedes AGT's Level 0 record for the same session

The two records are linked by a shared `subject` and `tool_transcript.hash` — AGT's record and cMCP's record are mutually verifiable.

→ [Integration guide: cMCP](cmcp.md)

## Framework support

AGT instruments any Python callable via `govern()`. Confirmed compatible frameworks:

| Framework | Notes |
|---|---|
| LangGraph | Wrap tool nodes with `govern()` |
| CrewAI | Wrap task tools |
| AutoGen | Wrap function tools |
| Mastra | Via adapter contract |
| Raw Python | Direct function wrapping |

For the full integration list, see the [AGT integrations repo](https://github.com/agentrust-io/integrations).

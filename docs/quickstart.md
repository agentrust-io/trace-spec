# Quickstart

Get your first TRACE Trust Record in five minutes.

## Install

```bash
pip install agentrust-trace
```

## Generate a signing key

```bash
# Ed25519 key — store the private key securely; distribute only the public key
python -m agentrust_trace keygen --out trace-key.pem
```

## Emit a Trust Record from AGT

```python
from agentmesh.governance import govern, GovernanceConfig
from agentmesh.governance.trace_sink import TraceConfig

config = GovernanceConfig(
    policy_path="policy.cedar",
    trace=TraceConfig(
        output_path="session.trace.json",
        model_provider="anthropic",
        model_id="claude-sonnet-4-6",
        model_version="20251001",
    ),
)

governed_fn = govern(my_tool, agent_did="spiffe://trust.example.org/agent/my-agent", config=config)

# Your agent runs normally — TRACE record is emitted on session close
result = governed_fn(input)
governed_fn.close_session()
# → writes session.trace.json
```

## Verify offline

```bash
agentrust-trace verify session.trace.json --pubkey trace-key.pem.pub
```

Output:

```
✓  Signature     valid (Ed25519)
✓  eat_profile   tag:agentrust.io,2026:trace-v0.1
✓  subject       spiffe://trust.example.org/agent/my-agent
✓  policy        sha256:b2c3d4e5... (enforce)
✓  data_class    internal
✓  tool_calls    3
✓  appraisal     affirming

Trust Record verified. No issuer callback required.
```

## What you now have

| Claim | What it proves |
|---|---|
| `policy.bundle_hash` | Exact Cedar policy hash that governed the session |
| `tool_transcript.hash` | Merkle-chained audit log of every tool invocation |
| `subject` | Workload identity (SPIFFE or DID) |
| `appraisal.status` | Verifier judgment: affirming / contraindicated |
| `signature` | Ed25519 over the full record — verifiable offline |

## Add hardware attestation (Level 2)

For TEE-rooted records (AMD SEV-SNP, Intel TDX, NVIDIA H100), use cMCP as the runtime — it issues Level 2 TRACE records with a TEE-bound key and a SCITT transparency anchor automatically.

→ [Integration guide: cMCP](integration/cmcp.md)

## Next steps

- [Full Specification](../spec/trace-v0.1.md) — all claims, wire formats, conformance
- [Verification Protocol](verification.md) — five-step offline verification
- [Schema Reference](schema.md) — JSON Schema with field descriptions

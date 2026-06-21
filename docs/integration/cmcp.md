# Integration: cMCP

[Confidential MCP (cMCP)](https://github.com/agentrust-io/cmcp) is the reference implementation of TRACE Level 2. It is an MCP gateway that:

1. Intercepts every tool call from any MCP-compatible agent
2. Evaluates Cedar policy inside a hardware TEE (AMD SEV-SNP, Intel TDX, NVIDIA H100)
3. Measures the policy bundle into the TEE before any code runs
4. Signs the TRACE Trust Record with a TEE-bound Ed25519 key
5. Anchors the record in the TRACE transparency registry (optional)

The result: a hardware-verifiable governance record for every agent session — signed by silicon, not by an operator process.

## Architecture

```
  Agent (LangGraph, CrewAI, AutoGen, ...)
        │  MCP tool call
        ▼
  ┌─────────────────────────────────────┐
  │  cMCP Gateway (TEE boundary)        │
  │  ┌────────────────────────────────┐ │
  │  │  Cedar policy evaluation       │ │
  │  │  → allow / deny / escalate     │ │
  │  └────────────────────────────────┘ │
  │  ┌────────────────────────────────┐ │
  │  │  Tool-call transcript signing  │ │
  │  │  TEE-bound key (cnf.jwk)       │ │
  │  └────────────────────────────────┘ │
  │  ┌────────────────────────────────┐ │
  │  │  TRACE Level 2 record emission │ │
  │  └────────────────────────────────┘ │
  └─────────────────────────────────────┘
        │  Forwarded tool call
        ▼
  MCP Tool Server (outside TEE)
```

## Conformance level

cMCP emits **TRACE Level 2** records:

| Property | Level 0 (AGT) | Level 2 (cMCP) |
|---|---|---|
| Policy hash | ✓ SHA-256 | ✓ SHA-256, TEE-measured |
| Signing key | Software key | TEE-bound key (never leaves enclave) |
| `runtime.platform` | `software-only` | `amd-sev-snp` / `intel-tdx` / `nvidia-h100` |
| Hardware measurement | ✗ | ✓ `runtime.measurement` |
| Independent verifiability | Key management by operator | Hardware endorsement chain |

## Quick start

```bash
docker pull ghcr.io/agentrust-io/cmcp:latest

docker run --device /dev/sev \
  -e CEDAR_POLICY_PATH=/policies/my-policy.cedar \
  -e UPSTREAM_MCP_URL=http://my-mcp-server:8080 \
  -p 8443:8443 \
  -v $(pwd)/policies:/policies \
  ghcr.io/agentrust-io/cmcp:latest
```

Your agent points at `https://localhost:8443` instead of the upstream MCP server. Zero code change.

## Cedar policy example

```cedar
// Allow credit-risk agent to call financial tools — deny if data class is secret
permit(
  principal == Agent::"spiffe://trust.example.org/agent/credit-risk",
  action == Action::"call_tool",
  resource in Tools::"financial"
)
when {
  context.data_class != "secret"
};
```

Cedar policies are versioned, code-reviewable, and their SHA-256 hash is bound into the TRACE record at the TEE measurement step — before any code runs.

## Connect an MCP-compatible agent

```python
import anthropic

# Point at cMCP gateway instead of your MCP server
client = anthropic.Anthropic()
response = client.beta.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    tools=[{
        "type": "mcp",
        "server_url": "https://localhost:8443",  # cMCP gateway
    }],
    messages=[{"role": "user", "content": "Analyze this credit application"}],
    betas=["mcp-client-2025-04-04"],
)
```

## Retrieve the TRACE record

After the session, fetch the TRACE record from the gateway:

```python
import httpx

record = httpx.get("https://localhost:8443/trace/latest").json()
# → full TRACE v0.1 Trust Record, Level 2, signed by TEE-bound key
```

Or let cMCP push it to the transparency registry automatically:

```yaml
# cmcp.yaml
trace:
  emit: true
  registry: https://registry.agentrust.io
  scitt_anchor: true
```

## Hardware platform support

| Platform | Status |
|---|---|
| AMD SEV-SNP | ✓ GA |
| Intel TDX | ✓ GA |
| NVIDIA H100 Confidential | ✓ GA (demonstrated at GTC Berlin) |
| NVIDIA Blackwell | Preview |
| TPM 2.0 (software-only TEE) | ✓ GA — development mode, no memory encryption |
| Azure CVM (SEV-SNP) | ✓ GA |
| GCP Confidential VM (TDX) | ✓ GA |
| AWS Nitro Enclave | Preview |

## Relationship to AGT

cMCP embeds AGT. The Cedar policy engine, SPIFFE identity, and Merkle audit chain are AGT. cMCP adds the TEE boundary, hardware key generation, and Level 2 TRACE emission.

When cMCP emits a Level 2 record for a session, it supersedes any Level 0 record AGT might have emitted for the same session. The two records are linked by shared `subject` and `tool_transcript.hash`.

## Related

| What | Where |
|------|-------|
| Trust level guarantees | [Trust Levels](../trust-levels.md) |
| Hardware attestation platforms | [Platforms overview](../platforms/index.md) |
| Step-by-step cMCP integration tutorial | [Integrating with cMCP](../tutorials/integrating-with-cmcp.md) |
| cMCP source and deployment | [agentrust-io/cmcp](https://github.com/agentrust-io/cmcp) |
| AGT integration | [Integration: AGT](agt.md) |

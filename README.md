<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="TRACE"/>
</p>

# TRACE: Trust Runtime Attestation and Compliance Evidence

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](LICENSE)
[![AAIF](https://img.shields.io/badge/Targeting-AAIF_%2F_Linux_Foundation-6366f1)](https://agenticai.foundation)
[![Spec](https://img.shields.io/badge/Spec-v0.1-0ea5e9)](spec/trace-v0.1.md)

> **Developer Preview.** Launching at Confidential Computing Summit, June 23 2026. May have breaking changes before v1.0.

<p align="center">
  <a href="spec/trace-v0.1.md">Specification</a> &nbsp;|&nbsp;
  <a href="schema/trace-claim.json">Schema</a> &nbsp;|&nbsp;
  <a href="examples/">Examples</a> &nbsp;|&nbsp;
  <a href="https://github.com/agentrust-io/trace-registry">Registry</a> &nbsp;|&nbsp;
  <a href="https://github.com/agentrust-io/cmcp">Reference Impl</a>
</p>

An open specification for hardware-attested AI agent governance records. TRACE defines the format, anchoring protocol, and verification rules for cryptographically provable evidence that an AI agent ran under a specific policy, in a verified hardware environment, on classified data, invoking identified tools, bound into a single signed artifact rooted in silicon attestation.

## What a TRACE Trust Record Is

```json
{
  "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
  "iat": 1750676142,
  "subject": "spiffe://trust.example.org/agent/payments-processor/prod",
  "model": {
    "provider": "anthropic",
    "model_id": "claude-sonnet-4-6",
    "version": "20251001",
    "weights_digest": "sha256:a3f8d2c1..."
  },
  "runtime": {
    "platform": "amd-sev-snp",
    "measurement": "sha384:c9e4b1d2e3f4...",
    "rim_uri": "https://kdsintf.amd.com/vcek/v1/..."
  },
  "policy": {
    "bundle_hash": "sha256:b2c3d4e5...",
    "enforcement_mode": "enforce",
    "version": "1.2.0"
  },
  "data_class": "confidential",
  "tool_transcript": {
    "hash": "sha256:d4e5f6a7...",
    "call_count": 3
  },
  "build_provenance": {
    "slsa_level": 2,
    "builder": "https://github.com/slsa-framework/slsa-github-generator",
    "digest": "sha256:e5f6a7b8..."
  },
  "appraisal": {
    "status": "affirming",
    "verifier": "https://trust-authority.example.org",
    "policy_ref": "https://trust-authority.example.org/policy/agent-v1"
  },
  "transparency": "https://registry.agentrust.io/claim/trace-2026-06-23T09:15:42Z-f2a8d1",
  "cnf": {
    "jwk": {"kty": "EC", "crv": "P-256", "x": "MEkwEw...", "y": "..."}
  }
}
```

The record is a single EAT envelope (RFC 9711). Each field is independently verifiable. No callback to the issuer is required.

### Supported platforms

| Platform | v0.1 | v0.2 (planned) | Notes |
|---|---|---|---|
| `intel-tdx` | Yes | Yes | |
| `amd-sev-snp` | Yes | Yes | |
| `nvidia-h100` | Yes | Yes | |
| `gpu-cc` | No | Planned | Generic GPU confidential compute |
| `opaque` | Yes | Yes | Explicit opt-in; contact maintainers |

## Specification

- [`spec/trace-v0.1.md`](spec/trace-v0.1.md) -- full specification
- [`schema/trace-claim.json`](schema/trace-claim.json) -- JSON Schema
- [`examples/`](examples/) -- example Trust Records for Intel TDX, AMD SEV-SNP, and NVIDIA H100

## Standards composition

TRACE profiles existing standards rather than replacing them:

| Primitive | Role in TRACE |
|---|---|
| RATS / EAT (RFC 9711) | Wire envelope and claim model |
| SLSA Provenance v1.0 | Build-time provenance (`build_provenance`) |
| SPIFFE SVID | Workload identity (`subject`) |
| SCITT | Append-only transparency anchoring (`transparency`) |
| EAR (draft-ietf-rats-ar4si) | Verifier appraisal output (`appraisal`) |
| MCP / A2A | Agent tool-call transcript surface (`tool_transcript`) |
| AIBOM (SPDX 3.0 / CycloneDX 1.7) | Model component inventory (`model`) |

## Reference implementation

[agentrust-io/cmcp](https://github.com/agentrust-io/cmcp) -- Confidential MCP Gateway. Hardware-attested policy enforcement at the MCP tool-call boundary on Intel TDX, AMD SEV-SNP, and NVIDIA H100/Blackwell.

## Registry

A public append-only Merkle registry of TRACE Trust Record anchors: [agentrust-io/trace-registry](https://github.com/agentrust-io/trace-registry).

## Status

Draft v0.1. Publishing at Confidential Computing Summit, San Francisco, June 23 2026. Targeting submission to the [Agentic AI Foundation (AAIF)](https://agenticai.foundation) under the Linux Foundation.

## License

Creative Commons Attribution 4.0 International (CC BY 4.0)

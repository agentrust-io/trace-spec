# TRACE — Trust Runtime Attestation and Compliance Evidence

An open specification for hardware-attested AI agent governance claims. TRACE defines the format, anchoring protocol, and verification API for cryptographically provable evidence that an AI agent ran under a specific policy, in a specific hardware environment, producing a tamper-evident audit chain.

## What a TRACE Claim Is

```json
{
  "spec_version": "0.1",
  "claim_id": "trace-2026-06-23T09:15:42Z-f2a8d1",
  "producer": "cmcp-gateway/0.1.0",
  "policy_bundle_hash": "sha256:a3f8d2...",
  "enforcement_mode": "enforce",
  "audit_chain_root": "sha256:c9e4b1...",
  "trust_score": 847,
  "tee_public_key": "ecdsa-p256:MEkwEw...",
  "hardware_sig": "base64:MEQCIHx...",
  "tee_platform": "sev-snp",
  "timestamp": "2026-06-23T09:15:42Z"
}
```

## Specification

- [`spec/trace-v0.1.md`](spec/trace-v0.1.md) — full specification
- [`schema/trace-claim.json`](schema/trace-claim.json) — JSON Schema
- [`examples/`](examples/) — example claims from each hardware provider

## Standards

TRACE is being submitted to the [Agentic AI Foundation (AAIF)](https://agenticai.foundation) under the Linux Foundation. Submission target: July 2026.

The Certificate Transparency analogy: Opaque authors the standard and operates the reference registry. Any governance tool can produce TRACE claims. Any auditor can verify them independently.

## Registry

A public append-only Merkle registry of TRACE claim anchors is mirrored at [agentrust-io/trace-registry](https://github.com/agentrust-io/trace-registry).

## Status

Private. Spec v0.1 publishing at CC Summit June 23, 2026.

## License

Creative Commons Attribution 4.0 International (CC BY 4.0)
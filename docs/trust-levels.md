---
description: TRACE defines three trust levels, each adding a stronger guarantee about the origin and integrity of a trust record, from software signing to hardware attestation.
---

# Trust Levels

TRACE defines three trust levels. Each level adds a stronger guarantee about the origin and integrity of the trust record. Higher levels require additional infrastructure but enable stronger relying-party policies.

## Summary

| Level | Name | Key guarantee | Typical use |
|-------|------|--------------|-------------|
| 0 | Software-only | Record is structurally valid and Ed25519-signed | Development, CI, unit testing |
| 1 | TEE attestation | Record is signed by a key that was generated inside a verified TEE | Staging, regulated production |
| 2 | Transparency anchoring | Level 1 plus SCITT transparency log entry | Multi-tenant, cross-org audit chains |

## Level 0 — Software-only

Level 0 records are signed with an Ed25519 key held by the agent process. There is no hardware attestation step. The `runtime.platform` field must be `software-only`.

**What it proves:** The record has not been tampered with since the agent process signed it. The signing key is trust-on-first-use.

**What it does not prove:** The key was generated in a trusted execution environment. An attacker with access to the signing key can forge records.

**Minimum required fields:**

```json
{
  "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
  "iat": 1750000000,
  "subject": "spiffe://trust.example.org/agent/my-agent",
  "model": { "provider": "anthropic", "model_id": "claude-sonnet-4-6", "version": "20251001" },
  "runtime": { "platform": "software-only", "measurement": "sha256:0000...0000" },
  "policy": { "bundle_hash": "sha256:b2c3...", "enforcement_mode": "enforce" },
  "data_class": "internal",
  "build_provenance": { "slsa_level": 1, "digest": "sha256:e5f6..." },
  "appraisal": { "status": "none", "verifier": "https://verifier.example.org" },
  "transparency": "https://registry.agentrust.io/claim/placeholder",
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>" } },
  "signature": "<base64url>"
}
```

All-zero measurement (`sha256:000...000`) is conventional for software-only development records. The `appraisal.status` of `"none"` is correct when no hardware verifier is in the path.

---

## Level 1 — TEE Attestation

Level 1 requires that the signing key be generated inside a verified TEE (AMD SEV-SNP, Intel TDX, NVIDIA H100, or TPM2). The `runtime.platform` field must be one of these values, and `runtime.measurement` must be a non-zero hardware measurement (PCR hash, launch measurement, or equivalent).

**What it proves:** The signing key was generated inside a hardware-isolated enclave whose firmware digest matches the `runtime.measurement`. An attacker who compromises the host OS cannot forge records without breaking the TEE isolation boundary.

**What it does not prove:** The record was published to a public ledger. Audit chains cannot span organizational boundaries without a shared transparency anchor.

**Additional required fields over Level 0:**

| Field | Requirement |
|-------|-------------|
| `runtime.platform` | Must be `tpm2`, `sev-snp`, `tdx`, or `opaque` (not `software-only`) |
| `runtime.measurement` | Non-zero `sha256:` or `sha384:` digest of the TEE launch state |
| `appraisal.status` | Must be `affirming` (verifier has checked the TEE quote) |
| `build_provenance.slsa_level` | Must be present (0–4) |
| `build_provenance.digest` | Must be a valid `sha256:` digest |

The cMCP runtime handles Level 1 record emission automatically when running in a supported TEE. See [Hardware Attestation Platforms](tutorials/hardware-attestation-platforms.md).

---

## Level 2 — Transparency Anchoring

Level 2 adds a SCITT transparency log entry to a Level 1 record. The `transparency` field must be a resolvable HTTPS URI that returns a valid reference manifest from a SCITT-compatible log.

**What it proves:** The record has been durably committed to an append-only transparency log that any party can query. This makes post-hoc audit possible without trusting either the agent or its operator.

**What it does not prove:** That every field in the record is correct — only that the specific record at the URI has not been altered since it was logged.

**Additional required fields over Level 1:**

| Field | Requirement |
|-------|-------------|
| `transparency` | Resolvable `https://` URI to a SCITT receipt |

The [SCITT reference implementation](https://github.com/microsoft/scitt-api-emulator) and the [agentrust SCITT registry](https://registry.agentrust.io) are both supported anchors.

**Recommended flow:**

```
Agent signs Level 1 record
        ↓
Submit record to SCITT transparency log → get receipt URI
        ↓
Append transparency URI to record (does not invalidate signature)
        ↓
Distribute Level 2 record to relying party
```

The signature covers all fields except `signature` itself. Appending the `transparency` field after the initial signing step requires re-signing. The recommended pattern is to emit a Level 1 record, submit it for transparency, then emit a new Level 2 record with the receipt URI and a fresh signature.

---

## Choosing a level

| If you are... | Use level |
|---------------|-----------|
| Building an agent locally or writing tests | 0 |
| Running agents in production but within a single org | 1 |
| Sharing records across organizational boundaries | 2 |
| Meeting a regulated compliance requirement | 1 or 2 (check your framework) |

Relying parties set the minimum acceptable level in their Cedar policy. Records that fail to meet the required level are rejected at the policy enforcement point before the agent is permitted to act.

## Related

- [Trust Levels in the test suite](https://tests.agentrust-io.com/levels)
- [TRACE Specification — Section 4: Trust Levels](../spec/trace-v0.1.md)
- [Hardware Attestation Platforms](tutorials/hardware-attestation-platforms.md)
- [Glossary](glossary.md)

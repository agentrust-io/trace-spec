# Schema Reference

JSON Schema for the TRACE v0.1 Trust Record. Source: [`schema/trace-claim.json`](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-claim.json).

## Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `eat_profile` | string | **yes** | EAT profile URI. Must be `tag:agentrust.io,2026:trace-v0.1` |
| `iat` | integer | **yes** | Issued-at timestamp (Unix epoch seconds) |
| `subject` | string | **yes** | Workload identity. SPIFFE SVID (`spiffe://`) or DID (`did:`) |
| `model` | object | **yes** | Model artifact binding |
| `runtime` | object | **yes** | Execution environment binding |
| `policy` | object | **yes** | Governance policy binding |
| `data_class` | string | **yes** | Data sensitivity classification |
| `tool_transcript` | object | **yes** | Tool-call audit summary |
| `build_provenance` | object | **yes** | Build-time artifact provenance |
| `appraisal` | object | **yes** | Verifier judgment |
| `transparency` | string | **yes** | SCITT transparency log anchor URI (empty string if not anchored) |
| `cnf` | object | **yes** | Confirmation method — contains the `jwk` signing key |
| `signature` | string | **yes** | Base64url Ed25519 / ES256 / ES384 signature over the record |

## `model`

Binds the model artifact used in this session.

| Field | Type | Required | Description |
|---|---|---|---|
| `provider` | string | **yes** | Model provider (e.g., `anthropic`, `openai`, `meta`) |
| `model_id` | string | **yes** | Model identifier (e.g., `claude-sonnet-4-6`) |
| `version` | string | **yes** | Model version or date stamp |
| `weights_digest` | string | no | SHA-256 digest of model weights artifact |
| `aibom_uri` | string | no | URI to the AI Bill of Materials (SPDX/CycloneDX) |

## `runtime`

Binds the execution environment. Platform-specific fields vary by TEE type.

| Field | Type | Required | Description |
|---|---|---|---|
| `platform` | string | **yes** | One of: `amd-sev-snp`, `intel-tdx`, `nvidia-h100`, `nvidia-blackwell`, `tpm-2.0`, `software-only` |
| `measurement` | string | **yes** | Hardware measurement hash (`sha384:` for SEV-SNP/TDX, `sha256:` for TPM) |
| `rim_uri` | string | no | Reference Integrity Manifest URI for hardware verification |
| `firmware_version` | string | no | TEE firmware version |
| `nonce` | string | no | Freshness nonce — ties this record to a specific attestation challenge |

## `policy`

Binds the governance policy in force during this session.

| Field | Type | Required | Description |
|---|---|---|---|
| `bundle_hash` | string | **yes** | `sha256:` digest of the Cedar policy bundle bytes |
| `enforcement_mode` | string | **yes** | `enforce` or `silent` (advisory) |
| `version` | string | no | Policy bundle version string |
| `policy_uri` | string | no | URI to the policy bundle for inspection |

## `data_class`

String. Sensitivity classification applied to the data processed in this session.

Defined values: `public`, `internal`, `confidential`, `restricted`, `secret`.

Custom values are allowed and SHOULD follow your organization's data classification policy.

## `tool_transcript`

Audit summary of tool invocations during the session.

| Field | Type | Required | Description |
|---|---|---|---|
| `hash` | string | **yes** | `sha256:` of the canonical JSON of the full `AuditEntry` list |
| `call_count` | integer | **yes** | Number of tool invocations recorded |
| `transcript_uri` | string | no | URI to the full per-call transcript (may be encrypted) |

## `build_provenance`

Build-time provenance binding the deployed artifact.

| Field | Type | Required | Description |
|---|---|---|---|
| `slsa_level` | integer | **yes** | SLSA provenance level (0–3) |
| `builder` | string | **yes** | Builder identity URI (e.g., GitHub Actions SLSA generator) |
| `digest` | string | **yes** | `sha256:` digest of the built artifact |
| `provenance_uri` | string | no | URI to the SLSA provenance document (e.g., Rekor entry) |

## `appraisal`

Verifier judgment on the evidence in this record.

| Field | Type | Required | Description |
|---|---|---|---|
| `status` | string | **yes** | One of: `affirming`, `warning`, `contraindicated`, `none` |
| `verifier` | string | **yes** | URI of the verifier that produced this appraisal |
| `policy_ref` | string | no | URI to the appraisal policy applied |
| `timestamp` | integer | no | Unix epoch seconds when appraisal was performed |

## `transparency`

String. URI of the SCITT transparency log entry anchoring this record. Empty string (`""`) if not anchored at issuance — anchoring may happen asynchronously.

## `cnf`

Confirmation method. Contains the signing key bound to this record.

| Field | Type | Description |
|---|---|---|
| `jwk` | object | JWK-format public key used to verify `signature` |

For TEE-issued records, this key was generated inside the measured enclave and its private half never leaves it. The hardware measurement in `runtime` cryptographically binds this key to the TEE.

## Wire formats

TRACE v0.1 supports two wire formats:

**JSON** (primary): signed JSON object with `signature` as a top-level field.

**CBOR-COSE** (constrained devices): COSE_Sign1 structure with TRACE claims as the payload. Defined in §3.2 of the spec — deferred to a future profile for constrained-device deployments.

## Example — AMD SEV-SNP

```json
{
  "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
  "iat": 1750676142,
  "subject": "spiffe://trust.example.org/agent/payments-processor/prod",
  "model": {
    "provider": "anthropic",
    "model_id": "claude-sonnet-4-6",
    "version": "20251001"
  },
  "runtime": {
    "platform": "amd-sev-snp",
    "measurement": "sha384:c9e4b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6...",
    "rim_uri": "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain",
    "firmware_version": "1.53.0"
  },
  "policy": {
    "bundle_hash": "sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1...",
    "enforcement_mode": "enforce",
    "version": "1.2.0"
  },
  "data_class": "confidential",
  "tool_transcript": {
    "hash": "sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3...",
    "call_count": 3
  },
  "build_provenance": {
    "slsa_level": 2,
    "builder": "https://github.com/slsa-framework/slsa-github-generator/...",
    "digest": "sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4..."
  },
  "appraisal": {
    "status": "affirming",
    "verifier": "https://trust-authority.example.org"
  },
  "transparency": "https://registry.agentrust.io/claim/trace-2026-06-23T09:15:42Z",
  "cnf": {
    "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
  },
  "signature": "base64url..."
}
```

See the full example files in [`examples/`](https://github.com/agentrust-io/trace-spec/tree/main/examples).

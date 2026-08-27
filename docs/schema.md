# Schema Reference

JSON Schema for the TRACE v0.2 Trust Record. Source: [`schema/trace-claim.json`](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-claim.json).

Every field typed `integer` here is bounded to -9007199254740991 through 9007199254740991, and no field is
typed `number`. That is not a size limit on the data; it is what spec section 3.2.2 can canonicalize
unambiguously, since RFC 8785 serializes numbers through an IEEE 754 double and two integers outside that range
can share one. A value that needs to be larger is carried as a string. The same bound applies to members a
`cnf.jwk` carries that this schema does not name.

## Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `eat_profile` | string | **yes** | EAT profile URI. Must be `tag:agentrust-io.com,2026:trace-v0.2` |
| `iat` | integer | **yes** | Issued-at timestamp (Unix epoch seconds) |
| `subject` | string | **yes** | Workload identity. SPIFFE SVID (`spiffe://`) or DID (`did:`) |
| `model` | object | **yes** | Model artifact binding |
| `runtime` | object | **yes** | Execution environment binding |
| `policy` | object | **yes** | Governance policy binding |
| `data_class` | string | **yes** | Data sensitivity classification |
| `tool_transcript` | object | **yes** | Tool-call audit summary |
| `delegation` | object | no | A2A profile: link to the delegating hop's Trust Record |
| `origin` | object | no | Where the evidence came from, when that is not this runtime |
| `references` | array | no | Facts outside this record that it points at. Assurance-neutral |
| `build_provenance` | object | **yes** | Build-time artifact provenance |
| `appraisal` | object | **yes** | Verifier judgment |
| `transparency` | string | no | Registry or SCITT anchor for the record. Optional below Level 2, where an unanchored record has no receipt to name. Use `null`, never `""` |
| `cnf` | object | **yes** | Confirmation method: contains the `jwk` signing key |
| `signature` | string | **yes** | Base64url Ed25519 / ES256 / ES384 signature over the canonical record with only `signature` absent; `cnf` is included |

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
| `platform` | string | **yes** | One of: `intel-tdx`, `amd-sev-snp`, `azure-cvm-sev-snp`, `nvidia-h100`, `nvidia-blackwell`, `aws-nitro`, `arm-cca`, `google-confidential-space`, `tpm2`, `software-only` |
| `measurement` | string | **yes** | Hardware measurement hash (`sha384:` for SEV-SNP/TDX, `sha256:` for TPM) |
| `rim_uri` | string | no | Reference Integrity Manifest URI for hardware verification |
| `firmware_version` | string | no | TEE firmware version |
| `nonce` | string | no | Freshness nonce: ties this record to a specific attestation challenge |

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

Custom values are allowed and should follow your organization's data classification policy.

## `tool_transcript`

Audit summary of tool invocations during the session.

| Field | Type | Required | Description |
|---|---|---|---|
| `hash` | string | **yes** | `sha256:` of the canonical JSON of the full `AuditEntry` list |
| `call_count` | integer | **yes** | Number of tool invocations recorded |
| `transcript_uri` | string | no | URI to the full per-call transcript (may be encrypted) |

## `delegation`

A2A profile. Present when this execution acted on authority delegated by another agent; absent on a root (non-delegated) execution. A chain of records linked this way forms an offline-verifiable delegation DAG: a verifier walks `parent_record_hash` from a leaf record back to the root and confirms each hop acted under a credential in the delegation chain.

| Field | Type | Required | Description |
|---|---|---|---|
| `parent_record_hash` | string | **yes** | `sha256:`/`sha384:` digest of the parent hop's Trust Record |
| `credential_id` | string | **yes** | Identifier of the delegation credential this hop acted under |

## `origin`

Absent means the runtime produced its own record, which is what every hardware profile is and what a consumer assumes. Present means something else assembled the record from evidence it did not itself measure.

It exists because `runtime.platform: "software-only"` is ambiguous on its own: it is the honest value for a dev-mode record, where nothing attested the execution, and for a record transcribed from another vendor's control plane, where the party asserting the evidence also wrote the log.

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | string | **yes** | `self`, `third-party-control-plane`, or `log-import` |
| `producer` | string | **yes** | Identifier of the system that produced the source evidence |
| `source_event_id` | string | no | Identifier of the source event in that system |
| `ingested_at` | integer | no | Unix time the evidence was ingested; `iat` is when this record was issued |

A record whose `kind` is not `self` **must** carry `runtime.platform: "software-only"`. An importer holding someone else's log has no quote to present, so a hardware platform on such a record is untrue rather than stronger. Both the reference model and `schema/trace-claim.json` reject the combination.

## `references`

An array of pointers to facts held outside this record: an authorization decided before execution, a human approval, a behavioural trace. What the signature attests is that this record points there, not the truth of what it points at.

`origin` records where evidence *came from* and can lower assurance. `references` records what a record *points at* and cannot. Before the block existed, a record that needed to name something external had to use `origin` and take `runtime.platform: "software-only"` with it, which said something untrue about how the evidence was obtained.

| Field | Type | Required | Description |
|---|---|---|---|
| `rel` | string | **yes** | Registered values: `authorized-intent`, `approval-outcome`, `behavior-trace`. A registry rather than a closed set, so the schema does not restrict which relation is named: only that one is: the value must be non-empty |
| `id` | string | **yes** | Identifier of the referenced fact within the resolver's system |
| `resolver` | string | **yes** | Identifier of the party obliged to resolve `id` |
| `retention` | string | no | ISO 8601 duration the resolver undertakes to keep `id` resolvable. An undertaking only; nothing enforces it |
| `digest` | string | no | `sha256:` or `sha384:` digest of the referenced object, when the producer holds it at issue time |

`rel` is open where `origin.kind` is closed. Section 3.1.1 says `kind` is a closed set "because the value of the field is that a verifier can key on it"; section 3.1.2 calls `rel`'s values a registry and does not say that, so a new relation is a spec change and not also a schema change.

Spec section 3.1.2 also binds verifiers: one **must not** reject a record because an entry cannot be resolved, and **must not** treat a resolved entry as attested evidence. A reference that could invalidate a record would hand whoever controls the target a way to invalidate evidence they do not hold. Both are verifier behaviour, so neither the schema nor the reference model can enforce them; they are conformance-suite rules. What the schema and the model do enforce is the shape, and that a producer who cannot name a `resolver` cannot emit an empty one.

## `build_provenance`

Build-time provenance binding the deployed artifact.

| Field | Type | Required | Description |
|---|---|---|---|
| `slsa_level` | integer | **yes** | SLSA provenance level (0 to 3) |
| `builder` | string | no | Builder identity URI (e.g., GitHub Actions SLSA generator) |
| `digest` | string | **yes** | `sha256:` digest of the built artifact |
| `provenance_uri` | string | no | URI to the SLSA provenance document (e.g., Rekor entry) |
| `provenance_depth` | string | no | Depth the issuer claims: `surface`, `builder` or `transitive`. Absent is read as `surface` |

## `appraisal`

Verifier judgment on the evidence in this record.

| Field | Type | Required | Description |
|---|---|---|---|
| `status` | string | **yes** | One of: `affirming`, `warning`, `contraindicated`, `none` |
| `verifier` | string | **yes** | URI of the verifier that produced this appraisal |
| `policy_ref` | string | no | URI to the appraisal policy applied |
| `timestamp` | integer | no | Unix epoch seconds when appraisal was performed |
| `provenance_depth_verified` | string | no | Depth this verifier actually ran: `surface`, `builder` or `transitive` |

## `transparency`

String. URI of the SCITT transparency log entry anchoring this record. Omitted, or `null`, when the record is not anchored at issuance: anchoring may happen asynchronously. Never an empty string: the reference model rejects one (`min_length=1`).

## `cnf`

Confirmation method. Contains the signing key bound to this record.

| Field | Type | Description |
|---|---|---|
| `jwk` | object | JWK-format public key used to verify `signature` |

For TEE-issued records, this key was generated inside the measured enclave and its private half never leaves it. The hardware measurement in `runtime` cryptographically binds this key to the TEE.

## Wire formats

TRACE v0.2 supports two wire formats:

**JSON** (primary): signed JSON object with `signature` as a top-level field.

**CBOR-COSE** (constrained devices): COSE_Sign1 structure with TRACE claims as the payload. Defined in §3.2 of the spec: deferred to a future profile for constrained-device deployments.

## Example: AMD SEV-SNP

```json
{
  "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
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
  "transparency": "https://registry.agentrust-io.com/claim/trace-2026-06-23T09:15:42Z",
  "cnf": {
    "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
  },
  "signature": "base64url..."
}
```

See the full example files in [`examples/`](https://github.com/agentrust-io/trace-spec/tree/main/examples).

# Conformance Levels

This page explains what a record needs to reach each conformance level, and which failures stop it. Read it when a record lands at a lower level than you expected, or before you decide which level to aim for.

TRACE defines three conformance levels. Level 0 is for development, Level 1 adds a claim about the secure hardware the agent ran on, and Level 2 adds a log of tool calls and proof that the record was entered in a public log. Each level runs everything the level below runs, plus more checks.

| Level | Required Modules               | Use Case                                            |
| ----- | ------------------------------ | --------------------------------------------------- |
| **0** | TR-ENV, TR-SIG, TR-POL, TR-APR | Development and staging, no secure hardware         |
| **1** | Level 0 + TR-RTE, TR-SCA       | Records that declare a TEE platform and measurement |
| **2** | Level 1 + TR-TXN, TR-ANC       | Full records with transparency anchoring            |

## Level 0: Software-only

Level 0 records are signed with a key kept in ordinary software rather than in secure hardware. The `runtime.platform` must be `"software-only"`. All-zero measurement is conventional for development use. The `appraisal` block (a verifier's verdict on the evidence) must be present and well formed, with a recognised `status` and a `verifier` that is an absolute URI, but Level 0 does not require the verdict to be positive.

**Minimum conformant Level 0 record:**

```
{
  "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
  "iat": 1750000000,
  "subject": "spiffe://trust.example.org/agent/my-agent",
  "model": {
    "provider": "example-provider",
    "model_id": "example-model-1",
    "version": "20251001"
  },
  "runtime": {
    "platform": "software-only",
    "measurement": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  },
  "policy": {
    "bundle_hash": "sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    "enforcement_mode": "enforce"
  },
  "data_class": "internal",
  "build_provenance": {
    "slsa_level": 1,
    "digest": "sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
  },
  "appraisal": {
    "status": "none",
    "verifier": "https://verifier.example.org"
  },
  "transparency": "https://registry.agentrust-io.com/claim/placeholder",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  },
  "signature": "eyJhbGciOiJFZERTQSJ9..."
}
```

**Modules tested:** TR-ENV, TR-SIG, TR-POL, TR-APR

**What causes a Level 0 failure:**

- `eat_profile` missing or wrong value: TR-ENV-001
- `runtime.platform` is a TEE value (e.g. `amd-sev-snp`) but Level 0 is requested: TR-RTE-001 does not apply, but TR-ENV still checks the envelope
- `policy.enforcement_mode` is `"strict"` or `"monitor"`: TR-POL-002
- `cnf.jwk` missing, of an unsupported key type, or carrying private key material (`d`): TR-SIG-004
- Signature does not verify against `cnf.jwk`: TR-SIG-005
- `policy.policy_uri` is not an absolute URI, or the bundle it resolves to does not have the digest `policy.bundle_hash` declares: TR-POL-003. The malformed case is reported with or without a resolver: a reference the record got wrong needs no network to detect
- `appraisal` is absent or not an object, or `appraisal.status` is not one of the four values the schema enumerates: TR-APR-001
- `appraisal.verifier` is absent or is not an absolute URI: TR-APR-002
- `appraisal.policy_ref` or `appraisal.timestamp` is present and malformed: TR-APR-003, TR-APR-004. Absent, either one is skipped rather than passed

______________________________________________________________________

## Level 1: TEE Attestation

Level 1 adds hardware attestation: the record names the TEE (trusted execution environment, a processor mode that keeps a program's memory sealed off) it ran in and the measurement (a fingerprint of the code loaded into it). The suite checks that these fields are well formed; it does not verify the hardware's signed report, which is a separate step (see [Known limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md)).

`runtime.platform` must be a value from the `runtime.platform` enum in `schemas/trace-claim.json` other than `software-only`, which carries no hardware attestation evidence. The measurement must be non-zero. `appraisal.status` must be `"affirming"` (TR-APR-005).

**Minimum conformant Level 1 record** (changes from Level 0 in bold context):

```
{
  "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
  "iat": 1750000000,
  "subject": "spiffe://trust.example.org/agent/my-agent",
  "model": {
    "provider": "example-provider",
    "model_id": "example-model-1",
    "version": "20251001"
  },
  "runtime": {
    "platform": "amd-sev-snp",
    "measurement": "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
  },
  "policy": {
    "bundle_hash": "sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    "enforcement_mode": "enforce"
  },
  "data_class": "confidential",
  "build_provenance": {
    "slsa_level": 2,
    "digest": "sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
  },
  "appraisal": {
    "status": "affirming",
    "verifier": "https://verifier.agentrust-io.com"
  },
  "transparency": "https://registry.agentrust-io.com/claim/placeholder",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  },
  "signature": "eyJhbGciOiJFZERTQSJ9..."
}
```

**Modules tested:** TR-ENV, TR-SIG, TR-POL, TR-APR, TR-RTE, TR-SCA

**What causes a Level 1 failure over Level 0:**

- `runtime.platform` is `"software-only"`: TR-RTE-001
- `runtime.measurement` is all zeros: TR-RTE-002 (all-zero is invalid at Level 1)
- `build_provenance` missing entirely: TR-SCA-001, TR-SCA-002
- `appraisal.status` is `"none"`: while not a hard schema violation, a conformant Level 1 record should carry `"affirming"`; TR-APR-005 reports this from Level 1 and skips it at Level 0

______________________________________________________________________

## Level 2: Transparency Anchoring

Level 2 adds two things: a fingerprint of the log of tool calls the agent made, and proof that the record was entered in a public, append-only transparency log, so it cannot be quietly swapped later. SCITT is the standard format for such logs.

The `transparency` field must be an HTTPS URI with a host, pointing to a SCITT receipt. The suite checks that it parses and that the scheme and host are present; it does not resolve the URI, and it does not recognise a placeholder value.

**Minimum conformant Level 2 record** (additional fields over Level 1):

```
{
  "tool_transcript": {
    "hash": "sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    "call_count": 4
  },
  "transparency": "https://registry.agentrust-io.com/claim/01J3XKWP4NQZ8R5HT6YD7VMBCE"
}
```

**Modules tested:** TR-ENV, TR-SIG, TR-POL, TR-APR, TR-RTE, TR-SCA, TR-TXN, TR-ANC

**What causes a Level 2 failure over Level 1:**

- `tool_transcript.hash` missing or not a valid `sha256:` digest: TR-TXN-001
- `tool_transcript.call_count` negative or not an integer: TR-TXN-002
- `transparency` is absent or empty, is not a string, or is not an `https://` URI with a host: TR-ANC-001
- no anchor receipt was supplied, the receipt is malformed, or its inclusion proof does not reproduce the committed `merkle_root`: TR-ANC-002. A record cannot reach Level 2 on a URI alone: pass the receipt with `--receipt`
- `policy.policy_uri` is present, a resolver was supplied with `--policy-dir`, and the bundle could not be read: TR-POL-003. Unverified rather than failed, and unverified fails the run from Level 2

______________________________________________________________________

## Unverified findings

Besides pass, fail and skip, a check can come back unverified: the suite could not reach the evidence it needed to decide. The table says from which level that counts as a failure.

An unverified finding means **the check could not be executed against the evidence the record cites**. It is held apart from a skip so that a consumer can never read it as a benign omission, and it is not a pass.

Whether it fails the run is per code rather than one rule over all of them. Different checks lose their evidence for different reasons, and the level at which that stops being tolerable is a property of the check.

| Code       | UNVERIFIED fails the run from level |
| ---------- | ----------------------------------- |
| TR-SIG-005 | 1                                   |
| TR-POL-003 | 2                                   |

A code absent from this table fails from Level 1.

Technical detail: where the table lives

That default is deliberate: a new code nobody registered still fails closed, and the registration guard turns red rather than the run turning quietly permissive. The table is `UNVERIFIED_FAILS_FROM_LEVEL` in `src/trace_tests/modules/unverified.py`, and `tests/test_docs_match_the_modules.py` fails if the two disagree.

______________________________________________________________________

## Choosing a level

- Use **Level 0** during development. Records can use `runtime.platform: "software-only"` and `build_provenance.slsa_level: 0`.
- Use **Level 1** for production deployments in a TEE (AMD SEV-SNP, Intel TDX, NVIDIA H100).
- Use **Level 2** when you need an auditable, tamper-evident log with a SCITT transparency service.

The certification program (launching 2027) will require Level 1 at minimum.

## Related

- [Error Codes](https://trace.agentrust-io.com/conformance/docs/error-codes/index.md): every TR-\* error with description and fix
- [Test Modules](https://trace.agentrust-io.com/conformance/docs/modules/index.md): per-module test lists with positive and negative cases
- [TRACE Trust Levels](https://trace.agentrust-io.com/docs/trust-levels/): full specification of what each level proves

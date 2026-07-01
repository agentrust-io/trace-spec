---
description: Install agentrust-trace and sign, anchor, and verify your first TRACE Trust Record in about five minutes.
---

# Quickstart

Get your first TRACE Trust Record in five minutes.

## Install

```bash
pip install agentrust-trace
```

## Generate a signing key

```python
from agentrust_trace import generate_key
from cryptography.hazmat.primitives import serialization

key = generate_key()

# Save private key — keep secure, never commit or log
pem_private = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
with open("trace-key.pem", "wb") as f:
    f.write(pem_private)

# Save public key — safe to distribute to verifiers
pem_public = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
with open("trace-key.pem.pub", "wb") as f:
    f.write(pem_public)
```

In production, pass the PEM to `TRACE_PRIVATE_KEY_PEM` as an environment variable instead of writing it to disk. `load_signing_key()` reads this variable automatically.

## Emit a Trust Record (standalone)

Use `sign_record()` to produce a Level 0 record without AGT or any other framework:

```python
import time, json
from agentrust_trace import generate_key, sign_record

key = generate_key()

record = {
    "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
    "iat": int(time.time()),
    "subject": "spiffe://trust.example.org/agent/my-agent",
    "model": {
        "provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
        "version": "20251001",
    },
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "0" * 64,
    },
    "policy": {
        "bundle_hash": "sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
                       "f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "enforcement_mode": "enforce",
    },
    "data_class": "internal",
    "build_provenance": {
        "slsa_level": 1,
        "digest": "sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
                  "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    },
    "appraisal": {
        "status": "none",
        "verifier": "https://verifier.example.org",
    },
    "transparency": "https://registry.agentrust.io/claim/placeholder",
}

signed = sign_record(record, key)

with open("session.trace.json", "w") as f:
    json.dump(signed, f, indent=2)
```

This produces a valid Level 0 record. For hardware-attested (Level 1+) records, use cMCP as the runtime — it handles TEE key generation and measurement automatically.

## Emit with a persistent key

In production, load the signing key from `TRACE_PRIVATE_KEY_PEM` so the same key is used across process restarts. `load_signing_key()` reads that variable and falls back to an ephemeral key with a warning if the variable is not set:

```python
import os, time, json
from agentrust_trace import load_signing_key, sign_record

# Export TRACE_PRIVATE_KEY_PEM before running, or set it in your deployment secrets.
# If unset, an ephemeral key is generated and a warning is emitted; records signed
# with an ephemeral key cannot be re-verified after the process exits.
key = load_signing_key()

record = {
    "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
    "iat": int(time.time()),
    "subject": "spiffe://trust.example.org/agent/my-agent",
    "model": {
        "provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
        "version": "20251001",
    },
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "0" * 64,
    },
    "policy": {
        "bundle_hash": "sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
                       "f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "enforcement_mode": "enforce",
    },
    "data_class": "internal",
    "build_provenance": {
        "slsa_level": 1,
        "digest": "sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
                  "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    },
    "appraisal": {
        "status": "none",
        "verifier": "https://verifier.example.org",
    },
    "transparency": "https://registry.agentrust.io/claim/placeholder",
}

signed = sign_record(record, key)

with open("session.trace.json", "w") as f:
    json.dump(signed, f, indent=2)
```

## Verify offline

```python
import json
from agentrust_trace import verify_record, validate_json
from cryptography.exceptions import InvalidSignature

with open("session.trace.json") as f:
    signed_record = json.load(f)

# Schema check
validate_json(signed_record)  # raises jsonschema.ValidationError if malformed

# Signature check — verify against a pinned trusted key in production.
# allow_embedded_key=True trusts the cnf.jwk in the record itself, which
# only proves internal consistency, not that the record came from a trusted issuer.
try:
    verify_record(signed_record, allow_embedded_key=True)
    print("Signature valid (Ed25519)")
    print(f"  subject:     {signed_record['subject']}")
    print(f"  policy:      {signed_record['policy']['bundle_hash'][:24]}... "
          f"({signed_record['policy']['enforcement_mode']})")
    print(f"  data_class:  {signed_record['data_class']}")
    print(f"  appraisal:   {signed_record['appraisal']['status']}")
except InvalidSignature:
    print("Signature invalid")
```

Output:

```
Signature valid (Ed25519)
  subject:     spiffe://trust.example.org/agent/my-agent
  policy:      sha256:b2c3d4e5f6a7b8c9... (enforce)
  data_class:  internal
  appraisal:   none
```

`verify_record()` raises `cryptography.exceptions.InvalidSignature` if the record was tampered with after signing. `appraisal.status` is `none` here because no external verifier was contacted — see [Verification Protocol](verification.md) for the full five-step flow.

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

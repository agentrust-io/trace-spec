# Verification Protocol

TRACE Trust Records are independently verifiable offline — no call to the issuer, no API, no trust-me-the-log-is-real.

## Five-step verification

This is the normative protocol from [§3.3 of the spec](https://trace.agentrust-io.com/spec/trace-v0.1/index.md).

### Step 1 — Parse the envelope

A TRACE Trust Record is a signed JSON object. The `signature` field contains a base64url-encoded Ed25519 (or ES256/ES384) signature over the canonical JSON of the record with `signature` and `cnf` removed.

```
import json, base64
import rfc8785  # RFC 8785 (JCS) canonicalization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

record = json.load(open("session.trace.json"))
sig_bytes = base64.urlsafe_b64decode(record["signature"] + "==")
payload = {k: v for k, v in record.items() if k != "signature"}
payload_bytes = rfc8785.dumps(payload)  # JCS canonical bytes, NOT json.dumps
```

The pre-image is the RFC 8785 (JCS) canonical form of the record with `signature` removed. `json.dumps(sort_keys=True)` is **not** JCS-conformant — it diverges for non-ASCII strings and IEEE 754 numbers — so use a JCS library (the spec mandates this in §3.2.2).

### Step 2 — Resolve the public key

The `cnf.jwk` field embeds the public key. For TEE-issued records, this key is TEE-bound — its private half never leaves the measured enclave.

```
from cryptography.hazmat.primitives.serialization import load_der_public_key

jwk = record["cnf"]["jwk"]
# For ES256/ES384: reconstruct EC key from x/y
# For Ed25519: decode x directly
pub_key = Ed25519PublicKey.from_public_bytes(
    base64.urlsafe_b64decode(jwk["x"] + "==")
)
```

### Step 3 — Verify the signature

```
pub_key.verify(sig_bytes, payload_bytes)
# Raises InvalidSignature if tampered — silent if valid
print("✓ Signature valid")
```

### Step 4 — Check the EAT profile

```
assert record["eat_profile"] == "tag:agentrust.io,2026:trace-v0.1", "Unknown profile"
print("✓ eat_profile correct")
```

### Step 5 — Appraise the claims

Interpret `appraisal.status` against your policy:

| Status            | Meaning                                        |
| ----------------- | ---------------------------------------------- |
| `affirming`       | All evidence passed verifier appraisal         |
| `warning`         | Evidence passed but with conditions            |
| `contraindicated` | Evidence failed — treat as untrusted           |
| `none`            | No appraisal performed (software-only Level 0) |

```
status = record["appraisal"]["status"]
assert status == "affirming", f"Appraisal failed: {status}"
print(f"✓ Appraisal: {status}")
```

## Verifying hardware-rooted records

For Level 2 records (TEE-issued), additionally verify that the `cnf.jwk` key is bound to the hardware measurement in `runtime`:

1. Fetch the Reference Integrity Manifest at `runtime.rim_uri`
1. Compare `runtime.measurement` against the RIM
1. Verify that `cnf.jwk` was endorsed by the TEE at that measurement

This chain proves the key that signed the TRACE record was generated *inside* the attested enclave — not by an operator process.

## CLI verification

```
# Install
pip install agentrust-trace

# Verify a record
agentrust-trace verify session.trace.json --pubkey issuer.pub

# Verify with hardware check (fetches RIM from AMD/Intel/NVIDIA)
agentrust-trace verify session.trace.json --pubkey issuer.pub --check-hardware

# Batch verify
agentrust-trace verify *.trace.json --pubkey issuer.pub --summary
```

## SCITT-anchored records

If `transparency` is set, the record is anchored in an append-only transparency log. Verify the anchor:

```
agentrust-trace verify-scitt session.trace.json \
  --transparency-log https://registry.agentrust.io
```

A valid SCITT receipt proves the record was included in the log and cannot be retroactively removed or modified.

## What verification proves

| Claim verified           | What it means                                                   |
| ------------------------ | --------------------------------------------------------------- |
| Signature valid          | The record was not tampered with after issuance                 |
| `cnf.jwk` hardware-bound | The signing key was generated inside a measured TEE             |
| `policy.bundle_hash`     | This exact Cedar policy was in force — not an approximate       |
| `tool_transcript.hash`   | The audit log is intact and matches the record                  |
| SCITT receipt valid      | The record is in an append-only log — cannot be quietly deleted |

## What verification does NOT prove

Verification proves *what happened during the recorded session* under the stated policy, in the stated environment. It does not:

- Prove the agent's internal reasoning was sound
- Prove the policy was correctly authored for the intent
- Prove tool call *contents* (only the hash of the transcript is in v0.1)
- Replace ongoing monitoring

See [Limitations](https://trace.agentrust-io.com/LIMITATIONS/index.md) for the full list.

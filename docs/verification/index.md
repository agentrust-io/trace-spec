# Verification Protocol

TRACE Trust Records are independently verifiable offline — no call to the issuer, no API, no trust-me-the-log-is-real. The one thing offline verification cannot establish is that the signing key is *still* trusted; see [Checking revocation status](#checking-revocation-status).

## Five-step verification

This is the normative protocol from [§3.3 of the spec](https://trace.agentrust-io.com/spec/trace-v0.2/index.md).

### Step 1 — Parse the envelope

A TRACE Trust Record is a signed JSON object. The `signature` field contains a base64url-encoded Ed25519 (or ES256/ES384) signature over the canonical JSON of the record with only `signature` removed. The `cnf.jwk` public key remains in the signed pre-image, binding that key to the rest of the record.

```
import json, base64
import rfc8785  # RFC 8785 (JCS) canonicalization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

record = json.load(open("session.trace.json"))
sig_bytes = base64.urlsafe_b64decode(record["signature"] + "==")
payload = {k: v for k, v in record.items() if k != "signature"}
payload_bytes = rfc8785.dumps(payload)  # JCS canonical bytes, NOT json.dumps
```

The pre-image is the RFC 8785 (JCS) canonical form of the record with only `signature` removed. All other top-level fields, including `cnf`, are included. `json.dumps(sort_keys=True)` is **not** JCS-conformant — it diverges for non-ASCII strings and IEEE 754 numbers — so use a JCS library (the spec mandates this in §3.2.2).

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
assert record["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2", "Unknown profile"
print("✓ eat_profile correct")
```

If you verify with `agentrust_trace.verify_record`, this step is enforced for you, before any cryptographic work: a record whose `eat_profile` is missing, superseded (the v0.1 identifier), or anything other than `TRACE_PROFILE_V0_2` raises `ValueError`. The manual assert above is what a from-scratch verifier must do itself — spec section 2 requires a v0.2 verifier to reject everything but the v0.2 identifier, and a valid signature over semantics your build does not implement is not evidence.

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

## Checking revocation status

The five steps above are self-contained: given the record and a trusted key, they run with no network. That is the property TRACE is built for, and it has exactly one gap. A signature is valid forever, so a record signed by a key that was later compromised and revoked still passes every offline step. Nothing inside the record can withdraw the key that signed it.

[§3.2.1 of the spec](https://trace.agentrust-io.com/spec/trace-v0.2/index.md) therefore requires the online half: *"Verifiers MUST consult current revocation status at verification time."*

`verify_record()` takes a `revocation` store to do this. Pass a container of revoked identifiers, or a callable that performs a live lookup:

```
from agentrust_trace import jwk_thumbprint, verify_record

# A revocation list the caller already holds.
verify_record(record, trusted_jwk, revocation={"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"})

# Or a live CRL / status endpoint / SCITT lookup.
def is_revoked(key_id: str) -> bool:
    return httpx.get(f"https://crl.example.org/keys/{key_id}").json()["revoked"]

verify_record(record, trusted_jwk, revocation=is_revoked)
```

Keys are identified by their RFC 7638 JWK Thumbprint (`jwk_thumbprint(jwk)`) or by `kid`; a match on either rejects the record. The check reads the **trusted** key, not `record["cnf"]["jwk"]`: the embedded key is attacker-controlled until the signature verifies, so keying the lookup on it would let a revoked issuer present an unlisted thumbprint.

Both failure modes raise `ValueError`, including a store that cannot answer:

| Outcome                               | Result                                                                             |
| ------------------------------------- | ---------------------------------------------------------------------------------- |
| Key listed as revoked                 | Rejected                                                                           |
| Store raises (endpoint down, timeout) | Rejected; an unavailable source is not evidence a key is unrevoked                 |
| Key absent from the store             | Verification continues                                                             |
| No `revocation` passed                | Check skipped; verification is offline and proves nothing about current key status |

The last row is the honest default. Omitting the store is a legitimate mode, since air-gapped audit of archived records has no other option, but the result means "this record was validly signed by this key", not "this key is still trusted".

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

## Action receipts and embodied workflows

Some deployments attach per-action receipts below the session layer. For example, an embodied-agent controller can sign a receipt that says a specific call was accepted, rejected, aborted, or handed off to another authority. These receipts extend the audit chain; they do not replace Trust Record verification.

Keep the verification results separate:

| Evidence layer           | What to verify                                                                                       | What not to infer                                                                 |
| ------------------------ | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Session evidence         | TRACE signature, freshness, policy hash, runtime measurement, transcript hash                        | Complete physical-world state                                                     |
| Action issuance evidence | Canonical action digest, receipt signature, trusted issuer key, session or call binding, chain order | Successful physical completion                                                    |
| Outcome evidence         | Controller or monitor decision carried by the receipt payload                                        | Functional-safety certification unless the issuer and profile explicitly claim it |

For action receipts, a verifier should distinguish five common outcomes:

| Outcome                    | Meaning                                                                                                                                                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `receipt_valid_accepted`   | The receipt is well-formed, trusted, bound to the call, and reports acceptance.                                                                                                                                                                              |
| `receipt_valid_rejected`   | The receipt is well-formed, trusted, bound to the call, and reports controller or policy rejection. This is valid negative evidence.                                                                                                                         |
| `receipt_missing_required` | The profile required a receipt, but none was present for the consequential action.                                                                                                                                                                           |
| `receipt_invalid`          | The receipt is present but fails signature, digest, freshness, ordering, or call-binding checks against a key the verifier holds.                                                                                                                            |
| `receipt_unverified`       | The receipt names an issuer key the verifier has not pinned, and nothing else failed. Per section 3.3.1 of the spec this is unverified, not invalid: the receipt confers no trust and proves no wrongdoing, surfaced with an advisory rather than a failure. |

The key boundary is that a valid rejection is not malformed evidence. It is evidence that the downstream authority declined the action. A valid acceptance also remains action-level evidence; it does not prove the requested physical or business outcome completed unless a stricter profile defines and trusts that external outcome claim.

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

- Prove the signing key is still trusted; offline verification cannot prove non-revocation, so pass a `revocation` store
- Prove the agent's internal reasoning was sound
- Prove the policy was correctly authored for the intent
- Prove tool call *contents* (only the hash of the transcript is in v0.1)
- Prove physical completion or functional-safety compliance for externally consequential actions
- Replace ongoing monitoring

See [Limitations](https://trace.agentrust-io.com/LIMITATIONS/index.md) for the full list.

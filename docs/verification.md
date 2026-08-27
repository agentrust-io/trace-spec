# Verification Protocol

TRACE Trust Records are independently verifiable offline: no call to the issuer, no API, no trust-me-the-log-is-real. The one thing offline verification cannot establish is that the signing key is *still* trusted; see [Checking revocation status](#checking-revocation-status).

## Five-step verification

This is the normative protocol from [§3.3 of the spec](../spec/trace-v0.2.md).

Before interpreting any claim, validate the complete object against the canonical
v0.2 JSON Schema. A valid signature authenticates every byte but does not make an
unknown field, missing required claim, or invalid enum meaningful. The Python
`verify_record()` API performs this schema check automatically and fails closed.

### Step 1: Parse the envelope

A TRACE Trust Record is a signed JSON object. The `signature` field contains a base64url-encoded Ed25519 (or ES256/ES384) signature over the canonical JSON of the record with only `signature` removed. The `cnf.jwk` public key remains in the signed pre-image, binding that key to the rest of the record.

```python
import json, base64
import rfc8785  # RFC 8785 (JCS) canonicalization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

record = json.load(open("session.trace.json"))
sig_bytes = base64.urlsafe_b64decode(record["signature"] + "==")
payload = {k: v for k, v in record.items() if k != "signature"}
payload_bytes = rfc8785.dumps(payload)  # JCS canonical bytes, NOT json.dumps
```

The pre-image is the RFC 8785 (JCS) canonical form of the record with only `signature` removed. All other top-level fields, including `cnf`, are included. `json.dumps(sort_keys=True)` is **not** JCS-conformant, it diverges for non-ASCII strings and IEEE 754 numbers, so use a JCS library (the spec mandates this in §3.2.2).

### Step 2: Resolve the public key

The `cnf.jwk` field embeds the public key. For TEE-issued records, this key is TEE-bound: its private half never leaves the measured enclave.

Resolve trust out of band and require the trusted key and `cnf.jwk` to have the
same RFC 7638 thumbprint before verification. Checking the signature with a
trusted key while allowing the signed record to name a different confirmation
key breaks the binding required by §3.2.2 and can mislead downstream
proof-of-possession checks.

```python
from cryptography.hazmat.primitives.serialization import load_der_public_key

jwk = record["cnf"]["jwk"]
# For ES256/ES384: reconstruct EC key from x/y
# For Ed25519: decode x directly
pub_key = Ed25519PublicKey.from_public_bytes(
    base64.urlsafe_b64decode(jwk["x"] + "==")
)
```

### Step 3: Verify the signature

```python
pub_key.verify(sig_bytes, payload_bytes)
# Raises InvalidSignature if tampered: silent if valid
print("✓ Signature valid")
```

### Step 4: Check the EAT profile

```python
assert record["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2", "Unknown profile"
print("✓ eat_profile correct")
```

If you verify with `agentrust_trace.verify_record`, this step is enforced for you,
before any cryptographic work: a record whose `eat_profile` is missing, superseded
(the v0.1 identifier), or anything other than `TRACE_PROFILE_V0_2` raises
`ValueError`. The manual assert above is what a from-scratch verifier must do
itself: spec section 2 requires a v0.2 verifier to reject everything but the v0.2
identifier, and a valid signature over semantics your build does not implement is
not evidence.

### Step 5: Appraise the claims

Interpret `appraisal.status` against your policy:

| Status | Meaning |
|---|---|
| `affirming` | All evidence passed verifier appraisal |
| `warning` | Evidence passed but with conditions |
| `contraindicated` | Evidence failed: treat as untrusted |
| `none` | No appraisal performed (software-only Level 0) |

```python
status = record["appraisal"]["status"]
assert status == "affirming", f"Appraisal failed: {status}"
print(f"✓ Appraisal: {status}")
```

## Checking revocation status

The five steps above are self-contained: given the record and a trusted key, they run with no network. That is the property TRACE is built for, and it has exactly one gap. A signature is valid forever, so a record signed by a key that was later compromised and revoked still passes every offline step. Nothing inside the record can withdraw the key that signed it.

[§3.2.3 of the spec](../spec/trace-v0.2.md) closes that gap without giving up offline verification. Two things are worth knowing before reading the code below.

**The boundary is a log entry ID, not a time.** The intuitive rule is to reject a record from a revoked key when its `iat` falls after the compromise. A compromised record-signing key also signs `iat`, so whoever holds it backdates the record and the rule passes. §3.2.3 anchors to the SCITT inclusion entry ID instead, because entry IDs are monotonic and bound to the Merkle structure, so ordering survives the compromise of the signing key in a way a timestamp does not. In §3.2.3's words, a record from a revoked key is valid *"if and only if its SCITT inclusion entry ID is less than or equal to `last_valid_entry_id`"*, on the log named in the statement.

**Offline is a state you report, not a check you skip.** Revocation statements are anchored in the same transparency log as the records they govern, and verifiers cache a signed bundle carrying `valid_until`. A verifier offline says what it checked against, "verified against revocation bundle valid at T", rather than reporting an affirming appraisal it did not earn. §3.2.3 states that an expired bundle *"MUST report the record as unverified for revocation rather than as verified"*, and that a verifier with no bundle *"MUST report that it performed no revocation check"*.

A record with no usable inclusion entry ID has no anchor to place it before or after the compromise, so §3.2.3 falls back to binary revocation for it: *"a verifier MUST reject every record signed by the revoked key"*. That fallback is what the current `verify_record()` store implements, and it is the correct behaviour for deployments carrying no receipts.

`verify_record()` takes a `revocation` store to do this. Pass a container of revoked identifiers, or a callable that performs a live lookup:

```python
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

| Outcome | Result |
|---|---|
| Key listed as revoked | Rejected |
| Store raises (endpoint down, timeout) | Rejected; an unavailable source is not evidence a key is unrevoked |
| Key absent from the store | Verification continues |
| No `revocation` passed | Check skipped; verification is offline and proves nothing about current key status |

The last row is the honest default. Omitting the store is a legitimate mode, since air-gapped audit of archived records has no other option, but the result means "this record was validly signed by this key", not "this key is still trusted".

What the store does not yet do is entry-ID-scoped revocation. It answers "is this key revoked", which is the §3.2.3 fallback, so a key revoked after a long run of legitimate records currently invalidates all of them rather than the ones logged after `last_valid_entry_id`. Carrying the entry ID through `verify_record()` is implementation work tracked in the issue that produced §3.2.3, and the schemas the bundle format needs are published at [`schema/trace-revocation.json`](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-revocation.json) and [`schema/trace-revocation-bundle.json`](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-revocation-bundle.json).

## Verifying hardware-rooted records

For Level 2 records (TEE-issued), additionally verify that the `cnf.jwk` key is bound to the hardware measurement in `runtime`:

1. Fetch the Reference Integrity Manifest at `runtime.rim_uri`
2. Compare `runtime.measurement` against the RIM
3. Verify that `cnf.jwk` was endorsed by the TEE at that measurement

This chain proves the key that signed the TRACE record was generated *inside* the attested enclave, not by an operator process.

## Verifying build provenance depth

The normative rules are defined by [§3.3.1 of the specification](../spec/trace-v0.2.md).
`build_provenance.provenance_depth` declares how far down the supply chain the issuer claims to
have walked. A verifier records what it actually checked in
`appraisal.provenance_depth_verified`, which is a statement about the verifier, not about the
record.

| Claimed depth | Verifier checks | May downgrade to, evidence does not resolve | Fails, evidence resolves and contradicts |
|---|---|---|---|
| `surface` (or absent) | Confirm `digest` matches the workload artifact and `builder` resolves to the configured trusted-builder set. | Already the floor. | `digest` does not match the artifact the verifier independently holds, or `builder` is outside the trusted-builder set. |
| `builder` | All of surface, plus fetch `provenance_uri`, verify the SLSA attestation signature, check the attestation `subject` matches `digest`, and check the attestation `builder.id` matches `builder`. | `surface`, when `provenance_uri` is absent or unreachable, or its signature does not resolve. | The attestation resolves and its `subject` does not match `digest`, or its `builder.id` does not match `builder`. |
| `transitive` | All of builder, plus enumerate the SLSA `materials` / `resolvedDependencies` and confirm every entry has a verifiable publisher attestation (npm OIDC, PyPI Trusted Publisher, Sigstore Rekor entry, or platform equivalent). | `builder`, when an input carries no publisher attestation or the attestation declares no inputs at all; or `surface` per the row above. | An input's publisher attestation resolves and was signed under an issuer outside the configured trusted set. |

The two right-hand columns are disjoint, and which one applies turns on whether the evidence
resolved, not on how serious the finding is.

**Evidence that does not resolve** leaves a check unrun. The verifier may stop at the depth
below, then records that lower depth in `appraisal.provenance_depth_verified`, and does not
report the missing evidence as a failure of the record. A record is not defective because
someone else's transparency log is unreachable, and a verifier that rejects on this is failing
records for the weather.

**Evidence that resolves and contradicts the record** fails the appraisal. A verifier does not
downgrade to escape it. Downgrading there would record a narrower claim that is true while
suppressing a wider one that is false: the record would pass as `builder` on evidence that
positively refutes it at `transitive`, and the appraisal would say nothing about why.

A verifier does not record `provenance_depth_verified` at a depth higher than it executed.
Downgrading is how a verifier stays honest when evidence does not resolve; claiming depth it did
not run is what the field exists to prevent. This last rule cannot be expressed in JSON Schema:
the record is byte-identical whether the verifier walked the chain or merely says it did. The
conformance vectors in
[`examples/build-provenance-depth/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/build-provenance-depth)
hold it instead, against a verifier's own output, and encode the split above vector by vector.

Records that omit `provenance_depth` are treated as `surface`. This keeps every record issued
before this field existed valid and correctly interpreted.

### Profile floors

Deployment profiles select the minimum acceptable verified depth:

| Profile | Floor |
|---|---|
| Default, SLSA L0 to L1 | `surface` |
| SLSA L2 and above | `builder` |
| FIPS-aligned, EU AI Act Annex IV high-risk, HIPAA | `transitive` |
| cMCP reference profile | `builder`, with `transitive` recommended where ecosystem coverage permits |

A verifier whose configured floor is not met by `provenance_depth_verified` sets
`appraisal.status` to `contraindicated`.

### Why depth is recorded rather than assumed

A SLSA attestation produced by a trusted builder is signature-valid even when a maintainer's CI
token has been stolen and used to publish a poisoned build input. Surface verification accepts
that record. Transitive verification rejects it, because the poisoned input's publisher
attestation does not chain back to the legitimate maintainer. Without a recorded depth, two
conformant verifiers reach opposite conclusions on the same record and neither says why, which
is the federation gap [section 1](../spec/trace-v0.2.md) names.

That case is a failure and not a downgrade, and it is the sharpest reason the two are kept
apart. The poisoned input's attestation resolved: the verifier holds it and can see the issuer
is outside the trusted set. A verifier permitted to call that "transitive coverage unavailable"
would record `builder`, accept, and report exactly what a verifier that never looked reports:
which would make the depth field cover for the attack it was added to expose.

### `transitive` is a floor on effort, not a comparable claim

Until evidence resolution is standardized, two verifiers can both honestly record `transitive`
over different material sets. Nothing above specifies which inputs must be enumerated or where a
publisher attestation must be looked up, so the value states how far a verifier walked, not what
ground it covered. `builder` has no such gap, because `provenance_uri` names its own evidence.
A consumer comparing `transitive` across verifiers is therefore comparing effort; it does not
license the inference that the same dependencies were checked. Specifying a transitive coverage
URI is left to a follow-up.

[Build provenance depth](build-provenance-depth.md) is the informative companion to this section:
it states what each depth does not assure.

## CLI verification

```bash
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

```bash
agentrust-trace verify-scitt session.trace.json \
  --transparency-log https://registry.agentrust-io.com
```

A valid SCITT receipt proves the record was included in the log and cannot be retroactively removed or modified.

## Action receipts and embodied workflows

Some deployments attach per-action receipts below the session layer. For
example, an embodied-agent controller can sign a receipt that says a specific
call was accepted, rejected, aborted, or handed off to another authority. These
receipts extend the audit chain; they do not replace Trust Record verification.

Keep the verification results separate:

| Evidence layer | What to verify | What not to infer |
|---|---|---|
| Session evidence | TRACE signature, freshness, policy hash, runtime measurement, transcript hash | Complete physical-world state |
| Action issuance evidence | Canonical action digest, receipt signature, trusted issuer key, session or call binding, chain order | Successful physical completion |
| Outcome evidence | Controller or monitor decision carried by the receipt payload | Functional-safety certification unless the issuer and profile explicitly claim it |

For action receipts, a verifier should distinguish five common outcomes:

| Outcome | Meaning |
|---|---|
| `receipt_valid_accepted` | The receipt is well-formed, trusted, bound to the call, and reports acceptance. |
| `receipt_valid_rejected` | The receipt is well-formed, trusted, bound to the call, and reports controller or policy rejection. This is valid negative evidence. |
| `receipt_missing_required` | The profile required a receipt, but none was present for the consequential action. |
| `receipt_invalid` | The receipt is present but fails signature, digest, freshness, ordering, or call-binding checks against a key the verifier holds. |
| `receipt_unverified` | The receipt names an issuer key the verifier has not pinned, and nothing else failed. Per section 3.3.1 of the spec this is unverified, not invalid: the receipt confers no trust and proves no wrongdoing, surfaced with an advisory rather than a failure. |

The key boundary is that a valid rejection is not malformed evidence. It is
evidence that the downstream authority declined the action. A valid acceptance
also remains action-level evidence; it does not prove the requested physical or
business outcome completed unless a stricter profile defines and trusts that
external outcome claim.

## What verification proves

| Claim verified | What it means |
|---|---|
| Signature valid | The record was not tampered with after issuance |
| `cnf.jwk` hardware-bound | The signing key was generated inside a measured TEE |
| `policy.bundle_hash` | This exact Cedar policy was in force, not an approximate |
| `tool_transcript.hash` | The audit log is intact and matches the record |
| SCITT receipt valid | The record is in an append-only log: cannot be quietly deleted |

## What verification does NOT prove

Verification proves *what happened during the recorded session* under the stated policy, in the stated environment. It does not:

- Prove the signing key is still trusted; offline verification cannot prove non-revocation, so pass a `revocation` store
- Prove the agent's internal reasoning was sound
- Prove the policy was correctly authored for the intent
- Prove tool call *contents* (only the hash of the transcript is in v0.1)
- Prove how the artifact was built past the depth recorded in `appraisal.provenance_depth_verified`; [Build provenance depth](build-provenance-depth.md) states what each stopping point leaves unknown
- Prove physical completion or functional-safety compliance for externally consequential actions
- Replace ongoing monitoring

See [Limitations](../LIMITATIONS.md) for the full list.

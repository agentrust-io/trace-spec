# Anchoring a Trust Record to the TRACE registry

After signing a Trust Record, you can anchor it to the TRACE transparency registry. The anchor proves the record existed at a specific time and has not been altered since, which is tamper evidence that holds even if the operator who produced the record is later compromised.

**What you need:** A signed Trust Record (from [Signing your first trust record](signing-your-first-trust-record.md)).

**What you'll do:** Submit the record, get back an inclusion proof, and check that proof yourself against the published registry entry.

!!! warning "This tutorial was rewritten on 2026-08-08"
    It previously described POSTing records to a SCITT HTTP API at a registry endpoint. That endpoint does not exist, and the hostname it named was on a domain this project has never controlled, the same defect that forced the [v0.2 profile URI cutover](../../spec/trace-v0.2.md). Anchoring works as described below. If you built against the old page, nothing you sent was received by us.

---

## Why transparency anchoring matters

A Trust Record carries a signature from the issuer's key. A verifier holding that key can confirm the record has not been modified, but only if the key is trustworthy. If the issuer is later compromised, an attacker holding the key could forge records backdated to before the compromise.

Anchoring solves this with a different trust root: an append-only log whose history a third party can inspect. Once a record is anchored, its exact bytes are fixed in the log at that timestamp. A verifier recomputes the Merkle root from the record and its proof and compares it to the published entry. No trust in the operator is required, and no call back to the issuer is needed.

The normative format is [TRACE Registry Anchor Format v1](../../spec/registry-anchor-v1.md). Read §0 of it before you implement anything: TRACE uses **RFC 8785 (JCS)** to canonicalize a record for *signing* and **sorted-key JSON** to canonicalize it for the *anchor leaf*. Assuming JCS at the leaf produces proofs that never verify, and the failure has no useful diagnostic.

---

## The `transparency` field

In the `TrustRecord` schema, `transparency` is optional below Level 2:

```python
transparency: str | None
```

`None` means the record is unanchored, which is the honest state for a Level 0 or Level 1 record. An empty string is rejected: `""` is not a URI, and a field that looks populated but resolves to nothing is worse in a trust record than an absent one.

Where present, it identifies the registry entry anchoring the record. At Level 2 and above, a verifier must be able to retrieve that entry and check inclusion without contacting you.

---

## Step 1: Sign the record

Sign as normal. You do not need a placeholder for `transparency`; leave it unset until you have an anchor.

```python
import time
from agentrust_trace.sign import generate_key, sign_record

key = generate_key()

record = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": int(time.time()),
    "subject": "spiffe://example.org/agent/my-agent",
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "internal",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "none", "verifier": "self"},
}

signed = sign_record(record, key)
```

!!! note "The anchored unit is the signed object"
    Anchoring binds the complete signed claim, signature included. Change either the body or the signature after anchoring and the proof stops verifying, which is the property you want.

---

## Step 2: Submit the record

Producers submit signed records to the registry's staging area, one JSON file per record. The anchor pipeline runs on a schedule, groups pending records by producer, builds one Merkle batch per group, and writes both the registry entry and one inclusion proof per record.

You do not have to use the reference registry. Anything implementing [Anchor Format v1 §8](../../spec/registry-anchor-v1.md) works, and running your own is a reasonable choice for a deployment that cannot publish record bytes to a third party.

---

## Step 3: Retrieve your inclusion proof

The pipeline writes one proof per submitted record:

```json
{"leaf_index": 0, "audit_path": ["sha256:...", "sha256:..."]}
```

`leaf_index` is your record's position in the batch. `audit_path` is the sibling hash at each tree level, ordered leaf to root. A batch of one has an empty `audit_path`, which is valid and not an error.

---

## Step 4: Verify the proof yourself

This is the step that matters, and the one most likely to be skipped. A proof you have never checked is a receipt, not evidence.

```bash
pip install trace-verify

trace-verify \
  --claim your-record.json \
  --proof your-record.proof.json \
  --entry registry/2026/06/12.ndjson \
  --batch-id 2026-06-12-001
```

Exit code 0 means the record is proven included in that batch. Exit code 1 means it is not, and there is no partial result between the two.

The verifier is standard library only and small enough to read in one sitting. Read it, or reimplement it from [Anchor Format v1 §5.1](../../spec/registry-anchor-v1.md), which is written so you can. Verifying with a tool the registry operator wrote is better than nothing, and weaker than verifying with one you wrote.

---

## Step 5: Set `transparency`

Once anchored, set `transparency` to the entry that anchors your record and re-sign, so the signature covers the anchor reference.

```python
record["transparency"] = "<registry entry URI>"
signed_final = sign_record(record, key)
```

A verifier retrieving that entry can confirm inclusion without contacting you, which is the whole point.

---

## What this proves, and what it does not

Inclusion proves the exact signed bytes were in the batch at the entry's timestamp, and that they have not changed since.

It does not validate the signature, and it does not say the record's contents are true. Signature verification against the producer key is a separate step (spec §3.3). A record can be genuinely anchored and still describe something inaccurate; anchoring establishes *when these bytes existed*, and nothing more.

---

## Summary

| Step | What happens |
|---|---|
| Sign the record | `transparency` stays unset until there is an anchor to name |
| Submit to staging | The pipeline batches by producer and builds a Merkle tree |
| Retrieve the proof | `leaf_index` plus `audit_path`, one per record |
| **Verify it yourself** | Recompute the root; exit 0 or exit 1, nothing in between |
| Set `transparency`, re-sign | Signature now covers the anchor reference |

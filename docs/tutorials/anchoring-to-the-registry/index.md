# Anchoring a Trust Record to the TRACE registry

This page is for anyone who has signed a TRACE record and wants a public, hard-to-rewrite trace that the record existed. You will add the record to the TRACE registry (a public, append-only log of records), get back a small proof that it is in there, and check that proof yourself.

The proof shows your exact signed record is part of one batch in the registry. Any claim about *when* the record existed also depends on trusting the registry's own published history and its timestamps, which you check separately.

**What you need:** A signed Trust Record (from [Signing your first trust record](https://trace.agentrust-io.com/docs/tutorials/signing-your-first-trust-record/index.md)).

**What you'll do:** Submit the record, get back an inclusion proof, and check that proof yourself against the published registry entry.

This tutorial was rewritten on 2026-08-08

It previously described POSTing records to a SCITT HTTP API at a registry endpoint. That endpoint does not exist, and the hostname it named was on a domain this project has never controlled, the same defect that forced the [v0.2 profile URI cutover](https://trace.agentrust-io.com/spec/trace-v0.2/index.md). Anchoring works as described below. If you built against the old page, nothing you sent was received by us.

______________________________________________________________________

## Why transparency anchoring matters

A signed record shows it has not changed since the issuer (whoever produced it) signed it, as long as you trust the issuer's key. Keys can be stolen. If that happens, the thief could sign fake records and date them before the theft, and the signature alone could not tell them apart.

Anchoring adds a second, independent witness: the registry. Once a record is in a published registry batch, a later forger cannot slip a backdated record into that batch. The check only counts if you get the registry entry from the registry itself. A record, proof and registry entry that all arrive from the same untrusted sender only show that the three agree with each other.

Technical detail: Merkle proofs and the two canonical forms

A verifier recomputes the Merkle root from the record and proof and compares it to an independently authenticated entry. Check the registry's append-only history and timestamp policy separately.

The normative format is [TRACE Registry Anchor Format v1](https://trace.agentrust-io.com/spec/registry-anchor-v1/index.md). Read §0 of it before you implement anything: TRACE uses **RFC 8785 (JCS)** to canonicalize a record for *signing* and **sorted-key JSON** to canonicalize it for the *anchor leaf*. Assuming JCS at the leaf produces proofs that never verify, and the failure has no useful diagnostic.

______________________________________________________________________

## The `transparency` field

The record has one field, `transparency`, that points at its registry entry. It is optional for Levels 0 and 1 and needed from Level 2 up.

In the `TrustRecord` schema, `transparency` is optional below Level 2:

```
transparency: str | None
```

`None` means the record is unanchored, which is the honest state for a Level 0 or Level 1 record. An empty string is rejected: `""` is not a URI, and a field that looks populated but resolves to nothing is worse in a trust record than an absent one.

Where present, it identifies the registry entry anchoring the record. At Level 2 and above, a verifier must be able to retrieve that entry and check inclusion without contacting you.

______________________________________________________________________

## Step 1: Sign the record

Sign the record in its final form first, because the registry stores the exact signed bytes. Leave `transparency` absent if the registry entry URI is not known yet; distribute the receipt separately. If the registry supports reserving an entry URI, set that URI before signing and submit those exact signed bytes. Do not invent a placeholder URI.

```
import time
from agentrust_trace.sign import generate_key, sign_record

key = generate_key()

record = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": int(time.time()),
    "subject": "spiffe://example.org/agent/my-agent",
    "model": {"provider": "example-provider", "model_id": "example-model-1"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "internal",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "none", "verifier": "self"},
}

signed = sign_record(record, key)
```

The anchored unit is the signed object

Anchoring binds the complete signed claim, signature included. Change either the body or the signature after anchoring and the proof stops verifying, which is the property you want.

______________________________________________________________________

## Step 2: Submit the record

You hand the signed record to the registry's staging area (a waiting area), one JSON file per record. On a schedule, the registry collects waiting records, groups them by who produced them, seals each group into a batch, and writes back the registry entry plus one inclusion proof (the evidence your record is in the batch) for each record.

You do not have to use the reference registry. Anything implementing [Anchor Format v1 §8](https://trace.agentrust-io.com/spec/registry-anchor-v1/index.md) works, and running your own is a reasonable choice for a deployment that cannot publish record bytes to a third party.

______________________________________________________________________

## Step 3: Retrieve your inclusion proof

The pipeline writes one proof per submitted record:

```
{"leaf_index": 0, "audit_path": ["sha256:...", "sha256:..."]}
```

`leaf_index` is your record's position in the batch. `audit_path` is the list of fingerprints needed to rebuild the batch's top-level fingerprint from your record, ordered from your record upward (technically, the sibling hash at each Merkle tree level, leaf to root). A batch of one has an empty `audit_path`, which is valid and not an error.

______________________________________________________________________

## Step 4: Verify the proof yourself

This is the step that matters, and the one most likely to be skipped. A proof you have never checked is only a piece of paper. Checking it is what turns it into evidence.

```
pip install trace-verify

trace-verify \
  --claim your-record.json \
  --proof your-record.proof.json \
  --entry registry/2026/06/12.ndjson \
  --batch-id 2026-06-12-001
```

Exit code 0 means the record is proven included in that batch **and** its producer's signature verified. Exit code 1 means one of those failed, and there is no partial result between the two.

You do not need a clone of the registry for this. Swap `--entry` for `--entry-url` and both the entry and the producer key that signed the record are fetched over https, from an allowlisted host only:

```
trace-verify   --claim your-record.json   --proof your-record.proof.json   --entry-url https://raw.githubusercontent.com/agentrust-io/trace-registry/main/registry/2026/06/12.ndjson
```

Needs `trace-verify` 0.4.1 or later. The command reports which producer key it used and where it came from, because a key fetched from a host is a different trust statement from one you already held.

The verifier is standard library only and small enough to read in one sitting. Read it, or reimplement it from [Anchor Format v1 §5.1](https://trace.agentrust-io.com/spec/registry-anchor-v1/index.md), which is written so you can. Verifying with a tool the registry operator wrote is better than nothing, and weaker than verifying with one you wrote.

______________________________________________________________________

## Step 5: Preserve the anchored record

Store the signed record exactly as it is, together with its proof and registry entry. If you later add `transparency` and sign again, you have a different record, and the old proof no longer covers it. Submit that new record for anchoring if you change any signed field. A Level 2 setup needs a registry that can tell you the entry address before you sign, so the final record can name it.

______________________________________________________________________

## What this proves, and what it does not

A passing check shows this exact signed record is part of the registry batch you checked against. Whether that batch is genuine, and when it was made, depends on how you got the registry entry and whether you trust it.

Signature verification is a separate question from inclusion, and `trace-verify` answers both: it verifies the producer's Ed25519 signature against the registered key unless you pass `--no-verify-signature`, which warns loudly, because inclusion alone does not prove the named producer signed anything. Exit code 0 means both passed.

Neither says the record's contents are true. Inclusion alone does not establish complete logging, a trustworthy timestamp, or an append-only history either. For the last of those, ask the registry's own history the question directly:

```
trace-verify chain registry/2026/09/01.ndjson
```

That checks the checkpoint chain is internally consistent and that it still matches the entries stored under it. The second half is what catches an entry edited after it was anchored.

______________________________________________________________________

## Summary

| Step                   | What happens                                                            |
| ---------------------- | ----------------------------------------------------------------------- |
| Sign the record        | Set a reserved entry URI before signing, or leave `transparency` absent |
| Submit to staging      | The pipeline batches by producer and builds a Merkle tree               |
| Retrieve the proof     | `leaf_index` plus `audit_path`, one per record                          |
| **Verify it yourself** | Recompute the root; exit 0 or exit 1, nothing in between                |
| Preserve the record    | Keep the exact signed object covered by the proof                       |

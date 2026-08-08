# TRACE Registry Anchor Format v1

| Field | Value |
|---|---|
| Version | 1 |
| Status | Normative companion to [TRACE v0.2](trace-v0.2.md) |
| Applies to | The `transparency` claim (TRACE v0.2 §3.1) and Level 2 conformance |
| License | CC BY 4.0 |

This document specifies how TRACE Trust Records are anchored into an append-only registry, and how a third party verifies, **without trusting the registry operator**, that a given record was included in an anchor.

It is published here rather than only in the registry implementation for a reason that matters more than tidiness: an inclusion proof nobody outside can check is not transparency. A conforming verifier can be written from this document alone. The reference tooling named in §7 is one implementation, not the definition.

The construction follows [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) (Certificate Transparency) Merkle trees; the inclusion-proof check is the [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) algorithm.

---

## 0. The canonicalization trap, before anything else

**TRACE uses two different canonicalizations at two different layers, and they are not interchangeable.**

| Layer | Canonicalization | Specified in |
|---|---|---|
| Signing a Trust Record | **RFC 8785 (JCS)** | TRACE v0.2 §3.2 |
| Hashing a record into an anchor leaf | **Sorted-key JSON**, defined in §1 below | this document |

An implementer who reasonably assumes JCS at the leaf will produce proofs that never verify, and the failure gives no useful diagnostic: the recomputed root simply differs from the published one, with nothing to indicate why.

The two agree on records whose strings and keys are pure ASCII and whose numbers are integers, which is most records, which is exactly what makes this dangerous. They diverge on non-ASCII strings, where JCS emits the character and §1 emits a `\uXXXX` escape, and on non-integer numbers, where JCS applies ECMAScript number serialization. §1 excludes non-integer numbers from this profile for that reason.

Do not "simplify" a verifier by reusing the signing canonicalizer at the leaf. If you do, write a test that anchors a record containing a non-ASCII character and verifies it, which is the test that catches this.

---

## 1. Canonical claim bytes

The unit of anchoring is the **complete signed claim object, signature included**. Anchoring binds the signed artifact, not a pre-signature payload: if either the claim body or its signature changes, the anchor no longer matches.

`canonical_claim_bytes` is the canonical JSON serialization of the claim object:

- Object keys sorted lexicographically by Unicode code point, recursively.
- Separators `","` and `":"`, no whitespace.
- Non-ASCII characters escaped (`ensure_ascii`); output encoded as ASCII bytes.
- No trailing newline.

In Python this is exactly:

```python
json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
```

Claims MUST be JSON objects. TRACE Trust Records contain only strings, integers, booleans, nulls, arrays, and objects; claims containing non-integer numbers are outside this profile, because cross-language float serialization is not canonical.

## 2. Leaf hash

```
leaf = SHA-256(0x00 || canonical_claim_bytes)
```

The `0x00` domain-separation prefix is the RFC 6962 leaf prefix. It prevents an interior node from being presented as a leaf (second-preimage attack).

## 3. Merkle tree

The tree over the ordered list of leaves is the RFC 6962 Merkle Tree Hash:

- A tree of one leaf has root equal to that leaf hash.
- Interior nodes: `node = SHA-256(0x01 || left || right)`, where `left` and `right` are the 32-byte child hashes and `0x01` is the interior prefix.
- Construction proceeds level by level over the ordered leaves: adjacent pairs are hashed together; when a level has an odd number of nodes, the final node is **promoted unchanged** to the next level. It is NOT duplicated. This yields the same tree as the RFC 6962 recursive split at the largest power of two.
- The empty batch (zero leaves) is invalid and MUST be rejected.

The root is published hex-encoded, lowercase, prefixed with the algorithm:

```
sha256:<64 lowercase hex characters>
```

## 4. Registry entry

An anchor is recorded as one JSON object with exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `ts` | string | Anchoring time, ISO-8601 UTC with `Z` suffix |
| `merkle_root` | string | `sha256:<hex>` root of the batch tree (§3) |
| `leaf_count` | integer | Number of leaves in the batch, `>= 1` |
| `producer` | string | Identifier of the party that produced and submitted the batch |
| `batch_id` | string | Producer-scoped unique identifier for the batch |

```json
{"ts":"2026-06-12T18:30:00Z","merkle_root":"sha256:9c4f...","leaf_count":1,"producer":"cmcp-gateway/0.1.0","batch_id":"2026-06-12-001"}
```

**Entries are append-only.** Lines are only ever added; existing entries are never rewritten. A registry MUST make that property checkable by an outside party rather than merely assert it. The reference registry uses git history as the tamper-evidence layer: any rewrite of a published entry diverges the commit hashes that auditors and mirrors have already observed, which is why non-fast-forward pushes to its default branch are refused at the platform level as well as in CI.

A registry conforming to this document MUST publish, for each anchor, the fields above, and MUST make the sequence of anchors retrievable by a party with no account or credential on the operator's infrastructure.

## 5. Inclusion proof

A producer gives each claim holder an inclusion proof:

```json
{"leaf_index": 0, "audit_path": ["sha256:<hex>", "sha256:<hex>"]}
```

- `leaf_index`: 0-based position of the claim's leaf in the batch.
- `audit_path`: the RFC 6962 audit path, ordered leaf-to-root: at each tree level, the sibling hash needed to recompute the parent. A level where the node was promoted, and therefore had no sibling, contributes no path element. A single-leaf batch has an empty `audit_path`.

### 5.1 Verification algorithm

Inputs: the claim object, the proof (`leaf_index`, `audit_path`), and the registry entry (`merkle_root`, `leaf_count`). All `sha256:<hex>` strings decode to 32 raw bytes.

```
1. If leaf_index >= leaf_count, reject.
2. r  = SHA-256(0x00 || canonical_claim_bytes)        # §1, §2
   fn = leaf_index
   sn = leaf_count - 1
3. For each p in audit_path, in order:
     a. If sn == 0, reject (path too long).
     b. If fn is odd, or fn == sn:
          r = SHA-256(0x01 || p || r)
          If fn is even:                  # fn == sn, right-edge promotion
              until fn is odd or fn == 0: fn = fn >> 1; sn = sn >> 1
        else:
          r = SHA-256(0x01 || r || p)
     c. fn = fn >> 1; sn = sn >> 1
4. Accept iff sn == 0 and r equals the entry's merkle_root.
```

Any failure, including a wrong root, leftover `sn`, a malformed hash, or an out-of-range index, means the claim is NOT proven included in that entry. A verifier MUST NOT report partial success.

### 5.2 What verification proves, and what it does not

A successful check proves the **exact signed claim bytes** were part of the batch whose root is committed in the registry at the entry's timestamp.

It does not validate the claim's signature, and it does not validate the claim's semantics. Signature verification against the producer key is a separate TRACE step (v0.2 §3.3). A record can be genuinely anchored and still be a record of something untrue; anchoring proves when the bytes existed and that they have not changed since, which is the property the `transparency` claim is asserting and the only one it asserts.

## 6. Relationship to the `transparency` claim

TRACE v0.2 makes `transparency` optional below Level 2, because an unanchored Level 0 or Level 1 record has no receipt to name. Where it is present, it identifies the registry entry that anchors the record.

At **Level 2 and above the anchor is what makes the record independently checkable**, so a verifier appraising a Level 2 record MUST be able to retrieve the entry and check inclusion without contacting the record's issuer. A `transparency` value that resolves only through the issuer's own infrastructure does not satisfy this.

## 7. Reference implementations

Named so that "here is the algorithm, and here is one implementation that is not the definition" is available as a pairing. Neither is normative.

- **`trace-verify`** (PyPI): `pip install trace-verify`, then verify a claim against a proof and an entry. Standard library only.
- A single-file standalone verifier and the anchoring tool ship in the registry repository, deliberately self-contained so they can be copied and audited in isolation rather than trusted.

## 8. Conformance

A registry conforms to Anchor Format v1 if it:

1. Computes leaves and roots per §1 to §3.
2. Publishes entries carrying the §4 fields, append-only, retrievable without operator credentials.
3. Issues proofs of the §5 shape that verify under §5.1 against its published entries.
4. Makes the append-only property externally checkable rather than asserted.

An operator that satisfies 1 through 3 but not 4 is running a log, not a transparency log. The distinction is the whole point of the document.

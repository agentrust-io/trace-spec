# RFC Proposal: behavior-trace blocks

A signed, hash-linked record of every step of one agent run, written by the systems around the agent rather than by the agent itself.

**Status:** Draft proposal. Binds nothing. Experimental wire, `behavior-trace-block/experimental-v1`.
**Scope:** The block format, the chain rules and the verifier outcomes. Signals, task contracts, action tickets and anchoring are later work and are only named here.
**Schema:** `schema/behavior-trace-block-experimental-v1.json`.
**Reference code:** `prototype/behavior_trace.py` (outside the installed SDK) and `verifyRun` in `trust-record-verify`. See section 6 for how the two are held to each other.
**Vectors:** `examples/behavior-trace/`, built by `gen_vectors.py` from raw primitives, not from the reference code.

## 1. Why

A Trust Record says what happened in a run as a summary. It does not show the steps. `references` already has a `behavior-trace` relation for that record of steps (`docs/references-registry.md`), with no format committed. This proposes one.

Two rules shape it:

- **Observed, not reported.** Each block is written and signed by an *edge*: a component the agent has to pass through to act, such as a model gateway, a tool gateway or an egress proxy. Nothing in a block comes from the agent describing itself.
- **No reasoning.** A block may commit to the bytes of a model response. It never extracts, labels or interprets any part of them.

## 2. The block

```json
{
  "v": "behavior-trace-block/experimental-v1",
  "run_id": "sha256:<digest of the run_start block>",
  "edge": "cmcp",
  "seq": 3,
  "prev": "sha256:<digest of this edge's previous block>",
  "parents": ["sha256:<digest of a block this one follows from>"],
  "kind": "tool_call",
  "t": {"observed_at": 1794716520123, "duration_ms": 412},
  "body": {},
  "provenance": {"/body/tool": "observed"},
  "sig": {"alg": "Ed25519", "kid": "<RFC 7638 thumbprint>", "value": "<base64url>"}
}
```

| Member | Rule |
|---|---|
| `v` | The profile string above. |
| `run_id` | Digest of the run's `run_start` block. Absent on `run_start` itself, present on every other block. |
| `edge` | One of `wrapper`, `model-gateway`, `cmcp`, `egress-proxy`, `sandbox`, `ca2a`. |
| `seq` | Position in this edge's chain, from 0, no gaps. |
| `prev` | `null` on `run_start`. On the first block of any other edge, the `run_id`. Otherwise the digest of the edge's previous block. |
| `parents` | Digests of blocks this one follows from, from any edge. May be empty. No repeats, at most 256. |
| `kind` | One of the kinds in section 3. |
| `t` | `observed_at` in Unix milliseconds by the edge's clock, optional `duration_ms`. Host clocks order nothing; links do. |
| `body` | Kind-specific content. Commitments to raw content are salted digests, never the content. Numbers are integers in the safe range. |
| `provenance` | Optional, at most 256 entries. Maps a member to `observed`, `derived` or `asserted`. Each key is an RFC 6901 JSON Pointer that must name a member of this block, other than `sig`, `provenance` or anything inside them. |
| `sig` | Ed25519 by the edge's key over the RFC 8785 bytes of the block without `sig`. `kid` is the RFC 7638 thumbprint of the key. |

**Digest of a block:** `"sha256:" + hex(SHA-256(JCS(block)))`, over the whole block **with** `sig`, the same rule as `delegation.parent_record_hash` in `spec/trace-v0.2.md` section 3.1.3.

Every member is inside the signed bytes except `sig` itself.

**What a parent means.** A block names a parent by its digest, which covers the parent's signature, so the parent existed before the block naming it was signed. A parent link therefore means "happened before". A cycle of parents would need blocks that each contain the digest of the next, around the loop, which is computationally infeasible under SHA-256. The verifier does not search for cycles; it checks that each parent exists, and that none is the run's end (section 3).

## 3. Kinds and the run lifecycle

`run_start`, `model_call`, `tool_call`, `tool_result`, `fetch`, `dns`, `file`, `device`, `approval`, `delegation`, `policy_decision`, `heartbeat`, `run_end`.

A run has exactly one start and at most one end, both written by `wrapper`:

- `run_start`: `wrapper`, `seq` 0, `prev` null, no `run_id`. Its digest is the `run_id` of every other block.
- `run_end`: `wrapper`, the one block at the end of the wrapper chain, `body.outcome` one of `completed`, `blocked`, `failed`, `killed`, `abandoned`. No block may name it as a parent, since that would be activity after the end.
- `heartbeat`: `body.peers` maps an edge name to the digest of a block in that edge's chain. It records what the signing edge had seen from its peers.

Blocks of other edges have no order relative to `run_end` beyond their links. A block that names `run_end` as a parent is after the end and is rejected. A heartbeat may name `run_end` as a peer: that records that its edge saw the end, and is not activity.

## 4. Verifying a run

Input: the blocks of one run, and the keys trusted for each edge (`pinned_keys`: edge name to a list of public JWKs). Output: a classification and a sorted list of codes.

**Configuration errors raise, bad blocks never do.** A `pinned_keys` that is not a map from the edge names above to lists of Ed25519 public JWKs, or `blocks` that is not a list, is the caller's error and is refused (Python `ValueError`, TypeScript `TraceVerificationError`). The same key listed twice for an edge counts once; an edge with an empty list trusts no key; a key pinned for an edge with no blocks is unused. Anything inside `blocks` is untrusted data and is only ever reported through codes.

Per block, first failure only:

| Code | When |
|---|---|
| `schema_invalid` | The block fails the schema, or nests too deeply to check. |
| `key_not_pinned` | `sig.kid` is not a key pinned for the block's `edge`. |
| `signature_invalid` | The signature does not verify. |
| `provenance_path_invalid` | A provenance pointer names no member, or names `sig` or `provenance`. |

If any block fails, the run is `rejected` with those codes and nothing else is checked: structure built on unverified blocks means nothing.

Across blocks:

| Code | When |
|---|---|
| `duplicate_block` | The same block (same digest) appears more than once. The copies are then ignored, so the codes below see each block once. |
| `run_start_invalid` | Not exactly one `run_start`, or it is not `wrapper` with `seq` 0. When this fires, the rules below are not checked. |
| `run_id_mismatch` | A block's `run_id` is not the digest of the `run_start`. |
| `fork` | Two different blocks share an edge and a `seq`. |
| `chain_gap` | An edge's `seq` values are not 0, 1, 2 ... with none missing. |
| `chain_link_broken` | A `prev` does not match the rule in section 2. |
| `parent_missing` | A `parents` digest names no block in the run. |
| `heartbeat_peer_unknown` | A heartbeat peer digest names no block of that edge. |
| `block_after_end` | More than one `run_end`, a `run_end` that is not the one block at the end of the wrapper chain, or a block that names `run_end` as a parent. |

Classification:

| Classification | Meaning |
|---|---|
| `verified` | No codes, and the run has a `run_end`. |
| `truncated` | No codes, and no `run_end`. Every block is genuine, but the run's end is not in the record. Never shown as complete. |
| `rejected` | One or more codes. |

**Input size.** Cost grows with the total size of the blocks. The schema caps `parents` and `provenance` at 256 entries each, which bounds the one quadratic check (`parents` uniqueness). A caller handling untrusted input bounds its size in bytes before parsing it.

## 5. What `verified` does not establish

- That the record is complete. A chain cannot show blocks its edge never wrote, and an edge can stop writing. Heartbeat deadlines and external anchoring, which make the end of a run checkable, are later work.
- That an edge is honest. A block proves its edge signed it, under a key the verifier pinned.
- Anything about the model's reasoning, or why the agent acted.
- Wall-clock order across edges. Only links establish order.

## 6. How the two implementations are held to each other

- Both run the 39 vectors in `examples/behavior-trace/` and must give the expected result for each: 4 `verified`, 2 `truncated` and 33 `rejected`. Every code has at least two vectors.
- `tests/test_behavior_trace_parity.py` builds 600 runs from seeded random changes to valid runs, runs both implementations, and requires the same result for every run. Changes to a block's content re-sign it, so the run reaches the checks after the signature; one change deliberately does not, to keep the signature check in play. The test also requires that the runs reach every code and all three classifications.
- Each rule has a near-miss mutant in both implementations that the tests above must reject.

That is evidence over the inputs those tests generate, not a proof of equivalence over every input.

## 7. Later work

Task contracts, deviation signals, heartbeat deadlines, anchoring in the registry, and action tickets.

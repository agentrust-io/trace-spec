# RFC Proposal: behavior-trace blocks

A signed, hash-linked record of every step of one agent run, written by the systems around the agent rather than by the agent itself.

**Status:** Draft proposal. Binds nothing. Experimental wire, `behavior-trace-block/experimental-v1`.
**Scope:** The block format, the chain rules and the verifier outcomes. Signals, task contracts, action tickets and anchoring are later work and are only named here.
**Schema:** `schema/behavior-trace-block-experimental-v1.json`.
**Reference code:** `prototype/behavior_trace.py` (outside the installed SDK).
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
  "provenance": {"body.tool": "observed"},
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
| `parents` | Digests of blocks from any edge that this block follows from. May be empty. No repeats. |
| `kind` | One of the kinds in section 3. |
| `t` | `observed_at` in Unix milliseconds by the edge's clock, optional `duration_ms`. Host clocks order nothing; links do. |
| `body` | Kind-specific content. Commitments to raw content are salted digests, never the content. |
| `provenance` | Optional. Maps a member path to `observed`, `derived` or `asserted`. |
| `sig` | Ed25519 by the edge's key over the RFC 8785 bytes of the block without `sig`. `kid` is the RFC 7638 thumbprint of the key. |

**Digest of a block:** `"sha256:" + hex(SHA-256(JCS(block)))`, over the whole block **with** `sig`, the same rule as `delegation.parent_record_hash` in `spec/trace-v0.2.md` section 3.1.3.

Every member is inside the signed bytes except `sig` itself.

## 3. Kinds

`run_start`, `model_call`, `tool_call`, `tool_result`, `fetch`, `dns`, `file`, `device`, `approval`, `delegation`, `policy_decision`, `heartbeat`, `run_end`.

Two kinds carry rules in this version:

- `heartbeat`: `body.peers` maps an edge name to the digest of a block in that edge's chain. It records what the signing edge had seen from its peers.
- `run_end`: written by `wrapper`, last in the wrapper chain, `body.outcome` one of `completed`, `blocked`, `failed`, `killed`, `abandoned`.

## 4. Verifying a run

Input: the blocks of one run, and the keys trusted for each edge (`pinned_keys`: edge name to a list of public JWKs). Output: a classification and a sorted list of codes.

Per block:

| Code | When |
|---|---|
| `schema_invalid` | The block fails the schema. |
| `key_not_pinned` | `sig.kid` is not a key pinned for the block's `edge`. |
| `signature_invalid` | The signature does not verify. |

If any block fails, the run is `rejected` with those codes and nothing else is checked: structure built on unverified blocks means nothing.

Across blocks:

| Code | When |
|---|---|
| `run_start_invalid` | Not exactly one `run_start`, or it is not `wrapper`, `seq` 0, `prev` null, without `run_id`. |
| `run_id_mismatch` | A block's `run_id` is not the digest of the `run_start`. |
| `fork` | Two blocks share an edge and a `seq`. |
| `chain_gap` | An edge's `seq` values are not 0, 1, 2 ... with none missing. |
| `chain_link_broken` | A `prev` does not match the rule in section 2. |
| `parent_missing` | A `parents` digest names no block in the run. |
| `heartbeat_peer_unknown` | A heartbeat peer digest names no block of that edge. |
| `block_after_end` | `run_end` is not last in the wrapper chain, or there is more than one. |

Classification:

| Classification | Meaning |
|---|---|
| `verified` | No codes, and the run has a `run_end`. |
| `truncated` | No codes, and no `run_end`. Every block is genuine, but the run's end is not in the record. Never shown as complete. |
| `rejected` | One or more codes. |

## 5. What this does not establish

- That the record is complete. A chain cannot show blocks its edge never wrote, and an edge can stop writing. Heartbeat deadlines and external anchoring, which make the end of a run checkable, are later work.
- That an edge is honest. A block proves its edge signed it, under a key the verifier pinned.
- Anything about the model's reasoning, or why the agent acted.
- Wall-clock order across edges. Only links establish order.

## 6. Later work

Task contracts, deviation signals, heartbeat deadlines, anchoring in the registry, action tickets, and a browser verifier.

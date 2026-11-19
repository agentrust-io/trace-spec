# RFC Proposal: behavior-trace blocks

A signed, hash-linked record of the steps of one agent run that cross an instrumented edge, written by the systems around the agent rather than by the agent itself.

**Status:** Submitted as a candidate Draft Specification under `GOVERNANCE.md` ("Pre-Draft"). It has not been designated a Pre-Draft by the Project Lead, and binds nothing. Experimental wire, `behavior-trace-block/experimental-v1`.
**Scope:** The block format, the body of each kind, the chain rules and the verifier outcomes. Signals, task contracts, action tickets and anchoring are later work and are only named here.
**Schema:** `schema/behavior-trace-block-experimental-v1.json`.
**Reference code:** `prototype/behavior_trace.py` (outside the installed SDK) and `verifyRun` in `trust-record-verify`. Section 6 says how the two are held to each other.
**Vectors:** `examples/behavior-trace/`, built by `gen_vectors.py` from raw primitives, not from the reference code.

## 1. Why

A Trust Record says what happened in a run as a summary. It does not show the steps. `references` already has a `behavior-trace` relation for that record of steps (`docs/references-registry.md`), with no format committed. This proposes one.

Three rules shape it:

- **Observed, not reported.** Each block is written and signed by an *edge*: a component the agent has to pass through to act, such as a model gateway, a tool gateway or an egress proxy. Nothing in a block comes from the agent describing itself.
- **Only what crosses an edge.** Work inside the agent that reaches no edge is not recorded. The record covers the instrumented edges, not the whole run.
- **No content, no reasoning.** Content is carried as keyed digests (section 2.2). A block may commit to the bytes of a model response; it never extracts, labels or interprets any part of them.

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
  "body": {"tool": "search", "args": "hmac-sha256:<64 hex>", "decision": "allow"},
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
| `kind` | One of the kinds in section 2.1. |
| `t` | `observed_at` in Unix milliseconds by the edge's clock, optional `duration_ms`. Host clocks order nothing; links do. |
| `body` | Closed, and defined per kind (section 2.1). |
| `provenance` | Optional, at most 256 entries. See section 2.3. |
| `sig` | Ed25519 by the edge's key over the RFC 8785 bytes of the block without `sig`. `kid` is the RFC 7638 thumbprint of the key. |

**Digest of a block:** `"sha256:" + hex(SHA-256(JCS(block)))`, over the whole block **with** `sig`, the same rule as `delegation.parent_record_hash` in `spec/trace-v0.2.md` section 3.1.3. Every member is inside the signed bytes except `sig` itself.

**What a parent link means.** A block names a parent by its digest, which covers the parent's signature, so the parent's bytes existed before the block naming them was signed. A parent link therefore commits to an order within the record: it is evidence of the order the signing edges produced blocks in, not of when anything physically happened. A cycle of parents would need blocks that each contain the digest of the next, around the loop, which is computationally infeasible under SHA-256. The verifier does not search for cycles; it checks that each parent exists and that none is the run's end (section 3).

### 2.1 Bodies

Every body is closed: a member not listed is a schema failure. Every body may also carry `ext` (section 2.2).

| Kind | Required | Optional |
|---|---|---|
| `run_start` | | `contract` (digest), `manifest` (digest) |
| `model_call` | `model` (identifier, as the provider states it), `request`, `response` (commitments) | `requested_tools` (list of `{tool, args}`), `usage` (`input_tokens`, `output_tokens`) |
| `tool_call` | `tool`, `args` (commitment), `decision` | `server`, `rule` |
| `tool_result` | `tool`, `status` (`ok`, `error`) | `result` (commitment) |
| `policy_decision` | `tool`, `decision` | `rule`, `args` (commitment) |
| `fetch` | `url` (commitment), `status` (0 to 999), `content` (commitment) | `host` (commitment), `bytes` |
| `dns` | `query` (commitment) | `answers` (commitment) |
| `file` | `path` (commitment), `op` (`read`, `write`, `create`, `delete`, `list`) | `bytes` |
| `device` | `device` (`camera`, `microphone`, `screen`, `location`, `other`), `op` (`open`, `close`) | |
| `approval` | `approver` (identifier), `approves` (digest), `decision` (`approved`, `rejected`) | |
| `delegation` | `credential` (identifier) | `child_run` (digest) |
| `heartbeat` | `peers`: edge name to the digest of a block in that edge's chain | |
| `run_end` | `outcome` (`completed`, `blocked`, `failed`, `killed`, `abandoned`) | |

`decision` is one of `allow`, `deny`, `redact`, `advisory_deny`, `step_up`, `defer`.

### 2.2 Commitments, identifiers and `ext`

- A **commitment** is `hmac-sha256:` and 64 lowercase hex: a keyed digest of content, so that low-entropy content cannot be recovered by guessing. Every member that carries content (arguments, results, URLs, paths, model requests and responses) is a commitment.
- An **identifier** is a token of 1 to 256 characters from `A-Z a-z 0-9 . _ : / @ + -`, with no spaces.
- **`ext`** holds up to 32 producer-specific values, keys up to 64 characters, each value a commitment, an identifier, a boolean or a non-negative integer.

What the schema enforces and what it cannot: it guarantees that content members have the shape of a commitment and that no member carries free text. It cannot tell whether a commitment was really keyed and salted, since the verifier does not hold the key, or whether a producer encoded content into an identifier. Those are producer obligations.

### 2.3 Provenance

`provenance` maps an RFC 6901 JSON Pointer of at most 1024 characters to `observed`, `derived` or `asserted`. Each pointer starts with `/body` and must resolve to a leaf value inside the body (a string, number, boolean or null), which may be an array element. It must not resolve to an object or an array. An array index longer than 15 digits resolves to nothing, without being converted to a number.

A label is the signing edge's statement about how it obtained that value. The verifier checks that the pointer resolves; it does not check that the label is true.

## 3. The run lifecycle

A run has exactly one start and at most one end, both written by `wrapper`:

- `run_start`: `wrapper`, `seq` 0, `prev` null, no `run_id`. Its digest is the `run_id` of every other block.
- `run_end`: the one block at the end of the wrapper chain. No block may name it as a parent, since that would be activity after the end.
- `heartbeat`: records what its edge had seen from its peers. A heartbeat may name `run_end` as a peer: that records that its edge saw the end, and is not activity.

Blocks of other edges have no order relative to `run_end` beyond their links. A block that names `run_end` as a parent is after the end and is rejected.

## 4. Verifying a run

Input: the blocks of one run, and the keys trusted for each edge (`pinned_keys`: edge name to a list of public JWKs). Output: a classification and a sorted list of codes.

**Configuration errors raise, bad blocks never do.** These are the caller's errors and are refused (Python `ValueError`, TypeScript `TraceVerificationError`): `blocks` not a list; `pinned_keys` not a map from the edge names above to lists; a pinned key that is not an Ed25519 public JWK, carries private material, or has a malformed `x`; more blocks than the block limit. Within the key set, the same key listed twice counts once, an edge with an empty list trusts no key, and a key pinned for an edge with no blocks is unused. Anything inside `blocks` is untrusted data and is only ever reported through codes.

Per block, first failure only:

| Code | When |
|---|---|
| `schema_invalid` | The block fails the schema (a malformed signature encoding included), or nests too deeply to check. |
| `key_not_pinned` | `sig.kid` is not a key pinned for the block's `edge`. |
| `signature_invalid` | The signature does not verify. |
| `provenance_path_invalid` | A provenance pointer does not resolve to a leaf value. |

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
| `block_after_end` | A `run_end` that is not the one block at the end of the wrapper chain (so also any second `run_end`), or a block that names `run_end` as a parent. |

Classification:

| Classification | Meaning |
|---|---|
| `verified` | No codes, and the run has a `run_end`. |
| `truncated` | No codes, and no `run_end`. Never shown as complete. |
| `rejected` | One or more codes. |

**Exactly what `verified` establishes:** every block has the shape its kind requires and was signed by a key pinned for its edge; there is one `run_start` and every block names it; each edge's chain is complete from its first block to its last, with no fork; every parent and heartbeat peer is a block in the run; and the wrapper chain ends with the one `run_end`, which no block follows.

**Input size.** The default limit is 100,000 blocks (`max_blocks` in Python, `maxBlocks` in TypeScript; `None` or `null` lifts it). On one laptop a valid run of 150,000 blocks took 79 s in TypeScript and 146 s in Python, most of it checking each block against its kind's body. The schema caps `parents` and `provenance` at 256 entries each, which bounds the one quadratic check. Bound the input's size in bytes before parsing it; the verifier sees parsed values, not bytes.

## 5. What `verified` does not establish

- That the record is complete. A chain cannot show blocks its edge never wrote, and an edge can stop writing. Heartbeat deadlines and external anchoring, which make the end of a run checkable, are later work.
- That an edge is honest, that a label in `provenance` is true, or that a commitment was really salted.
- When anything physically happened. Only links establish order, and only the order of signing.
- Anything about the model's reasoning, or why the agent acted.

## 6. How the two implementations are held to each other

- **Vectors.** Both run the 44 vectors in `examples/behavior-trace/` and must give the expected result for each: 5 `verified`, 2 `truncated` and 37 `rejected`. Every code has at least two vectors.
- **Near-miss mutants.** `tests/test_behavior_trace_mutants.py` weakens each rule, one at a time, the way a careful reviewer might have written it: 21 mutants of the Python code and 19 of the compiled TypeScript (two Python rules, `$` anchoring and the bound on index digits, have no TypeScript counterpart). The Python mutants run at the lowest limit Python allows on converting digit strings to integers. Each must fail the vectors named beside it. The runner checks that the unmutated code passes, that every rewrite hits exactly one site, and that a mutant which breaks the verifier outright is reported killed.
- **Random runs.** `tests/test_behavior_trace_parity.py` builds 600 runs from seeded random changes to valid runs and requires both implementations to give the same result for each, and the runs to reach every code and all three classifications. Changes to a block's content re-sign it, so the run reaches the checks after the signature; one change deliberately does not, to keep the signature check in play. The same file runs 17 inputs at the line between a configuration error and a verdict and requires both to draw it in the same place.

That is evidence over the inputs those tests use, not a proof of equivalence over every input.

## 7. Later work

Task contracts, deviation signals, heartbeat deadlines, anchoring in the registry, and action tickets.

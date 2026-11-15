/**
 * Verify behavior-trace blocks (docs/rfcs/behavior-trace.md).
 *
 * Experimental. Implements the same rules as prototype/behavior_trace.py.
 * Section 6 of the RFC says how the two are held to each other.
 *
 * Bad configuration (`pinnedKeys`, a non-array `blocks`) throws a
 * TraceVerificationError. Bad blocks never throw: they become codes.
 */

import { decodeBase64url } from "./base64url.js";
import { digest, hex, importEd25519, verifyEd25519 } from "./crypto.js";
import { fail, TraceVerificationError } from "./errors.js";
import { validateBlock } from "./generated/validators.js";
import { canonicalize } from "./jcs.js";
import { jwkThumbprint } from "./jwk.js";
import { isPlainObject, own } from "./text.js";

export const BEHAVIOR_EDGES = Object.freeze([
  "wrapper",
  "model-gateway",
  "cmcp",
  "egress-proxy",
  "sandbox",
  "ca2a",
] as const);

export const BEHAVIOR_BLOCK_CODES = Object.freeze([
  "schema_invalid",
  "key_not_pinned",
  "signature_invalid",
  "provenance_path_invalid",
] as const);

export const BEHAVIOR_RUN_CODES = Object.freeze([
  "duplicate_block",
  "run_start_invalid",
  "run_id_mismatch",
  "fork",
  "chain_gap",
  "chain_link_broken",
  "parent_missing",
  "heartbeat_peer_unknown",
  "block_after_end",
] as const);

export type BehaviorCode = (typeof BEHAVIOR_BLOCK_CODES)[number] | (typeof BEHAVIOR_RUN_CODES)[number];

export interface RunResult {
  readonly classification: "verified" | "truncated" | "rejected";
  readonly codes: readonly BehaviorCode[];
}

type Block = Record<string, unknown> & {
  edge: string;
  seq: number;
  prev: string | null;
  parents: string[];
  kind: string;
  body: Record<string, unknown>;
  sig: { kid: string; value: string };
};

/**
 * SHA-256 over the RFC 8785 form of the whole block, sig included.
 *
 * Throws a TraceVerificationError (`canonicalization_failed`) for a value that
 * has no RFC 8785 form, such as a non-finite number or one nested too deeply.
 */
export async function blockDigest(block: unknown): Promise<string> {
  return `sha256:${hex(await digest("SHA-256", canonicalize(block)))}`;
}

function signingBytes(block: Record<string, unknown>): Uint8Array {
  const unsigned: Record<string, unknown> = {};
  for (const key of Object.keys(block)) {
    if (key !== "sig") {
      unsigned[key] = block[key];
    }
  }
  return canonicalize(unsigned);
}

type Pinned = Map<string, Map<string, CryptoKey>>;

/** Map edge -> kid -> key. Refuses a malformed key set up front. */
async function pinnedIndex(pinnedKeys: unknown): Promise<Pinned> {
  if (!isPlainObject(pinnedKeys)) {
    fail("invalid_argument", "pinnedKeys must map an edge name to a list of JWKs");
  }
  const index: Pinned = new Map();
  for (const edge of Object.keys(pinnedKeys)) {
    const jwks = own(pinnedKeys, edge);
    if (!(BEHAVIOR_EDGES as readonly string[]).includes(edge) || !Array.isArray(jwks)) {
      fail("invalid_argument", `pinnedKeys must map an edge name in ${BEHAVIOR_EDGES.join(", ")} to a list of JWKs`);
    }
    const keys = new Map<string, CryptoKey>();
    for (const jwk of jwks) {
      const key = await importEd25519(jwk, "bundle_key");
      keys.set(await jwkThumbprint(jwk), key);
    }
    index.set(edge, keys);
  }
  return index;
}

const INDEX = /^(0|[1-9][0-9]*)$/;

/** True if the RFC 6901 pointer names a member of the block outside sig and provenance. */
function resolves(block: Record<string, unknown>, pointer: string): boolean {
  const tokens = pointer
    .split("/")
    .slice(1)
    .map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
  if (tokens[0] === "sig" || tokens[0] === "provenance") {
    return false;
  }
  let node: unknown = block;
  for (const token of tokens) {
    if (isPlainObject(node) && Object.hasOwn(node, token)) {
      node = node[token];
    } else if (Array.isArray(node) && INDEX.test(token) && Number(token) < node.length) {
      node = node[Number(token)];
    } else {
      return false;
    }
  }
  return true;
}

/** The first per-block failure, or null if the block verifies. */
async function blockCode(block: unknown, pinned: Pinned): Promise<BehaviorCode | null> {
  let signed: Uint8Array;
  try {
    if (!validateBlock(block)) {
      return "schema_invalid";
    }
    signed = signingBytes(block as Record<string, unknown>);
  } catch (error) {
    if (error instanceof TraceVerificationError || error instanceof RangeError) {
      return "schema_invalid";
    }
    throw error;
  }
  const b = block as Block;
  const key = pinned.get(b.edge)?.get(b.sig.kid);
  if (key === undefined) {
    return "key_not_pinned";
  }
  const raw = decodeBase64url(b.sig.value);
  if (raw === null || !(await verifyEd25519(key, raw, signed))) {
    return "signature_invalid";
  }
  const provenance = (own(b, "provenance") ?? {}) as Record<string, unknown>;
  if (!Object.keys(provenance).every((path) => resolves(b, path))) {
    return "provenance_path_invalid";
  }
  return null;
}

function result(codes: Set<BehaviorCode>, ended: boolean): RunResult {
  if (codes.size > 0) {
    return { classification: "rejected", codes: [...codes].sort() };
  }
  return { classification: ended ? "verified" : "truncated", codes: [] };
}

/**
 * Verify the blocks of one run against the keys pinned for each edge.
 *
 * Returns `verified`, `truncated` (genuine blocks but no run_end) or `rejected`
 * with the codes that apply.
 *
 * `verified` means every block is authentic and correctly linked and the run is
 * closed by a run_end. It does not mean the record is complete: an edge can stop
 * writing, and a chain cannot show blocks that were never written.
 *
 * Cost grows with the total size of the input. Bound it before calling.
 */
export async function verifyRun(blocks: unknown, pinnedKeys: unknown): Promise<RunResult> {
  if (!Array.isArray(blocks)) {
    fail("invalid_argument", "blocks must be an array");
  }
  const pinned = await pinnedIndex(pinnedKeys);

  const codes = new Set<BehaviorCode>();
  for (const block of blocks) {
    const code = await blockCode(block, pinned);
    if (code !== null) {
      codes.add(code);
    }
  }
  if (codes.size > 0) {
    return result(codes, false);
  }

  // The same block twice is reported once, then dropped, so `fork` below only
  // ever means two different blocks in one position.
  const byDigest = new Map<string, Block>();
  for (const b of blocks as Block[]) {
    const d = await blockDigest(b);
    if (byDigest.has(d)) {
      codes.add("duplicate_block");
    } else {
      byDigest.set(d, b);
    }
  }
  const digests = [...byDigest.keys()];
  const run = [...byDigest.values()];

  const starts = run.flatMap((b, i) => (b.kind === "run_start" ? [i] : []));
  const start = starts.length === 1 ? run[starts[0] as number] : undefined;
  if (start === undefined || start.edge !== "wrapper" || start.seq !== 0) {
    return result(codes.add("run_start_invalid"), false);
  }
  const runId = digests[starts[0] as number] as string;

  if (run.some((b) => (own(b, "run_id") ?? runId) !== runId)) {
    codes.add("run_id_mismatch");
  }

  const chains = new Map<string, Map<number, number[]>>();
  run.forEach((b, i) => {
    const bySeq = chains.get(b.edge) ?? new Map<number, number[]>();
    bySeq.set(b.seq, [...(bySeq.get(b.seq) ?? []), i]);
    chains.set(b.edge, bySeq);
  });

  for (const [edge, bySeq] of chains) {
    if ([...bySeq.values()].some((idx) => idx.length > 1)) {
      codes.add("fork");
    }
    const seqs = [...bySeq.keys()].sort((a, b) => a - b);
    if (seqs.some((seq, i) => seq !== i)) {
      codes.add("chain_gap");
    }
    for (const [seq, idx] of bySeq) {
      for (const i of idx) {
        let want: string | null;
        if (seq === 0) {
          want = edge === "wrapper" ? null : runId;
        } else if (bySeq.get(seq - 1)?.length === 1) {
          want = digests[(bySeq.get(seq - 1) as number[])[0] as number] as string;
        } else {
          continue; // gap or fork already reported
        }
        if ((run[i] as Block).prev !== want) {
          codes.add("chain_link_broken");
        }
      }
    }
  }

  for (const b of run) {
    if (b.parents.some((p) => !byDigest.has(p))) {
      codes.add("parent_missing");
    }
    if (b.kind === "heartbeat") {
      const peers = b.body["peers"] as Record<string, string>;
      for (const edge of Object.keys(peers)) {
        if (byDigest.get(peers[edge] as string)?.edge !== edge) {
          codes.add("heartbeat_peer_unknown");
        }
      }
    }
  }

  // A run_end must be the one block at the end of the wrapper chain, and no
  // block may name it as a parent: a parent link means "happened before".
  // A heartbeat may still name it as a peer, recording that its edge saw the end.
  const ends = run.flatMap((b, i) => (b.kind === "run_end" ? [i] : []));
  const wrapper = chains.get("wrapper");
  let last = -1;
  for (const seq of wrapper?.keys() ?? []) {
    last = Math.max(last, seq); // a loop, not a spread: a spread overflows on long chains
  }
  const terminal = wrapper?.get(last) ?? [];
  const endDigests = new Set(ends.map((i) => digests[i] as string));
  if (
    ends.length > 1 ||
    ends.some((i) => terminal.length !== 1 || terminal[0] !== i) ||
    run.some((b) => b.parents.some((p) => endDigests.has(p)))
  ) {
    codes.add("block_after_end");
  }

  return result(codes, ends.length > 0);
}

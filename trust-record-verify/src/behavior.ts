/**
 * Verify behavior-trace blocks (docs/rfcs/behavior-trace.md).
 *
 * Experimental. Mirrors prototype/behavior_trace.py rule for rule, so both
 * give the same classification and codes for the same run.
 */

import { decodeBase64url } from "./base64url.js";
import { digest, hex, importEd25519, verifyEd25519 } from "./crypto.js";
import { fail, TraceVerificationError } from "./errors.js";
import { validateBlock } from "./generated/validators.js";
import { canonicalize } from "./jcs.js";
import { jwkThumbprint } from "./jwk.js";
import { isPlainObject, own } from "./text.js";

export const BEHAVIOR_BLOCK_CODES = Object.freeze([
  "schema_invalid",
  "key_not_pinned",
  "signature_invalid",
] as const);

export const BEHAVIOR_RUN_CODES = Object.freeze([
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

/** SHA-256 over the RFC 8785 form of the whole block, sig included. */
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
    if (!Array.isArray(jwks)) {
      fail("invalid_argument", "pinnedKeys must map an edge name to a list of JWKs");
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
 * Returns `verified` (complete), `truncated` (genuine but no run_end) or
 * `rejected` with the codes that apply.
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

  const run = blocks as Block[];
  const digests = await Promise.all(run.map((b) => blockDigest(b)));
  const byDigest = new Map<string, Block>();
  run.forEach((b, i) => byDigest.set(digests[i] as string, b));

  const starts = run.flatMap((b, i) => (b.kind === "run_start" ? [i] : []));
  const start = starts.length === 1 ? run[starts[0] as number] : undefined;
  if (start === undefined || start.edge !== "wrapper" || start.seq !== 0) {
    return result(new Set(["run_start_invalid"]), false);
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

  const ends = run.filter((b) => b.kind === "run_end");
  const wrapperLast = Math.max(...(chains.get("wrapper") as Map<number, number[]>).keys());
  if (ends.length > 1 || ends.some((e) => e.edge !== "wrapper" || e.seq !== wrapperLast)) {
    codes.add("block_after_end");
  }

  return result(codes, ends.length > 0);
}

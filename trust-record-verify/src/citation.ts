/**
 * Citation-resolution consumer for `verifyRecord` (spec section 3.1.2).
 *
 * A Trust Record cites objects outside itself at `appraisal.policy_ref`,
 * `runtime.rim_uri` and `model.aibom_uri`. This module records, per surface,
 * whether a caller-supplied resolver produced bytes for the cited URI and what
 * those bytes hashed to. It records resolvability and nothing else:
 *
 * - It asserts no binding (held open by agentrust-io/trace-spec#280 and #190).
 * - It never reads `references[]` (section 3.1.2 rule 3).
 * - The resolver is caller-supplied only, never selected or configured from the record.
 * - `transparency` is deferred (coordinated in agentrust-io/trace-tests#92; spec
 *   section 7 open question 3) and reported as `not_attempted` with `surface_deferred`.
 * - It runs last in `verifyRecord`, after signature verification and every check
 *   that can reject, so an unauthenticated record never drives resolution.
 * - It imports no network or platform library.
 */

import { digest, hex } from "./crypto.js";
import { fail } from "./errors.js";
import { isPlainObject, isUint8Array, own } from "./text.js";

/** What the resolver did for one cited surface. */
export type CitationOutcome = "resolved" | "unresolvable" | "not_attempted";

/** Why a surface reports anything other than `resolved`. */
export type CitationCause =
  | "no_resolver"
  | "field_absent"
  | "surface_deferred"
  | "resolver_raised"
  | "resolver_returned_non_bytes";

/**
 * What the resolver did for one surface, and the facts a second run needs.
 * `evidence` is JSON-serializable by construction.
 */
export interface CitationCheck {
  readonly outcome: CitationOutcome;
  readonly cause: CitationCause | null;
  readonly evidence: Readonly<Record<string, unknown>>;
}

/** Caller-supplied citation resolver returning the cited object's bytes. */
export type CitationResolver = (uri: string) => Uint8Array | Promise<Uint8Array>;

/**
 * The citation surfaces, in report order. The second element is the deferral
 * reason for a surface this module does not consume, or `null` for one it does.
 */
export const SURFACES: readonly (readonly [string, string | null])[] = Object.freeze([
  Object.freeze(["appraisal.policy_ref", null] as const),
  Object.freeze(["runtime.rim_uri", null] as const),
  Object.freeze(["model.aibom_uri", null] as const),
  Object.freeze([
    "transparency",
    "coordinated in agentrust-io/trace-tests#92; spec section 7 open question 3",
  ] as const),
]);

function lookup(record: Record<string, unknown>, path: string): unknown {
  let node: unknown = record;
  for (const part of path.split(".")) {
    if (!isPlainObject(node)) {
      return undefined;
    }
    node = own(node, part);
  }
  return node;
}

/** Extract an exception's class/type name without leaking message text. */
export function exceptionName(err: unknown): string {
  if (typeof err === "object" && err !== null) {
    try {
      const name = (err as { name?: unknown }).name;
      if (typeof name === "string" && name !== "") {
        return name;
      }
      const ctor = (err as { constructor?: { name?: unknown } }).constructor;
      if (typeof ctor === "function" && typeof ctor.name === "string" && ctor.name !== "") {
        return ctor.name;
      }
    } catch {
      return "object";
    }
  }
  return typeof err;
}

/** Describe a non-bytes / invalid value's runtime type without leaking content. */
export function typeName(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "Array";
  }
  if (typeof value === "object") {
    try {
      const ctor = (value as { constructor?: { name?: unknown } }).constructor;
      if (typeof ctor === "function" && typeof ctor.name === "string" && ctor.name !== "") {
        return ctor.name;
      }
    } catch {
      return "object";
    }
    return "object";
  }
  return typeof value;
}

/**
 * Report, per surface in `SURFACES` order, whether the cited URI resolved.
 *
 * Throws `TraceVerificationError` with `record_not_object` when `record` is not a
 * plain JSON object, or `invalid_argument` when `resolver` is neither a function,
 * `null`, nor `undefined`. Every resolver failure or non-bytes return value is
 * recorded as `unresolvable` rather than thrown.
 */
export async function checkCitations(
  record: unknown,
  resolver?: CitationResolver | null,
): Promise<Readonly<Record<string, CitationCheck>>> {
  if (!isPlainObject(record)) {
    fail("record_not_object", "a Trust Record is a JSON object");
  }
  if (resolver !== undefined && resolver !== null && typeof resolver !== "function") {
    fail("invalid_argument", "citationResolver must be a function or null");
  }

  const out: Record<string, CitationCheck> = {};
  for (const [path, deferred] of SURFACES) {
    if (deferred !== null) {
      out[path] = Object.freeze({
        outcome: "not_attempted",
        cause: "surface_deferred",
        evidence: Object.freeze({ reason: deferred }),
      });
      continue;
    }
    if (resolver === undefined || resolver === null) {
      out[path] = Object.freeze({
        outcome: "not_attempted",
        cause: "no_resolver",
        evidence: Object.freeze({}),
      });
      continue;
    }
    const uri = lookup(record, path);
    if (uri === undefined || uri === null) {
      out[path] = Object.freeze({
        outcome: "not_attempted",
        cause: "field_absent",
        evidence: Object.freeze({}),
      });
      continue;
    }
    let value: unknown;
    try {
      value = await resolver(uri as string);
    } catch (err) {
      out[path] = Object.freeze({
        outcome: "unresolvable",
        cause: "resolver_raised",
        evidence: Object.freeze({ uri, exception: exceptionName(err) }),
      });
      continue;
    }
    if (!isUint8Array(value)) {
      out[path] = Object.freeze({
        outcome: "unresolvable",
        cause: "resolver_returned_non_bytes",
        evidence: Object.freeze({ uri, returned: typeName(value) }),
      });
      continue;
    }
    const sha256 = hex(await digest("SHA-256", value));
    out[path] = Object.freeze({
      outcome: "resolved",
      cause: null,
      evidence: Object.freeze({ uri, sha256, bytes: value.byteLength }),
    });
  }
  return Object.freeze(out);
}

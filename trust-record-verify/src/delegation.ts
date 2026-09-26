/**
 * The delegation link of section 3.1.3: the digest a child record commits its
 * parent hop to.
 *
 * The pre-image is the complete parent record as published, with its `signature`
 * member present, canonicalised with RFC 8785 (section 3.1.3):
 *
 *     delegation.parent_record_hash = "sha256:" + hex(SHA-256(JCS(parent_record)))
 *
 * That is deliberately not the signature pre-image of section 3.2.2, which has
 * `signature` absent because a signature cannot cover itself. Digesting the record
 * as published means a verifier digests exactly what it received, with no
 * member-removal step to get wrong.
 *
 * What a verifier does with a *chain* of these links is not normative in v0.2, so
 * this module stops at one link. It gives a caller walking a chain the two
 * operations the specification does fix: recomputing the digest, and comparing a
 * child's commitment against a candidate parent.
 */

import { digest, hex } from "./crypto.js";
import { fail } from "./errors.js";
import { canonicalize } from "./jcs.js";
import { isPlainObject, own, timingSafeEqual } from "./text.js";

/** The digest algorithms the schema's pattern permits for a chain digest (section 3.1.3). */
export const DELEGATION_DIGEST_ALGORITHMS = Object.freeze(["sha256", "sha384"] as const);

export type DelegationDigestAlgorithm = (typeof DELEGATION_DIGEST_ALGORITHMS)[number];

const WEBCRYPTO_NAME: Readonly<Record<DelegationDigestAlgorithm, "SHA-256" | "SHA-384">> = {
  sha256: "SHA-256",
  sha384: "SHA-384",
};

/**
 * The chain digest of *record*, in the form `"<alg>:<hex>"` (section 3.1.3).
 *
 * The record is digested whole, signature included, over its RFC 8785 form. The
 * RFC 8785 key order is by UTF-16 code unit, which agrees with code-point order
 * across the Basic Multilingual Plane and diverges above it, so an implementation
 * that sorts by code point computes correct digests for ASCII records
 * indefinitely and a wrong one the first time a key carries a supplementary-plane
 * character.
 */
export async function parentRecordHash(
  record: unknown,
  algorithm: DelegationDigestAlgorithm = "sha256",
): Promise<string> {
  if (typeof algorithm !== "string" || !Object.hasOwn(WEBCRYPTO_NAME, algorithm)) {
    fail(
      "delegation_algorithm_unsupported",
      `unsupported chain digest algorithm ${typeof algorithm === "string" ? JSON.stringify(algorithm) : typeof algorithm}`,
    );
  }
  return `${algorithm}:${hex(await digest(WEBCRYPTO_NAME[algorithm], canonicalize(record)))}`;
}

export interface DelegationLinkOptions {
  /**
   * The algorithms this verifier implements. A link naming any other algorithm is
   * reported as unsupported and MUST NOT fall back to another one (section 3.1.3).
   */
  readonly supportedDigestAlgorithms?: readonly string[];
}

export interface DelegationLink {
  /** The digest as the child states it. */
  readonly parentRecordHash: string;
  readonly algorithm: DelegationDigestAlgorithm;
  /** The delegation credential the child names as its authority for this hop. */
  readonly credentialId: string;
}

/**
 * Check that *parent* is the record *child* commits to in its `delegation` block.
 *
 * Returns the link when the recomputed digest of *parent* equals the child's
 * `parent_record_hash`. Refuses with `delegation_absent` when the child has no
 * `delegation` block (a root hop, which this function's caller has to handle as
 * such rather than treat as a broken link), `delegation_algorithm_unsupported`
 * when the prefix names an algorithm this verifier does not implement, and
 * `delegation_parent_mismatch` when the digests differ.
 *
 * This checks the link and nothing else: whether either record's own signature
 * verifies is `verifyRecord`'s question, and whether the credential authorises
 * what the child claims is not fixed by v0.2.
 */
export async function verifyDelegationLink(
  child: unknown,
  parent: unknown,
  options: DelegationLinkOptions = {},
): Promise<DelegationLink> {
  if (!isPlainObject(options)) {
    fail("invalid_argument", "verifyDelegationLink takes a plain options object");
  }
  const configured = (options as DelegationLinkOptions).supportedDigestAlgorithms;
  if (configured !== undefined && (!Array.isArray(configured) || configured.some((a) => typeof a !== "string"))) {
    fail("invalid_argument", "supportedDigestAlgorithms must be an array of algorithm names");
  }
  const supported: readonly string[] = configured ?? DELEGATION_DIGEST_ALGORITHMS;
  if (!isPlainObject(child)) {
    fail("record_not_object", "a Trust Record is a JSON object");
  }
  const delegation = own(child, "delegation");
  if (delegation === undefined || delegation === null) {
    fail("delegation_absent", "the record has no delegation block, so it claims no parent hop");
  }
  if (!isPlainObject(delegation)) {
    fail("schema_invalid", "the record's delegation member is not an object", { path: "delegation" });
  }
  const stated = own(delegation, "parent_record_hash");
  const credentialId = own(delegation, "credential_id");
  if (typeof stated !== "string" || typeof credentialId !== "string" || credentialId === "") {
    fail("schema_invalid", "the delegation block needs a parent_record_hash and a credential_id", {
      path: "delegation",
    });
  }
  const separator = stated.indexOf(":");
  const algorithm = separator === -1 ? "" : stated.slice(0, separator);
  if (!supported.includes(algorithm)) {
    fail(
      "delegation_algorithm_unsupported",
      `the link names digest algorithm ${JSON.stringify(algorithm)}, which this verifier does not ` +
        "implement; section 3.1.3 forbids falling back to another one",
    );
  }
  if (!Object.hasOwn(WEBCRYPTO_NAME, algorithm)) {
    fail(
      "delegation_algorithm_unsupported",
      `digest algorithm ${JSON.stringify(algorithm)} is not one this build can compute`,
    );
  }
  const alg = algorithm as DelegationDigestAlgorithm;
  const computed = await parentRecordHash(parent, alg);
  if (!timingSafeEqual(computed, stated)) {
    fail(
      "delegation_parent_mismatch",
      "the candidate parent record does not digest to the value the child commits to",
    );
  }
  return { parentRecordHash: stated, algorithm: alg, credentialId };
}

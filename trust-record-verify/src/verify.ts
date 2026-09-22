/**
 * `verifyRecord`: verification of a TRACE v0.2 Trust Record with an embedded signature.
 *
 * The checks run in this order, and the first one that fails is the one reported.
 * The order is the Python reference's (`agentrust_trace.verify_record`), so two
 * implementations report the same failure for the same input; where the
 * specification requires a check, the section is named.
 *
 *    1. Options: `invalid_argument` for a malformed option (caller data, not record data).
 *    2. The record is a JSON object: `record_not_object`.
 *    3. Profile, before any cryptographic work. A v0.2 verifier MUST require
 *       `tag:agentrust-io.com,2026:trace-v0.2` and MUST reject the v0.1 identifier
 *       (spec/trace-v0.2.md, "Changes from v0.1"): `profile_missing`,
 *       `profile_superseded`, `profile_unsupported`.
 *    4. The embedded signature is present and is a string: `signature_missing`,
 *       `signature_malformed`.
 *    5. The record conforms to the schema: `schema_invalid`, with the location.
 *       Then the signature is decoded as canonical unpadded base64url
 *       (section 3.2.2), after the schema's own pattern for the member has run.
 *    6. A trusted key: the caller's, or `cnf.jwk` only when `allowEmbeddedKey` is
 *       set, and it is an Ed25519 key: `trusted_key_missing`,
 *       `trusted_key_unsupported`, `trusted_key_malformed`.
 *    7. Revocation (section 3.2.3), keyed on the trusted key and never on the
 *       record's own `cnf.jwk`: a caller-supplied store, then a bundle.
 *       `key_revoked`, `revocation_unavailable`; any other bundle defect is
 *       reported in the result, not thrown.
 *    8. The confirmation key: `cnf.jwk` is an Ed25519 key with the same RFC 7638
 *       thumbprint as the trusted key, because the binding is a signature made
 *       by the key in `cnf` (section 3.2.2): `cnf_key_unsupported`,
 *       `cnf_key_malformed`, `cnf_key_mismatch`.
 *    9. Freshness (section 3.2.2): `iat_invalid`, `record_in_future` past the
 *       allowed skew, `record_stale` past the maximum age, `nonce_mismatch` when a
 *       challenge nonce was issued.
 *   10. The signature verifies over the RFC 8785 form of the record with
 *       `signature` absent (section 3.2.2): `canonicalization_failed`,
 *       `signature_invalid`.
 */

import { decodeBase64url } from "./base64url.js";
import { importEd25519, verifyEd25519 } from "./crypto.js";
import { fail, TraceVerificationError } from "./errors.js";
import { canonicalize } from "./jcs.js";
import { keyIdentifiers } from "./jwk.js";
import { checkRevocationBundle, NO_CHECK, type RevocationCheck } from "./revocation.js";
import { recordSchemaViolations } from "./schema.js";
import { isPlainObject, own, timingSafeEqual } from "./text.js";

/** The profile URI this build implements, and the only one `verifyRecord` accepts. */
export const TRACE_PROFILE_V0_2 = "tag:agentrust-io.com,2026:trace-v0.2";

/** The superseded v0.1 identifier, named only so its rejection can say why. */
const TRACE_PROFILE_V0_1 = "tag:agentrust.io,2026:trace-v0.1";

/**
 * A caller-supplied revocation source: the identifiers of revoked keys, or a
 * lookup returning `true` for a revoked key. An identifier is a key's RFC 7638
 * thumbprint or its `kid`. A lookup that throws, or answers with anything but a
 * boolean, has not answered, and the record is rejected rather than passed.
 */
export type RevocationStore =
  | ReadonlySet<string>
  | readonly string[]
  | ((identifier: string) => boolean | Promise<boolean>);

export interface VerifyOptions {
  /** The Ed25519 public key, as a JWK, that the caller trusts to have signed the record. */
  readonly trustedKey?: unknown;
  /**
   * Verify against the record's own `cnf.jwk` when no trusted key is given. That
   * proves the record is internally consistent, not who produced it, and the
   * result reports it as `trustedKeySource: "record"`.
   */
  readonly allowEmbeddedKey?: boolean;
  /** Verification moment in Unix seconds. Defaults to the clock. */
  readonly now?: number;
  /** Maximum record age in seconds. Default 86400 (section 3.2.2); `null` disables the bound. */
  readonly maxAgeSeconds?: number | null;
  /** Tolerated clock skew for `iat` and for a bundle's `issued_at`. Default 300 (section 3.2.2). */
  readonly maxFutureSkewSeconds?: number;
  /** A challenge nonce the record's `runtime.nonce` must echo. */
  readonly expectedNonce?: string;
  readonly revocation?: RevocationStore;
  /** A `TraceRevocationBundle/1.0`, validated here against its schema. */
  readonly revocationBundle?: unknown;
  /** JWKs whose signature the caller accepts on a bundle. */
  readonly trustedBundleKeys?: readonly unknown[];
  /** Maximum bundle age in seconds, measured from `issued_at`. Default 86400. */
  readonly maxBundleAgeSeconds?: number;
}

export interface VerificationResult {
  /** What the revocation check reported. Only `verified` is a revocation check that passed. */
  readonly revocation: RevocationCheck;
  /** RFC 7638 thumbprint of the key the signature was verified against. */
  readonly trustedKeyThumbprint: string;
  /** `caller` for a pinned key, `record` when `allowEmbeddedKey` trusted `cnf.jwk`. */
  readonly trustedKeySource: "caller" | "record";
}

const DEFAULT_MAX_AGE_SECONDS = 86400;
const DEFAULT_MAX_FUTURE_SKEW_SECONDS = 300;
const DEFAULT_MAX_BUNDLE_AGE_SECONDS = 86400;

function seconds(name: string, value: unknown, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail("invalid_argument", `${name} must be a non-negative integer number of seconds`);
  }
  return value;
}

interface Settings {
  trustedKey: unknown;
  allowEmbeddedKey: boolean;
  now: number;
  maxAgeSeconds: number | null;
  maxFutureSkewSeconds: number;
  expectedNonce: string | undefined;
  revocation: RevocationStore | undefined;
  revocationBundle: unknown;
  trustedBundleKeys: readonly unknown[];
  maxBundleAgeSeconds: number;
}

function settings(options: unknown): Settings {
  if (options === undefined) {
    options = {};
  }
  if (!isPlainObject(options)) {
    fail("invalid_argument", "options must be an object");
  }
  const o = options as VerifyOptions;
  const allowEmbeddedKey = own(o as Record<string, unknown>, "allowEmbeddedKey");
  if (allowEmbeddedKey !== undefined && typeof allowEmbeddedKey !== "boolean") {
    fail("invalid_argument", "allowEmbeddedKey must be a boolean");
  }
  const now = own(o as Record<string, unknown>, "now");
  if (now !== undefined && (typeof now !== "number" || !Number.isSafeInteger(now))) {
    fail("invalid_argument", "now must be an integer Unix timestamp in seconds");
  }
  const maxAge = own(o as Record<string, unknown>, "maxAgeSeconds");
  const expectedNonce = own(o as Record<string, unknown>, "expectedNonce");
  if (expectedNonce !== undefined && typeof expectedNonce !== "string") {
    fail("invalid_argument", "expectedNonce must be a string");
  }
  const revocation = own(o as Record<string, unknown>, "revocation");
  if (
    revocation !== undefined &&
    typeof revocation !== "function" &&
    !(revocation instanceof Set) &&
    !(Array.isArray(revocation) && revocation.every((item) => typeof item === "string"))
  ) {
    fail("invalid_argument", "revocation must be a Set or array of key identifiers, or a lookup function");
  }
  const bundleKeys = own(o as Record<string, unknown>, "trustedBundleKeys");
  if (bundleKeys !== undefined && bundleKeys !== null && !Array.isArray(bundleKeys)) {
    fail("invalid_argument", "trustedBundleKeys must be an array of JWK objects");
  }
  const bundle = own(o as Record<string, unknown>, "revocationBundle");
  return {
    trustedKey: own(o as Record<string, unknown>, "trustedKey"),
    allowEmbeddedKey: allowEmbeddedKey === true,
    now: now === undefined ? Math.floor(Date.now() / 1000) : (now as number),
    maxAgeSeconds: maxAge === null ? null : seconds("maxAgeSeconds", maxAge, DEFAULT_MAX_AGE_SECONDS),
    maxFutureSkewSeconds: seconds(
      "maxFutureSkewSeconds",
      own(o as Record<string, unknown>, "maxFutureSkewSeconds"),
      DEFAULT_MAX_FUTURE_SKEW_SECONDS,
    ),
    expectedNonce: expectedNonce as string | undefined,
    revocation: revocation as RevocationStore | undefined,
    revocationBundle: bundle === null ? undefined : bundle,
    trustedBundleKeys: (bundleKeys ?? []) as readonly unknown[],
    maxBundleAgeSeconds: seconds(
      "maxBundleAgeSeconds",
      own(o as Record<string, unknown>, "maxBundleAgeSeconds"),
      DEFAULT_MAX_BUNDLE_AGE_SECONDS,
    ),
  };
}

async function checkStore(identifiers: readonly string[], store: RevocationStore): Promise<void> {
  for (const identifier of identifiers) {
    let revoked: unknown;
    if (typeof store === "function") {
      try {
        revoked = await store(identifier);
      } catch (error) {
        fail(
          "revocation_unavailable",
          `revocation status for key ${JSON.stringify(identifier)} could not be determined; ` +
            "an unavailable revocation source is not evidence that the key is unrevoked",
          { cause: error },
        );
      }
      if (typeof revoked !== "boolean") {
        fail(
          "revocation_unavailable",
          `revocation lookup for key ${JSON.stringify(identifier)} answered with a ${typeof revoked}, ` +
            "not a boolean, so it has not answered",
        );
      }
    } else if (store instanceof Set) {
      revoked = store.has(identifier);
    } else {
      revoked = (store as readonly string[]).includes(identifier);
    }
    if (revoked === true) {
      fail("key_revoked", `the signing key is revoked (listed as ${JSON.stringify(identifier)})`);
    }
  }
}

/**
 * Verify a signed TRACE v0.2 Trust Record.
 *
 * Resolves with a `VerificationResult` when the record verifies, and rejects
 * with a `TraceVerificationError` naming the first failed check otherwise. A
 * resolved result still has to be read: its `revocation.outcome` is
 * `no_check_performed` or `unverified_for_revocation` whenever no bundle or store
 * established that the key is unrevoked, and section 3.2.3 forbids treating
 * either as an affirming appraisal.
 */
export async function verifyRecord(record: unknown, options?: VerifyOptions): Promise<VerificationResult> {
  const s = settings(options);

  if (!isPlainObject(record)) {
    fail("record_not_object", "a Trust Record is a JSON object");
  }

  const profile = own(record, "eat_profile");
  if (typeof profile !== "string" || profile === "") {
    fail("profile_missing", "the record has no eat_profile, and a verifier cannot supply it by assumption");
  }
  if (profile !== TRACE_PROFILE_V0_2) {
    if (profile === TRACE_PROFILE_V0_1) {
      fail(
        "profile_superseded",
        "the record carries the superseded v0.1 profile; a v0.2 verifier rejects it " +
          "(spec/trace-v0.2.md, Changes from v0.1)",
      );
    }
    fail("profile_unsupported", `the record profile is not ${TRACE_PROFILE_V0_2}`);
  }

  const encodedSignature = own(record, "signature");
  if (!Object.hasOwn(record, "signature")) {
    fail("signature_missing", "the record has no embedded signature");
  }
  if (typeof encodedSignature !== "string") {
    fail("signature_malformed", "the signature must be a base64url string");
  }

  const violations = recordSchemaViolations(record);
  if (violations.length > 0) {
    const first = violations[0] as { path: readonly string[]; message: string };
    const path = first.path.length === 0 ? "<record>" : first.path.join(".");
    fail("schema_invalid", `the record does not conform to the TRACE v0.2 schema at ${path}: ${first.message}`, {
      path,
    });
  }
  // The schema's own pattern for `signature` has run by now, so what this adds is
  // the canonical-encoding rule the pattern cannot state: no padding, and unused
  // trailing bits zero (RFC 4648 section 3.5). Without it one signature has
  // several spellings, and section 3.1.3 digests the record with the signature
  // member present, so the spellings are different records that both verify.
  const signature = decodeBase64url(encodedSignature);
  if (signature === null) {
    fail("signature_malformed", "the signature is not canonical unpadded base64url");
  }

  // From here the schema holds: cnf.jwk is an object and iat an integer in range.
  const cnf = record["cnf"] as Record<string, unknown>;
  const embeddedJwk = cnf["jwk"];

  let trustedJwk: unknown;
  let trustedKeySource: "caller" | "record";
  if (s.trustedKey === undefined || s.trustedKey === null) {
    if (!s.allowEmbeddedKey) {
      fail(
        "trusted_key_missing",
        "verifyRecord requires a trusted key; pass trustedKey, or set allowEmbeddedKey to " +
          "trust the record's own cnf.jwk, which proves consistency and not origin",
      );
    }
    trustedJwk = embeddedJwk;
    trustedKeySource = "record";
  } else {
    trustedJwk = s.trustedKey;
    trustedKeySource = "caller";
  }
  const trustedKey = await importEd25519(trustedJwk, "trusted_key");
  const trustedIds = await keyIdentifiers(trustedJwk);

  if (s.revocation !== undefined) {
    await checkStore(trustedIds, s.revocation);
  }
  let revocation: RevocationCheck;
  if (s.revocationBundle !== undefined) {
    revocation = await checkRevocationBundle(s.revocationBundle, {
      trustedKeyIdentifiers: trustedIds,
      trustedBundleKeys: s.trustedBundleKeys,
      now: s.now,
      maxBundleAgeSeconds: s.maxBundleAgeSeconds,
      maxFutureSkewSeconds: s.maxFutureSkewSeconds,
    });
    if (s.revocation !== undefined) {
      revocation = { ...revocation, evidence: { ...revocation.evidence, store: "consulted" } };
    }
  } else if (s.revocation !== undefined) {
    revocation = { outcome: "verified", cause: null, evidence: { source: "store" } };
  } else {
    revocation = NO_CHECK;
  }

  await importEd25519(embeddedJwk, "cnf_key");
  const embeddedIds = await keyIdentifiers(embeddedJwk);
  if (!timingSafeEqual(embeddedIds[0] as string, trustedIds[0] as string)) {
    fail("cnf_key_mismatch", "the record's cnf.jwk does not identify the trusted key that verifies its signature");
  }

  const iat = record["iat"];
  if (typeof iat !== "number" || !Number.isSafeInteger(iat)) {
    fail("iat_invalid", "the record has no valid integer iat for the freshness check");
  }
  const age = s.now - iat;
  if (age < -s.maxFutureSkewSeconds) {
    fail(
      "record_in_future",
      `the record is dated ${-age}s in the future, past the allowed skew of ${s.maxFutureSkewSeconds}s`,
    );
  }
  if (s.maxAgeSeconds !== null && age > s.maxAgeSeconds) {
    fail("record_stale", `the record is ${age}s old, past the maximum age of ${s.maxAgeSeconds}s`);
  }
  if (s.expectedNonce !== undefined) {
    const nonce = own(record["runtime"] as Record<string, unknown>, "nonce");
    if (typeof nonce !== "string" || !timingSafeEqual(nonce, s.expectedNonce)) {
      fail("nonce_mismatch", "the record's runtime.nonce does not match the expected nonce");
    }
  }

  const unsigned = Object.fromEntries(Object.entries(record).filter(([name]) => name !== "signature"));
  let message: Uint8Array;
  try {
    message = canonicalize(unsigned);
  } catch (error) {
    if (error instanceof TraceVerificationError) {
      fail("canonicalization_failed", `the record has no RFC 8785 form: ${error.message}`, { cause: error });
    }
    throw error;
  }
  if (!(await verifyEd25519(trustedKey, signature, message))) {
    fail("signature_invalid", "the signature does not verify over the record's RFC 8785 form");
  }

  return { revocation, trustedKeyThumbprint: trustedIds[0] as string, trustedKeySource };
}

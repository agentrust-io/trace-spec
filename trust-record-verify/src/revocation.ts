/**
 * Revocation-bundle consumer for section 3.2.3.
 *
 * Section 3.2.3 separates three states a verifier reports: verified against a
 * bundle valid at T; unverified for revocation, because the bundle cannot ground
 * that answer; and no revocation check performed, because there was no bundle.
 * It forbids reporting either of the last two as an affirming appraisal. Those
 * three states are the three values of `RevocationCheck.outcome`, and nothing
 * here sets or names an appraisal status.
 *
 * The checks run in a fixed order, and the order is part of the result: a bundle
 * that fails a step is not read further, so `cause` names the first thing wrong.
 *
 *   1. Shape, against the bundle schema and the statement schema it refers to.
 *   2. One log per bundle: every statement names the bundle's `log_id`.
 *   3. Who signed the set: an `ed25519` signature by a key the caller trusts,
 *      over the RFC 8785 form of the bundle with `sig` absent.
 *   4. What the set says about this key. A statement naming it rejects the
 *      record, whatever the bundle's age: the statement was authenticated with
 *      the bundle, and section 3.2.3 gives a statement no expiry.
 *   5. Whether the set was issued in the future, beyond the allowed clock skew.
 *   6. Whether the set is still evidence for what it does not say: both the
 *      issuer's `valid_until` and the caller's maximum age hold, the tighter one
 *      governing, inclusive on the valid side.
 *
 * No inclusion entry ID reaches this function, so a statement naming the key
 * applies section 3.2.3's fallback for records without a usable receipt: every
 * record the key signed is rejected. Statement-level signatures are not checked;
 * the bundle signature authenticates the set.
 */

import { decodeBase64url } from "./base64url.js";
import { digest, hex, importEd25519, verifyEd25519 } from "./crypto.js";
import { fail, TraceVerificationError } from "./errors.js";
import { canonicalize } from "./jcs.js";
import { keyIdentifiers } from "./jwk.js";
import { bundleSchemaViolations } from "./schema.js";
import { isPlainObject } from "./text.js";

export type RevocationOutcome = "verified" | "unverified_for_revocation" | "no_check_performed";

export type RevocationCause =
  | "bundle_expired"
  | "bundle_malformed"
  | "bundle_key_untrusted"
  | "bundle_signature_invalid"
  | "bundle_signature_unsupported"
  | "bundle_issued_in_future";

/**
 * What the revocation check reported, with the facts a second verifier needs to
 * reach the same outcome from retained data alone. `evidence` is plain JSON.
 */
export interface RevocationCheck {
  readonly outcome: RevocationOutcome;
  readonly cause: RevocationCause | null;
  readonly evidence: Readonly<Record<string, unknown>>;
}

export const NO_CHECK: RevocationCheck = Object.freeze({
  outcome: "no_check_performed",
  cause: null,
  evidence: Object.freeze({}),
});

export interface BundleCheckOptions {
  /** Identifiers of the key the record is verified against: thumbprint first, then `kid`. */
  readonly trustedKeyIdentifiers: readonly string[];
  /** JWKs whose signature the caller accepts on a bundle. */
  readonly trustedBundleKeys: readonly unknown[];
  /** Verification moment, Unix seconds. */
  readonly now: number;
  readonly maxBundleAgeSeconds: number;
  readonly maxFutureSkewSeconds: number;
}

function unverified(cause: RevocationCause, evidence: Record<string, unknown>): RevocationCheck {
  return { outcome: "unverified_for_revocation", cause, evidence };
}

/** The bundle's identity: `sha256:` and the hex SHA-256 of its RFC 8785 form, signature included. */
export async function bundleDigest(bundle: unknown): Promise<string> {
  return `sha256:${hex(await digest("SHA-256", canonicalize(bundle)))}`;
}

async function trustedBundleKey(
  bundleKeyId: string,
  trustedBundleKeys: readonly unknown[],
): Promise<unknown> {
  for (const jwk of trustedBundleKeys) {
    let identifiers: string[];
    try {
      identifiers = await keyIdentifiers(jwk);
    } catch (error) {
      if (error instanceof TraceVerificationError && error.code === "jwk_invalid") {
        fail("invalid_argument", `a trusted bundle key is not a usable JWK: ${error.message}`, {
          cause: error,
        });
      }
      throw error;
    }
    if (identifiers.includes(bundleKeyId)) {
      return jwk;
    }
  }
  return undefined;
}

/**
 * Decide what *bundle* lets a verifier report about the trusted record key.
 *
 * Returns a `RevocationCheck`. Throws `key_revoked` when a statement on the
 * bundle's log names the key, and `invalid_argument` when a trusted bundle key
 * the search reaches has no thumbprint. Every other defect in the bundle is an
 * outcome, not an exception: inability to check is not evidence of a defect.
 */
export async function checkRevocationBundle(
  bundle: unknown,
  options: BundleCheckOptions,
): Promise<RevocationCheck> {
  if (!isPlainObject(options)) {
    fail("invalid_argument", "checkRevocationBundle needs an options object");
  }
  const { trustedKeyIdentifiers, trustedBundleKeys, now, maxBundleAgeSeconds, maxFutureSkewSeconds } =
    options as BundleCheckOptions;
  if (!Array.isArray(trustedKeyIdentifiers) || !trustedKeyIdentifiers.every((id) => typeof id === "string")) {
    fail("invalid_argument", "trustedKeyIdentifiers must be an array of key identifier strings");
  }
  if (!Array.isArray(trustedBundleKeys)) {
    fail("invalid_argument", "trustedBundleKeys must be an array of JWK objects");
  }
  for (const [name, value] of [
    ["now", now],
    ["maxBundleAgeSeconds", maxBundleAgeSeconds],
    ["maxFutureSkewSeconds", maxFutureSkewSeconds],
  ] as const) {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || (name !== "now" && value < 0)) {
      fail("invalid_argument", `${name} must be an integer number of seconds`);
    }
  }

  // 1. Shape. The first violation by location, so the evidence names one place.
  const violations = bundleSchemaViolations(bundle);
  if (violations.length > 0) {
    const first = violations[0] as { path: readonly string[]; message: string };
    return unverified("bundle_malformed", {
      path: first.path.length === 0 ? "/" : first.path.join("/"),
      error: first.message,
    });
  }
  const shaped = bundle as {
    log_id: string;
    issued_at: number;
    valid_until: number;
    statements: { log_id: string; compromised_key_id: string }[];
    bundle_key_id: string;
    sig: { alg: string; value: string };
  };
  const logId = shaped.log_id;

  // 2. One log per bundle.
  for (const [index, statement] of shaped.statements.entries()) {
    if (statement.log_id !== logId) {
      return unverified("bundle_malformed", {
        path: `statements/${index}/log_id`,
        error: "statement names a different log than the bundle",
      });
    }
  }

  let bundleId: string;
  try {
    bundleId = await bundleDigest(bundle);
  } catch (error) {
    if (error instanceof TraceVerificationError && error.code === "canonicalization_failed") {
      return unverified("bundle_malformed", {
        path: "/",
        error: `the bundle has no RFC 8785 form: ${error.message}`,
      });
    }
    throw error;
  }
  const base = {
    bundle_digest: bundleId,
    log_id: logId,
    issued_at: shaped.issued_at,
    valid_until: shaped.valid_until,
    now,
    max_bundle_age_seconds: maxBundleAgeSeconds,
  };

  // 3. Who signed the set. Only Ed25519 is verified here. The schema also admits
  // ES256 and ES384; a signature nobody checked grounds nothing, so those are
  // reported as unsupported rather than skipped.
  const alg = shaped.sig.alg;
  if (alg !== "ed25519") {
    return unverified("bundle_signature_unsupported", { ...base, alg });
  }
  const signerJwk = await trustedBundleKey(shaped.bundle_key_id, trustedBundleKeys);
  if (signerJwk === undefined) {
    return unverified("bundle_key_untrusted", { ...base, bundle_key_id: shaped.bundle_key_id });
  }
  let signer: CryptoKey;
  try {
    signer = await importEd25519(signerJwk, "bundle_key");
  } catch (error) {
    if (error instanceof TraceVerificationError && error.code !== "crypto_unavailable") {
      return unverified("bundle_signature_unsupported", { ...base, alg, key: error.message });
    }
    throw error;
  }
  const signature = decodeBase64url(shaped.sig.value);
  const unsigned = Object.fromEntries(Object.entries(shaped).filter(([name]) => name !== "sig"));
  const signed = signature !== null && (await verifyEd25519(signer, signature, canonicalize(unsigned)));
  if (!signed) {
    return unverified("bundle_signature_invalid", { ...base, bundle_key_id: shaped.bundle_key_id });
  }

  // 4. What the set says about this key, read before either time check.
  for (const statement of shaped.statements) {
    if (trustedKeyIdentifiers.includes(statement.compromised_key_id)) {
      fail(
        "key_revoked",
        `the signing key is revoked: a statement on log ${JSON.stringify(logId)} names it as ` +
          `${JSON.stringify(statement.compromised_key_id)} (bundle ${bundleId}). No inclusion ` +
          "entry ID is available to place this record before the revocation, so section " +
          "3.2.3's fallback applies and the record is rejected.",
      );
    }
  }

  // 5. Issued in the future: its silence about other keys is evidence of nothing.
  if (shaped.issued_at > now + maxFutureSkewSeconds) {
    return unverified("bundle_issued_in_future", { ...base, max_future_skew_seconds: maxFutureSkewSeconds });
  }

  // 6. Age. Tighter governs; inclusive on the valid side.
  const issuerTripped = now > shaped.valid_until;
  const deploymentTripped = now - shaped.issued_at > maxBundleAgeSeconds;
  if (issuerTripped || deploymentTripped) {
    const boundTripped = issuerTripped && deploymentTripped ? "both" : issuerTripped ? "issuer" : "deployment";
    return unverified("bundle_expired", { ...base, bound_tripped: boundTripped });
  }

  return { outcome: "verified", cause: null, evidence: { ...base, statements_count: shaped.statements.length } };
}

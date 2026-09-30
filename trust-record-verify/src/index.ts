/**
 * A TypeScript verifier for TRACE v0.2 Trust Records.
 *
 * Nothing here reaches the network, reads a file or imports a Node built-in: the
 * verifier runs in a browser, an edge worker, Deno, Bun and Node.js 20 and later
 * on WebCrypto alone. Every input a caller cannot vouch for, including the record
 * and a revocation bundle, is treated as untrusted data.
 *
 * Start at `verifyRecord`.
 */

export { decodeBase64url, encodeBase64url } from "./base64url.js";
export {
  DELEGATION_DIGEST_ALGORITHMS,
  parentRecordHash,
  verifyDelegationLink,
  type DelegationDigestAlgorithm,
  type DelegationLink,
  type DelegationLinkOptions,
} from "./delegation.js";
export { FAILURE_CODES, TraceVerificationError, type FailureCode } from "./errors.js";
export { canonicalize, canonicalJson, JCS_SAFE_INTEGER } from "./jcs.js";
export { jwkThumbprint, keyIdentifiers } from "./jwk.js";
export {
  bundleDigest,
  checkRevocationBundle,
  NO_CHECK,
  type BundleCheckOptions,
  type RevocationCause,
  type RevocationCheck,
  type RevocationOutcome,
} from "./revocation.js";
export {
  bundleSchemaViolations,
  recordSchemaViolations,
  SCHEMA_DIGESTS,
  type SchemaViolation,
} from "./schema.js";
export {
  TRACE_PROFILE_V0_2,
  verifyRecord,
  type RevocationStore,
  type VerificationResult,
  type VerifyOptions,
} from "./verify.js";

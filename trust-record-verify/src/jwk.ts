/**
 * RFC 7638 JWK Thumbprints, and the identifiers a revocation source may list a key under.
 */

import { encodeBase64url } from "./base64url.js";
import { digest } from "./crypto.js";
import { fail, TraceVerificationError } from "./errors.js";
import { canonicalize } from "./jcs.js";
import { isPlainObject, own } from "./text.js";

/**
 * The required members of each key type (RFC 7638 section 3.2, and RFC 8037
 * section 2 for OKP). Only these are hashed. `oct` is left out on purpose: it
 * carries a symmetric secret, and every key this package handles is public.
 */
const THUMBPRINT_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ["crv", "kty", "x", "y"],
  OKP: ["crv", "kty", "x"],
  RSA: ["e", "kty", "n"],
};

/**
 * The RFC 7638 thumbprint of *jwk*: base64url SHA-256 of the required members,
 * serialized with RFC 8785 (their names are ASCII, so that is the member order
 * RFC 7638 section 3.3 specifies).
 *
 * Refuses, as `jwk_invalid`, a value that is not an object, an unknown `kty`,
 * and a required member that is absent, empty or not a string.
 */
export async function jwkThumbprint(jwk: unknown): Promise<string> {
  if (!isPlainObject(jwk)) {
    fail("jwk_invalid", "a JWK must be a JSON object");
  }
  const kty = own(jwk, "kty");
  const members = typeof kty === "string" && Object.hasOwn(THUMBPRINT_MEMBERS, kty)
    ? (THUMBPRINT_MEMBERS[kty] as readonly string[])
    : undefined;
  if (members === undefined) {
    fail("jwk_invalid", "cannot compute a JWK thumbprint for this kty; expected EC, OKP or RSA");
  }
  const required: Record<string, string> = {};
  for (const name of members) {
    const value = own(jwk, name);
    if (typeof value !== "string" || value === "") {
      fail("jwk_invalid", `the JWK is missing required thumbprint member "${name}"`);
    }
    required[name] = value;
  }
  let bytes: Uint8Array;
  try {
    bytes = canonicalize(required);
  } catch (error) {
    if (error instanceof TraceVerificationError) {
      fail("jwk_invalid", `the JWK's thumbprint members have no RFC 8785 form: ${error.message}`, {
        cause: error,
      });
    }
    throw error;
  }
  return encodeBase64url(await digest("SHA-256", bytes));
}

/**
 * Every identifier a revocation store or statement may list *jwk* under: its
 * thumbprint first, then its `kid` when that is a non-empty string different
 * from the thumbprint. Matching either one revokes the key (section 3.2.3).
 */
export async function keyIdentifiers(jwk: unknown): Promise<string[]> {
  const identifiers = [await jwkThumbprint(jwk)];
  const kid = own(jwk as Record<string, unknown>, "kid");
  if (typeof kid === "string" && kid !== "" && !identifiers.includes(kid)) {
    identifiers.push(kid);
  }
  return identifiers;
}

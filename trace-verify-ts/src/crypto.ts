/**
 * WebCrypto access. Nothing here reaches the network or any module outside the
 * platform: the verifier runs wherever `globalThis.crypto.subtle` exists, which
 * covers current browsers, Node.js 20 and later, Deno, Bun and edge workers.
 */

import { fail, type FailureCode } from "./errors.js";
import { decodeBase64url } from "./base64url.js";
import { isPlainObject, own } from "./text.js";

function subtle(): SubtleCrypto {
  const value = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (value === undefined) {
    fail("crypto_unavailable", "this runtime exposes no WebCrypto (globalThis.crypto.subtle)");
  }
  return value;
}

function isNotSupported(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { name?: unknown }).name === "NotSupportedError"
  );
}

/** A short, never-throwing description of an untrusted value for an error message. */
export function show(value: unknown): string {
  return typeof value === "string" ? JSON.stringify(value.slice(0, 64)) : typeof value;
}

export async function digest(algorithm: "SHA-256" | "SHA-384", data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest(algorithm, data as Uint8Array<ArrayBuffer>));
}

export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Import an Ed25519 public key from a JWK, refusing every other key type.
 *
 * `role` selects which failure codes a refusal carries, so the caller learns
 * whether the trusted key or the record's own `cnf.jwk` was at fault. The
 * checks and their order follow the reference: `kty`, then `crv`, then the
 * presence of `x`, then its encoding, then its length.
 */
export async function importEd25519(
  jwk: unknown,
  role: "trusted_key" | "cnf_key" | "bundle_key",
): Promise<CryptoKey> {
  const unsupported: FailureCode =
    role === "trusted_key" ? "trusted_key_unsupported" : role === "cnf_key" ? "cnf_key_unsupported" : "invalid_argument";
  const malformed: FailureCode =
    role === "trusted_key" ? "trusted_key_malformed" : role === "cnf_key" ? "cnf_key_malformed" : "invalid_argument";
  const label = role === "trusted_key" ? "trusted key" : role === "cnf_key" ? "record cnf.jwk" : "bundle key";

  if (!isPlainObject(jwk)) {
    fail(unsupported, `${label} must be a JWK object`);
  }
  const kty = own(jwk, "kty");
  const crv = own(jwk, "crv");
  const x = own(jwk, "x");
  if (kty !== "OKP") {
    fail(unsupported, `${label} has kty ${show(kty)}; expected "OKP" for Ed25519`);
  }
  if (crv !== "Ed25519") {
    fail(unsupported, `${label} has crv ${show(crv)}; expected "Ed25519"`);
  }
  if (x === undefined || x === null || x === "") {
    fail(malformed, `${label} has no "x" member`);
  }
  if (typeof x !== "string") {
    fail(malformed, `${label} "x" must be a base64url string`);
  }
  const raw = decodeBase64url(x);
  if (raw === null) {
    fail(malformed, `${label} "x" is not canonical unpadded base64url`);
  }
  if (raw.length !== 32) {
    fail(malformed, `${label} "x" decodes to ${raw.length} bytes; an Ed25519 public key is 32 bytes`);
  }
  try {
    return await subtle().importKey("raw", raw as Uint8Array<ArrayBuffer>, { name: "Ed25519" }, false, ["verify"]);
  } catch (error) {
    if (isNotSupported(error)) {
      fail("crypto_unavailable", "this runtime's WebCrypto does not implement Ed25519", {
        cause: error,
      });
    }
    fail(malformed, `${label} "x" is not an Ed25519 public key this runtime accepts`, {
      cause: error,
    });
  }
}

/** Ed25519 verification. Any refusal by the platform counts as a signature that does not verify. */
export async function verifyEd25519(
  key: CryptoKey,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  try {
    return await subtle().verify(
      { name: "Ed25519" },
      key,
      signature as Uint8Array<ArrayBuffer>,
      message as Uint8Array<ArrayBuffer>,
    );
  } catch (error) {
    if (isNotSupported(error)) {
      fail("crypto_unavailable", "this runtime's WebCrypto does not implement Ed25519", {
        cause: error,
      });
    }
    return false;
  }
}

/**
 * base64url without padding (RFC 4648 section 5), decoded strictly.
 *
 * Section 3.2.2 carries an embedded signature as "base64url, no padding", and
 * RFC 7515 section 2 defines the same form for JWK members. A value is accepted
 * only in that form: characters from the URL-safe alphabet, no `=` padding, no
 * whitespace, a length that is not 1 more than a multiple of 4, and unused
 * trailing bits set to zero (RFC 4648 section 3.5). The last rule makes the
 * encoding canonical, so one byte string has exactly one accepted spelling.
 */

import { fail } from "./errors.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const DECODE = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** Why a value was refused, or `null` for a well-formed value. */
export function base64urlProblem(value: unknown): string | null {
  if (typeof value !== "string") {
    return `expected a string, got ${typeof value}`;
  }
  if (value.length % 4 === 1) {
    return `length ${value.length} is not a valid unpadded base64url length`;
  }
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 128 || DECODE[unit] === -1) {
      return `character at offset ${i} is outside the base64url alphabet`;
    }
  }
  const rest = value.length % 4;
  if (rest !== 0) {
    const last = DECODE[value.charCodeAt(value.length - 1)] as number;
    const unusedBits = rest === 2 ? 0b1111 : 0b11;
    if ((last & unusedBits) !== 0) {
      return "unused trailing bits are not zero, so the encoding is not canonical";
    }
  }
  return null;
}

/** Decode *value*, or return `null` when it is not canonical unpadded base64url. */
export function decodeBase64url(value: unknown): Uint8Array | null {
  if (typeof value !== "string") {
    return null;
  }
  if (base64urlProblem(value) !== null) {
    return null;
  }
  const out = new Uint8Array(Math.floor((value.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (let i = 0; i < value.length; i++) {
    buffer = ((buffer << 6) | (DECODE[value.charCodeAt(i)] as number)) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

/** Encode *bytes* as unpadded base64url. */
export function encodeBase64url(bytes: Uint8Array): string {
  if (!ArrayBuffer.isView(bytes)) {
    fail("invalid_argument", "encodeBase64url takes a Uint8Array");
  }
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += ALPHABET[(buffer >> bits) & 0x3f];
    }
  }
  if (bits > 0) {
    out += ALPHABET[(buffer << (6 - bits)) & 0x3f];
  }
  return out;
}

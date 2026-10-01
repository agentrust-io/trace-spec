// COSE_Sign1 (RFC 9052) handling for the two experimental profiles, plus the
// Ed25519 helpers. Only node:crypto is used.

import crypto from 'node:crypto';
import { decode, encode, Tagged, CborMalformed, CborNoncanonical } from './cbor.mjs';
import { parseStrict, canonicalize, JsonDuplicateKey } from './json.mjs';
import { fail } from './errors.mjs';

export const MAX_ENVELOPE = 65536;
export const ALG_ED25519 = -19; // fully specified Ed25519, RFC 9864
export const CRIT_LABEL = 'trace-profile';

export const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest();
export const sha256Hex = (bytes) => 'sha256:' + sha256(bytes).toString('hex');

function bytesEqual(a, b) {
  return a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
}

function decodeStrict(bytes) {
  try {
    return decode(bytes);
  } catch (e) {
    if (e instanceof CborNoncanonical) fail('noncanonical_cbor', e.message);
    if (e instanceof CborMalformed) fail('malformed_envelope', e.message);
    throw e;
  }
}

// Parses and checks the envelope and protected header, then the payload JSON
// (duplicate members, JCS form). Does not check the signature or the schema.
export function unpack(envelope, profile, mediaType) {
  if (!(envelope instanceof Uint8Array) || envelope.length > MAX_ENVELOPE) fail('envelope_size');
  const outer = decodeStrict(envelope);
  if (!(outer instanceof Tagged) || outer.tag !== 18) fail('envelope_tag');
  const body = outer.value;
  if (!Array.isArray(body) || body.length !== 4) fail('envelope_structure', 'not a 4-element array');
  const [protBytes, unprotected, payloadBytes, signature] = body;
  if (!(protBytes instanceof Uint8Array)) fail('envelope_structure', 'protected not bstr');
  if (!(unprotected instanceof Map) || unprotected.size !== 0) fail('envelope_structure', 'unprotected not empty map');
  if (!(payloadBytes instanceof Uint8Array)) fail('envelope_structure', 'payload not bstr');
  if (!(signature instanceof Uint8Array)) fail('envelope_structure', 'signature not bstr');

  if (protBytes.length === 0) fail('protected_headers', 'empty protected header');
  const hdr = decodeStrict(protBytes);
  if (!(hdr instanceof Map)) fail('protected_headers', 'not a map');
  const expectedKeys = [1, 2, 3, 4, CRIT_LABEL];
  if (hdr.size !== expectedKeys.length || !expectedKeys.every((k) => hdr.has(k))) fail('protected_headers', 'header label set');
  if (hdr.get(1) !== ALG_ED25519) fail('protected_headers', 'alg');
  const crit = hdr.get(2);
  if (!Array.isArray(crit) || crit.length !== 1 || crit[0] !== CRIT_LABEL) fail('protected_headers', 'crit');
  if (hdr.get(3) !== mediaType) fail('protected_headers', 'content type');
  const kid = hdr.get(4);
  if (!(kid instanceof Uint8Array) || kid.length !== 32) fail('protected_headers', 'kid');
  if (hdr.get(CRIT_LABEL) !== profile) fail('protected_headers', 'profile');
  if (signature.length !== 64) fail('protected_headers', 'signature length');

  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payloadBytes);
  } catch {
    fail('malformed_payload', 'payload not UTF-8');
  }
  let payload;
  try {
    payload = parseStrict(text);
  } catch (e) {
    if (e instanceof JsonDuplicateKey) fail('duplicate_json_key', e.message);
    fail('malformed_payload', e.message);
  }
  if (canonicalize(payload) !== text) fail('noncanonical_payload');
  return { protBytes, payloadBytes, signature, kid, payload };
}

export function sigStructure(protBytes, payloadBytes) {
  return encode(['Signature1', protBytes, new Uint8Array(0), payloadBytes]);
}

export function ed25519Verify(rawPublic, message, signature) {
  let key;
  try {
    key = crypto.createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(rawPublic).toString('base64url') },
      format: 'jwk',
    });
  } catch {
    return false;
  }
  try {
    return crypto.verify(null, message, key, signature);
  } catch {
    return false;
  }
}

// Ed25519 point decoding per RFC 8032 section 5.1.3, to decide whether 32
// bytes are a canonical public key encoding.
const P = 2n ** 255n - 19n;
const D = (-121665n * modInv(121666n)) % P;
function mod(a) { const r = a % P; return r < 0n ? r + P : r; }
function modPow(b, e) { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; } return r; }
function modInv(a) { return modPow(((a % (2n ** 255n - 19n)) + (2n ** 255n - 19n)) % (2n ** 255n - 19n), 2n ** 255n - 21n); }

export function isCanonicalEd25519(raw) {
  if (!(raw instanceof Uint8Array) || raw.length !== 32) return false;
  const bytes = Uint8Array.from(raw);
  const sign = bytes[31] >> 7;
  bytes[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  if (y >= P) return false;
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * modPow(v, 3n) * modPow(u * modPow(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === u) { /* root found */ } else if (vx2 === mod(-u)) {
    x = mod(x * modPow(2n, (P - 1n) / 4n));
  } else {
    return false;
  }
  if (x === 0n && sign === 1) return false;
  return true;
}

// Decodes an unpadded base64url string and requires it to round-trip, so a
// string with non-zero trailing bits is not accepted as an alias.
export function b64uStrict(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const b = Buffer.from(s, 'base64url');
  if (b.toString('base64url') !== s) return null;
  return new Uint8Array(b);
}

export { bytesEqual };

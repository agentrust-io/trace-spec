// Independent Node/OpenSSL crypto check of fixed portable COSE/JCS vectors.
// This bounded fixture reader is not a production parser or appraisal verifier.
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';

const file = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const anchor = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const envelope = Buffer.from(file.envelope_b64, 'base64url');
let cursor = 0;
function decode(depth = 0) {
  if (depth > 16 || cursor >= envelope.length) throw Error('bounded fixture reader');
  const head = envelope[cursor++];
  const major = head >> 5;
  let size = head & 31;
  if (size === 24) size = envelope[cursor++];
  else if (size === 25) { size = envelope.readUInt16BE(cursor); cursor += 2; }
  else if (size === 26) { size = envelope.readUInt32BE(cursor); cursor += 4; }
  else if (size >= 27) throw Error('unsupported fixture encoding');
  if (!Number.isSafeInteger(size) || size > 65536) throw Error('fixture bound');
  if (major === 0) return size;
  if (major === 1) return -1 - size;
  if (major === 2 || major === 3) {
    if (cursor + size > envelope.length) throw Error('truncated fixture');
    const value = envelope.subarray(cursor, cursor += size);
    return major === 2 ? value : new TextDecoder('utf8', { fatal: true }).decode(value);
  }
  if (major === 4) return Array.from({ length: size }, () => decode(depth + 1));
  if (major === 5) {
    const result = new Map();
    for (let i = 0; i < size; i++) {
      const key = decode(depth + 1);
      if (result.has(key)) throw Error('duplicate fixture map key');
      result.set(key, decode(depth + 1));
    }
    return result;
  }
  if (major === 6 && size === 18) return decode(depth + 1);
  throw Error('unsupported fixture value');
}
function bytes(value, major) {
  const data = Buffer.from(value);
  const n = data.length;
  const head = n < 24 ? Buffer.from([(major << 5) | n])
    : n < 256 ? Buffer.from([(major << 5) | 24, n])
    : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  return Buffer.concat([head, data]);
}
const [protectedBytes, unprotected, payload, signature] = decode();
if (cursor !== envelope.length || !(unprotected instanceof Map) || unprotected.size) {
  throw Error('unsupported fixture envelope');
}
const preimage = Buffer.concat([Buffer.from([0x84]), bytes('Signature1', 3),
  bytes(protectedBytes, 2), bytes(Buffer.alloc(0), 2), bytes(payload, 2)]);
const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519',
  x: anchor.issuer_public_b64 }, format: 'jwk' });
const digest = data => 'sha256:' + createHash('sha256').update(data).digest('hex');
console.log(JSON.stringify({ signature_valid_under_fixed_anchor: verify(null, preimage, key, signature),
  exact_manifest_digest: digest(Buffer.from(file.manifest_b64 ?? anchor.manifest_b64, 'base64url')),
  payload_digest: digest(payload),
  scope: 'Cryptographic byte agreement only; no schema, trust routing, status or component appraisal.' }));

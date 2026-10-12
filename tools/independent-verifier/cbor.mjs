// Strict deterministic CBOR (RFC 8949 section 4.2.1) decoder and a minimal
// encoder. Written from the RFC, no dependencies.
//
// Decoding distinguishes two failure classes:
//   CborMalformed     the bytes are not well-formed CBOR at all
//   CborNoncanonical  well-formed, but not the deterministic encoding
//                     (non-shortest argument, indefinite length, unsorted or
//                     duplicate map keys, non-shortest float, trailing bytes)

export class CborMalformed extends Error {}
export class CborNoncanonical extends Error {}

export class Tagged {
  constructor(tag, value) { this.tag = tag; this.value = value; }
}
export class Simple {
  constructor(value) { this.value = value; }
}

const MAX_DEPTH = 16;
const MAX_ITEMS = 4096;

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function halfToNumber(h) {
  const s = h & 0x8000 ? -1 : 1;
  const e = (h >> 10) & 0x1f;
  const f = h & 0x3ff;
  if (e === 0) return s * f * 2 ** -24;
  if (e === 31) return f ? NaN : s * Infinity;
  return s * (1 + f / 1024) * 2 ** (e - 15);
}

function numberToHalf(x) {
  // Returns the 16-bit pattern if x is exactly representable as binary16.
  if (Number.isNaN(x)) return 0x7e00;
  for (let h = 0; h < 0x10000; h++) {
    // 64k candidates; only called for floats, which never appear in valid
    // vectors, so the brute force costs nothing in practice.
    const v = halfToNumber(h);
    if (Object.is(v, x)) return h;
  }
  return null;
}

function float32Exact(x) {
  if (Number.isNaN(x)) return true;
  return Object.is(Math.fround(x), x);
}

export function decode(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let pos = 0;
  let items = 0;
  const utf8 = new TextDecoder('utf-8', { fatal: true });

  function need(n) {
    if (pos + n > buf.length) throw new CborMalformed('truncated');
  }

  function readArg(ai) {
    // Returns a BigInt argument, enforcing shortest form.
    if (ai < 24) return BigInt(ai);
    if (ai === 24) { need(1); const v = buf[pos]; pos += 1; if (v < 24) throw new CborNoncanonical('non-shortest argument'); return BigInt(v); }
    if (ai === 25) { need(2); const v = dv.getUint16(pos); pos += 2; if (v <= 0xff) throw new CborNoncanonical('non-shortest argument'); return BigInt(v); }
    if (ai === 26) { need(4); const v = dv.getUint32(pos); pos += 4; if (v <= 0xffff) throw new CborNoncanonical('non-shortest argument'); return BigInt(v); }
    if (ai === 27) { need(8); const v = dv.getBigUint64(pos); pos += 8; if (v <= 0xffffffffn) throw new CborNoncanonical('non-shortest argument'); return v; }
    if (ai === 31) throw new CborNoncanonical('indefinite length');
    throw new CborMalformed('reserved additional information');
  }

  function toLength(big) {
    if (big > BigInt(buf.length)) throw new CborMalformed('length exceeds input');
    return Number(big);
  }

  function item(depth) {
    if (depth > MAX_DEPTH) throw new CborMalformed('nesting too deep');
    if (++items > MAX_ITEMS) throw new CborMalformed('too many items');
    need(1);
    const ib = buf[pos]; pos += 1;
    const mt = ib >> 5;
    const ai = ib & 0x1f;
    if (mt === 7) {
      if (ai === 31) throw new CborMalformed('unexpected break');
      if (ai < 20) return new Simple(ai);
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      if (ai === 24) { need(1); const v = buf[pos]; pos += 1; if (v < 32) throw new CborMalformed('invalid simple'); return new Simple(v); }
      if (ai === 25) { need(2); const h = dv.getUint16(pos); pos += 2; return halfToNumber(h); }
      if (ai === 26) {
        need(4); const v = dv.getFloat32(pos); pos += 4;
        if (numberToHalf(v) !== null) throw new CborNoncanonical('non-shortest float');
        return v;
      }
      if (ai === 27) {
        need(8); const v = dv.getFloat64(pos); pos += 8;
        if (float32Exact(v)) throw new CborNoncanonical('non-shortest float');
        return v;
      }
      throw new CborMalformed('reserved simple encoding');
    }
    const arg = readArg(ai);
    switch (mt) {
      case 0: return arg <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(arg) : arg;
      case 1: { const v = -1n - arg; return v >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(v) : v; }
      case 2: { const n = toLength(arg); need(n); const v = buf.slice(pos, pos + n); pos += n; return v; }
      case 3: {
        const n = toLength(arg); need(n);
        let s;
        try { s = utf8.decode(buf.subarray(pos, pos + n)); } catch { throw new CborMalformed('invalid UTF-8'); }
        pos += n; return s;
      }
      case 4: {
        const n = toLength(arg); const out = [];
        for (let i = 0; i < n; i++) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        const n = toLength(arg); const out = new Map(); let prevKeyBytes = null;
        for (let i = 0; i < n; i++) {
          const start = pos;
          const k = item(depth + 1);
          const keyBytes = buf.subarray(start, pos);
          if (prevKeyBytes && compareBytes(prevKeyBytes, keyBytes) >= 0) {
            throw new CborNoncanonical('map keys unsorted or duplicated');
          }
          prevKeyBytes = keyBytes;
          const v = item(depth + 1);
          out.set(k, v);
        }
        return out;
      }
      case 6: return new Tagged(arg <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(arg) : arg, item(depth + 1));
      default: throw new CborMalformed('unreachable');
    }
  }

  const value = item(0);
  if (pos !== buf.length) throw new CborNoncanonical('trailing bytes');
  return value;
}

function head(mt, n) {
  const big = BigInt(n);
  if (big < 24n) return Uint8Array.of((mt << 5) | Number(big));
  if (big <= 0xffn) return Uint8Array.of((mt << 5) | 24, Number(big));
  if (big <= 0xffffn) { const b = new Uint8Array(3); b[0] = (mt << 5) | 25; new DataView(b.buffer).setUint16(1, Number(big)); return b; }
  if (big <= 0xffffffffn) { const b = new Uint8Array(5); b[0] = (mt << 5) | 26; new DataView(b.buffer).setUint32(1, Number(big)); return b; }
  const b = new Uint8Array(9); b[0] = (mt << 5) | 27; new DataView(b.buffer).setBigUint64(1, big); return b;
}

function concat(parts) {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// Minimal deterministic encoder: integers, byte strings, text strings,
// arrays and maps (keys sorted bytewise). Enough for Sig_structure.
export function encode(v) {
  if (v instanceof Uint8Array) return concat([head(2, v.length), v]);
  if (typeof v === 'string') { const b = new TextEncoder().encode(v); return concat([head(3, b.length), b]); }
  if (typeof v === 'number' || typeof v === 'bigint') {
    const big = BigInt(v);
    return big >= 0n ? head(0, big) : head(1, -1n - big);
  }
  if (Array.isArray(v)) return concat([head(4, v.length), ...v.map(encode)]);
  if (v instanceof Map) {
    const entries = [...v.entries()].map(([k, val]) => [encode(k), encode(val)]);
    entries.sort((a, b) => compareBytes(a[0], b[0]));
    return concat([head(5, entries.length), ...entries.flat()]);
  }
  throw new Error('unsupported CBOR value');
}

// Strict RFC 8259 JSON parser with duplicate-member detection, and an
// RFC 8785 (JCS) canonicalizer. Written from the RFCs, no dependencies.

export class JsonDuplicateKey extends Error {}
export class JsonSyntax extends Error {}

const MAX_DEPTH = 32;

export function parseStrict(text) {
  let i = 0;
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };
  const err = (m) => { throw new JsonSyntax(`${m} at ${i}`); };

  function value(depth) {
    if (depth > MAX_DEPTH) err('too deep');
    ws();
    const c = text[i];
    if (c === '{') return object(depth);
    if (c === '[') return array(depth);
    if (c === '"') return string();
    if (c === 't' && text.startsWith('true', i)) { i += 4; return true; }
    if (c === 'f' && text.startsWith('false', i)) { i += 5; return false; }
    if (c === 'n' && text.startsWith('null', i)) { i += 4; return null; }
    return number();
  }

  function object(depth) {
    i++; const out = Object.create(null); const seen = new Set();
    ws();
    if (text[i] === '}') { i++; return out; }
    for (;;) {
      ws();
      if (text[i] !== '"') err('expected member name');
      const k = string();
      if (seen.has(k)) throw new JsonDuplicateKey(k);
      seen.add(k);
      ws();
      if (text[i] !== ':') err('expected colon');
      i++;
      out[k] = value(depth + 1);
      ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; return out; }
      err('expected , or }');
    }
  }

  function array(depth) {
    i++; const out = [];
    ws();
    if (text[i] === ']') { i++; return out; }
    for (;;) {
      out.push(value(depth + 1));
      ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === ']') { i++; return out; }
      err('expected , or ]');
    }
  }

  function string() {
    i++; let s = '';
    for (;;) {
      if (i >= text.length) err('unterminated string');
      const c = text[i];
      const code = c.charCodeAt(0);
      if (c === '"') { i++; return s; }
      if (code < 0x20) err('control character in string');
      if (c === '\\') {
        const e = text[i + 1];
        const map = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        if (e in map) { s += map[e]; i += 2; continue; }
        if (e === 'u') {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) err('bad unicode escape');
          s += String.fromCharCode(parseInt(hex, 16)); i += 6; continue;
        }
        err('bad escape');
      }
      s += c; i++;
    }
  }

  function number() {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m || m[0] === '' || m[0] === '-') err('unexpected token');
    i += m[0].length;
    const n = Number(m[0]);
    if (!Number.isFinite(n)) err('number out of range');
    return n;
  }

  const v = value(0);
  ws();
  if (i !== text.length) err('trailing content');
  return v;
}

// RFC 8785 serialization. Object members are sorted by UTF-16 code units,
// numbers use the ECMAScript Number-to-String rules, strings use the
// JSON.stringify escaping, which matches JCS section 3.2.2.2.
export function canonicalize(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite number');
    return Object.is(v, -0) ? '0' : String(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  throw new Error('unsupported JSON value');
}

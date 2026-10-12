/** Optional Node.js cross-check of persisted fixtures; no Python imports. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const hash = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const node = (left, right) => hash(Buffer.from([1]), left, right);
const formatted = value => `sha256:${value.toString('hex')}`;

// JS's default string ordering uses UTF-16. Compare scalar values explicitly.
function codePointCompare(a, b) {
  const left = Array.from(a, c => c.codePointAt(0));
  const right = Array.from(b, c => c.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function quoted(value) {
  // JSON.stringify handles quotes, backslashes and short control escapes.
  // Escape non-printable ASCII/BMP code units, including surrogate pairs.
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g,
    c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function serialize(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'string') return quoted(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('outside integer profile');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`;
  if (typeof value !== 'object') throw new Error('not JSON');
  return `{${Object.keys(value).sort(codePointCompare)
    .map(key => `${quoted(key)}:${serialize(value[key])}`).join(',')}}`;
}

function canonical(claim) {
  if (claim === null || typeof claim !== 'object' || Array.isArray(claim)) {
    throw new Error('claim must be an object');
  }
  return Buffer.from(serialize(claim), 'ascii');
}

function decode(value) {
  if (typeof value !== 'string' || value.length !== 71 ||
      !/^sha256:[0-9a-f]{64}$/.test(value)) throw new Error('malformed hash');
  return Buffer.from(value.slice(7), 'hex');
}

function split(count) {
  let n = 1;
  while (n * 2 < count) n *= 2;
  return n;
}

function treeRoot(leaves) {
  if (leaves.length < 1) throw new Error('empty tree');
  if (leaves.length === 1) return leaves[0];
  const n = split(leaves.length);
  return node(treeRoot(leaves.slice(0, n)), treeRoot(leaves.slice(n)));
}

function verify(claim, receipt) {
  try {
    if (receipt === null || typeof receipt !== 'object') return false;
    const { leaf_index: index, leaf_count: count, audit_path: path } = receipt;
    if (!Number.isSafeInteger(index) || !Number.isSafeInteger(count) ||
        index < 0 || count < 1 || index >= count || !Array.isArray(path)) return false;
    const siblings = path.map(decode);
    let consumed = 0;
    const leaf = hash(Buffer.from([0]), canonical(claim));
    // Recursive RFC 6962 split: proof siblings consumed bottom-up. This uses
    // neither Python's fn/sn verifier nor the fixture generator at runtime.
    function reconstruct(position, size) {
      if (size === 1) return leaf;
      const n = split(size);
      const leftBranch = position < n;
      const child = leftBranch ? reconstruct(position, n) : reconstruct(position - n, size - n);
      if (consumed >= siblings.length) throw new Error('short proof');
      const sibling = siblings[consumed++];
      return leftBranch ? node(child, sibling) : node(sibling, child);
    }
    const actual = reconstruct(index, count);
    return consumed === siblings.length && actual.equals(decode(receipt.merkle_root));
  } catch {
    return false;
  }
}

let accepted = 0;
let rejected = 0;
for (const name of readdirSync(here).filter(name => /^\d\d-.*\.json$/.test(name)).sort()) {
  const vector = JSON.parse(readFileSync(join(here, name), 'utf8'));
  const expected = vector.expected.tr_anc_002 === 'pass';
  assert.equal(verify(vector.claim, vector.receipt), expected, name);
  if (expected) {
    const bytes = canonical(vector.claim);
    const construction = vector.construction;
    assert.equal(bytes.toString('ascii'), construction.canonical_ascii, `${name}: preimage`);
    assert.equal(formatted(hash(Buffer.from([0]), bytes)), construction.leaf_hash, `${name}: leaf`);
    const leaves = construction.ordered_leaf_hashes.map(decode);
    assert.equal(leaves.length, vector.receipt.leaf_count, `${name}: count`);
    assert.equal(formatted(leaves[vector.receipt.leaf_index]), construction.leaf_hash, `${name}: position`);
    assert.equal(formatted(treeRoot(leaves)), vector.receipt.merkle_root, `${name}: root`);
    accepted++;
  } else {
    rejected++;
  }
}
assert.equal(accepted, 9);
assert.equal(rejected, 18);
console.log(JSON.stringify({ vectors: accepted + rejected, accepted, rejected,
  canonical_preimages_checked: accepted, batch_roots_checked: accepted }));

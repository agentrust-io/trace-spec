// The behavior-trace vectors, run through this verifier. The expected results
// are the ones tests/test_behavior_trace.py holds the Python reference to.

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import {
  BEHAVIOR_BLOCK_CODES,
  BEHAVIOR_MAX_BLOCKS,
  BEHAVIOR_RUN_CODES,
  blockDigest,
  bundleSchemaViolations,
  recordSchemaViolations,
  TraceVerificationError,
  verifyRun,
} from "../dist/index.js";
import { validateBlock } from "../dist/generated/block-validator.js";
import { jsonEqual } from "../dist/text.js";

const DIR = join(dirname(dirname(dirname(fileURLToPath(import.meta.url)))), "examples", "behavior-trace");
const VECTORS = readdirSync(DIR)
  .filter((name) => name.endsWith(".json"))
  .sort()
  .map((name) => ({ name, ...JSON.parse(readFileSync(join(DIR, name), "utf8")) }));
const VALID = VECTORS.filter((v) => v.expected.codes.length === 0);

test("all vectors were found", () => {
  assert.equal(VECTORS.length, 51);
  assert.equal(VALID.length, 9);
});

for (const v of VECTORS) {
  test(`vector ${v.name}`, async () => {
    assert.deepEqual(await verifyRun(v.blocks, v.pinned_keys), v.expected);
  });
}

test("every code has at least two vectors, and the code lists match", () => {
  const seen = {};
  for (const v of VECTORS) {
    for (const code of v.expected.codes) {
      seen[code] = (seen[code] ?? 0) + 1;
    }
  }
  assert.deepEqual(Object.keys(seen).sort(), [...BEHAVIOR_BLOCK_CODES, ...BEHAVIOR_RUN_CODES].sort());
  assert.ok(Math.min(...Object.values(seen)) >= 2);
});

test("block digests match the run_id the Python generator wrote", async () => {
  let checked = 0;
  for (const v of VALID) {
    const start = v.blocks.find((b) => b.kind === "run_start");
    const others = v.blocks.filter((b) => b.kind !== "run_start");
    for (const b of others) {
      assert.equal(b.run_id, await blockDigest(start));
      checked++;
    }
  }
  assert.ok(checked > 0);
});

function leafPaths(node, path = []) {
  if (Array.isArray(node)) {
    return [path, ...node.flatMap((item, i) => leafPaths(item, [...path, i]))];
  }
  if (node !== null && typeof node === "object") {
    const own = path.length > 0 ? [path] : [];
    return [...own, ...Object.keys(node).flatMap((k) => leafPaths(node[k], [...path, k]))];
  }
  return [path];
}

function mutate(block, path) {
  const out = structuredClone(block);
  let parent = out;
  for (const step of path.slice(0, -1)) {
    parent = parent[step];
  }
  const last = path[path.length - 1];
  const value = parent[last];
  if (typeof value === "boolean") parent[last] = !value;
  else if (typeof value === "number") parent[last] = value + 1;
  else if (typeof value === "string") parent[last] = `${value}x`;
  else if (value === null) parent[last] = "x";
  else if (Array.isArray(value)) parent[last] = [...value, "x"];
  else parent[last] = { ...value, x: "x" };
  return out;
}

test("changing any member of a valid run rejects it", async () => {
  let checked = 0;
  for (const v of VALID) {
    for (const [i, block] of v.blocks.entries()) {
      const unsigned = Object.fromEntries(Object.entries(block).filter(([k]) => k !== "sig"));
      for (const path of leafPaths(unsigned)) {
        const blocks = v.blocks.with(i, mutate(block, path));
        const got = await verifyRun(blocks, v.pinned_keys);
        assert.equal(got.classification, "rejected", `${v.name} block ${i} ${path.join(".")}`);
        checked++;
      }
    }
  }
  assert.ok(checked > 100);
});

test("malformed arguments throw TraceVerificationError", async () => {
  for (const [blocks, pinned] of [[null, {}], [{}, {}], [[], null], [[], { cmcp: "x" }], [[], { cmcp: [{ kty: "EC" }] }]]) {
    await assert.rejects(verifyRun(blocks, pinned), TraceVerificationError);
  }
});

test("an empty run has no start, and a non-object block is schema_invalid", async () => {
  assert.deepEqual(await verifyRun([], {}), { classification: "rejected", codes: ["run_start_invalid"] });
  assert.deepEqual(await verifyRun(["x"], {}), { classification: "rejected", codes: ["schema_invalid"] });
});

const RUN_A = VECTORS.find((v) => v.name === "01-valid-two-edges");
assert.ok(RUN_A, "vector 01 not found");

test("an unknown edge in pinnedKeys is a configuration error", async () => {
  await assert.rejects(verifyRun(RUN_A.blocks, { ...RUN_A.pinned_keys, cmpc: [] }), TraceVerificationError);
});

test("pinned keys: duplicate, unused and empty lists", async () => {
  const pinned = RUN_A.pinned_keys;
  const doubled = { ...pinned, cmcp: [...pinned.cmcp, ...pinned.cmcp] };
  assert.equal((await verifyRun(RUN_A.blocks, doubled)).classification, "verified");
  const unused = { ...pinned, sandbox: pinned.cmcp };
  assert.equal((await verifyRun(RUN_A.blocks, unused)).classification, "verified");
  const empty = { ...pinned, cmcp: [] };
  assert.deepEqual((await verifyRun(RUN_A.blocks, empty)).codes, ["key_not_pinned"]);
});

function nested(depth) {
  let value = "x";
  for (let i = 0; i < depth; i++) value = [value];
  return value;
}

for (const where of ["body", "parents"]) {
  test(`deep nesting in ${where} is schema_invalid, not an exception`, async () => {
    const blocks = structuredClone(RUN_A.blocks);
    if (where === "body") blocks[2].body.deep = nested(100_000);
    else blocks[2].parents = [nested(100_000), nested(100_000)];
    assert.deepEqual(await verifyRun(blocks, RUN_A.pinned_keys), {
      classification: "rejected",
      codes: ["schema_invalid"],
    });
  });
}

test("jsonEqual compares JSON values deeply", () => {
  assert.equal(jsonEqual([1, [2, { a: [3] }]], [1, [2, { a: [3] }]]), true);
  assert.equal(jsonEqual({ a: 1, b: { c: [true, null] } }, { b: { c: [true, null] }, a: 1 }), true);
  assert.equal(jsonEqual({ a: 1 }, { a: 1, b: 2 }), false);
  assert.equal(jsonEqual({ a: 1, b: 2 }, { a: 1, c: 2 }), false);
  assert.equal(jsonEqual([1, 2], [2, 1]), false);
  assert.equal(jsonEqual([1], { 0: 1 }), false);
  assert.equal(jsonEqual("1", 1), false);
  assert.equal(jsonEqual(null, {}), false);
});

test("jsonEqual treats objects from another realm like local ones", () => {
  const other = vm.runInNewContext('({ a: [1, { b: "x" }] })');
  assert.equal(jsonEqual(other, { a: [1, { b: "x" }] }), true);
  assert.equal(jsonEqual(other, { a: [1, { b: "y" }] }), false);
});

test("jsonEqual on input nested past the stack throws RangeError", () => {
  assert.throws(() => jsonEqual(nested(1_000_000), nested(1_000_000)), RangeError);
});

test("maxBlocks limits the input", async () => {
  const n = RUN_A.blocks.length;
  await assert.rejects(verifyRun(RUN_A.blocks, RUN_A.pinned_keys, { maxBlocks: n - 1 }), TraceVerificationError);
  assert.deepEqual((await verifyRun(RUN_A.blocks, RUN_A.pinned_keys, { maxBlocks: n })).codes, []);
  assert.deepEqual((await verifyRun(RUN_A.blocks, RUN_A.pinned_keys, { maxBlocks: null })).codes, []);
  for (const bad of [-1, 1.5, true, "10"]) {
    await assert.rejects(verifyRun(RUN_A.blocks, RUN_A.pinned_keys, { maxBlocks: bad }), TraceVerificationError);
  }
  await assert.rejects(verifyRun(RUN_A.blocks, RUN_A.pinned_keys, "x"), TraceVerificationError);
});

test("maxBlocks null lifts the default limit", async () => {
  const junk = new Array(BEHAVIOR_MAX_BLOCKS + 1).fill("x");
  await assert.rejects(verifyRun(junk, {}), TraceVerificationError);
  assert.deepEqual((await verifyRun(junk, {}, { maxBlocks: null })).codes, ["schema_invalid"]);
});

test("a private or malformed pinned key is a configuration error", async () => {
  const jwk = RUN_A.pinned_keys.cmcp[0];
  for (const bad of [{ ...jwk, d: jwk.x }, { ...jwk, x: `${jwk.x}=` }, { ...jwk, x: "AAAA" }]) {
    await assert.rejects(verifyRun(RUN_A.blocks, { ...RUN_A.pinned_keys, cmcp: [bad] }), TraceVerificationError);
  }
});

test("a malformed signature encoding is schema_invalid", async () => {
  const blocks = structuredClone(RUN_A.blocks);
  blocks[2].sig.value = `!${blocks[2].sig.value.slice(1)}`;
  assert.deepEqual((await verifyRun(blocks, RUN_A.pinned_keys)).codes, ["schema_invalid"]);
});

test("several bad blocks give sorted codes", async () => {
  const blocks = structuredClone(RUN_A.blocks);
  blocks[1].body.model = "has a space";
  blocks[2].body.tool = "changed";
  blocks[3].edge = "sandbox";
  assert.deepEqual(await verifyRun(blocks, RUN_A.pinned_keys), {
    classification: "rejected",
    codes: ["key_not_pinned", "schema_invalid", "signature_invalid"],
  });
});

test("deep nesting in a Trust Record or bundle is a violation, not an exception", () => {
  const record = { cnf: { jwk: { kty: "OKP", deep: nested(100_000) } } };
  assert.ok(recordSchemaViolations(record).length > 0);
  const bundle = { statements: nested(100_000) };
  assert.ok(bundleSchemaViolations(bundle).length > 0);
});

test("only the block schema can reach jsonEqual", () => {
  // Ajv calls its deep-equality helper for uniqueItems, and for const or enum
  // with an object or array value. No other compiled schema may use those.
  const uses = (node) => {
    if (Array.isArray(node)) return node.some(uses);
    if (node === null || typeof node !== "object") return false;
    if (node.uniqueItems === true) return true;
    if (typeof node.const === "object" && node.const !== null) return true;
    if (Array.isArray(node.enum) && node.enum.some((v) => typeof v === "object" && v !== null)) return true;
    return Object.values(node).some(uses);
  };
  const schemaDir = join(dirname(DIR), "..", "schema");
  for (const name of ["trace-claim.json", "trace-revocation-bundle.json", "trace-revocation.json"]) {
    assert.equal(uses(JSON.parse(readFileSync(join(schemaDir, name), "utf8"))), false, name);
  }
  const block = JSON.parse(readFileSync(join(schemaDir, "behavior-trace-block-experimental-v1.json"), "utf8"));
  assert.equal(uses(block), true, "the guard should see the block schema's uniqueItems");
});

for (const where of ["block", "signature"]) {
  test(`symbol-keyed ${where} is schema_invalid, not an exception`, async () => {
    const blocks = structuredClone(RUN_A.blocks);
    const target = where === "block" ? blocks[0] : blocks[0].sig;
    target[Symbol("extra")] = "value";
    assert.deepEqual(await verifyRun(blocks, RUN_A.pinned_keys), {
      classification: "rejected", codes: ["schema_invalid"],
    });
  });
}

test("the block validator stops at its first failure", () => {
  // Compiled without allErrors: an array over maxItems is refused before
  // uniqueItems compares its pairs (quadratic in the array's length).
  const block = structuredClone(RUN_A.blocks[1]);
  block.parents = Array.from({ length: 300 }, () => 0);
  block.unknown = true;
  assert.equal(validateBlock(block), false);
  assert.equal(validateBlock.errors.length, 1);
});

test("an oversized block is refused quickly", async () => {
  // Each took 20 s or more: a long member name was rebuilt for every value
  // canonicalized, and uniqueItems compared every pair of an oversized array.
  const name = { ["x".repeat(400_000)]: new Array(400_000).fill(0) };
  const parents = structuredClone(RUN_A.blocks[0]);
  parents.parents = Array.from({ length: 160_000 }, (_, i) => i);
  for (const block of [name, parents]) {
    const started = performance.now();
    assert.deepEqual(await verifyRun([block], RUN_A.pinned_keys), {
      classification: "rejected", codes: ["schema_invalid"],
    });
    assert.ok(performance.now() - started < 2000, "an oversized block took too long to refuse");
  }
});

// The behavior-trace vectors, run through this verifier. The expected results
// are the ones tests/test_behavior_trace.py holds the Python reference to.

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  BEHAVIOR_BLOCK_CODES,
  BEHAVIOR_RUN_CODES,
  blockDigest,
  TraceVerificationError,
  verifyRun,
} from "../dist/index.js";

const DIR = join(dirname(dirname(dirname(fileURLToPath(import.meta.url)))), "examples", "behavior-trace");
const VECTORS = readdirSync(DIR)
  .filter((name) => name.endsWith(".json"))
  .sort()
  .map((name) => ({ name, ...JSON.parse(readFileSync(join(DIR, name), "utf8")) }));
const VALID = VECTORS.filter((v) => v.expected.codes.length === 0);

test("all vectors were found", () => {
  assert.equal(VECTORS.length, 26);
  assert.equal(VALID.length, 4);
});

for (const v of VECTORS) {
  test(`vector ${v.name}`, async () => {
    assert.deepEqual(await verifyRun(v.blocks, v.pinned_keys), v.expected);
  });
}

test("every code has two vectors, and the code lists match", () => {
  const seen = {};
  for (const v of VECTORS) {
    for (const code of v.expected.codes) {
      seen[code] = (seen[code] ?? 0) + 1;
    }
  }
  const all = [...BEHAVIOR_BLOCK_CODES, ...BEHAVIOR_RUN_CODES];
  assert.deepEqual(seen, Object.fromEntries(all.map((code) => [code, 2])));
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

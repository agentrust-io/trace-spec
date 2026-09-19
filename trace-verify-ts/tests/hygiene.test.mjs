// What the build must not contain, and what every exported function must survive.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as trace from "../dist/index.js";
import { SCHEMA_DIGESTS, TraceVerificationError } from "../dist/index.js";

const PACKAGE = dirname(dirname(fileURLToPath(import.meta.url)));
const REPOSITORY = dirname(PACKAGE);

function sources(directory) {
  const out = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      out.push(...sources(path));
    } else if (entry.name.endsWith(".js") || entry.name.endsWith(".d.ts")) {
      out.push(path);
    }
  }
  return out;
}

test("the build imports nothing: no platform module, no dependency, no network", () => {
  const forbidden = [/from\s+"node:/, /require\s*\(/, /\bfetch\s*\(/, /XMLHttpRequest/, /import\s*\(/];
  for (const path of sources(join(PACKAGE, "dist"))) {
    const text = readFileSync(path, "utf8");
    for (const pattern of forbidden) {
      assert.equal(pattern.test(text), false, `${path} matches ${pattern}`);
    }
    for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
      assert.ok(match[1].startsWith("."), `${path} imports ${match[1]}, which is not a relative path`);
    }
  }
});

test("the compiled validators are the repository's schemas", () => {
  for (const [name, expected] of Object.entries(SCHEMA_DIGESTS)) {
    const bytes = readFileSync(join(REPOSITORY, "schema", name));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), expected, name);
  }
  for (const name of ["trace-claim.json", "trace-revocation-bundle.json", "trace-revocation.json"]) {
    assert.ok(Object.hasOwn(SCHEMA_DIGESTS, name), `${name} is not among the compiled schemas`);
  }
});

test("every exported function refuses junk with a TraceVerificationError, never a TypeError", async () => {
  const junk = [
    undefined,
    null,
    true,
    0,
    -1,
    Number.NaN,
    "",
    "junk",
    [],
    {},
    { __proto__: { eat_profile: "tag:agentrust-io.com,2026:trace-v0.2" } },
    Object.create(null),
    new Map(),
    Symbol.iterator,
  ];
  const skip = new Set(["FAILURE_CODES", "NO_CHECK", "TRACE_PROFILE_V0_2", "JCS_SAFE_INTEGER",
    "DELEGATION_DIGEST_ALGORITHMS", "TraceVerificationError", "SCHEMA_DIGESTS"]);
  let exercised = 0;
  for (const [name, exported] of Object.entries(trace)) {
    if (skip.has(name) || typeof exported !== "function") {
      continue;
    }
    for (const [i, first] of junk.entries()) {
      for (const [j, second] of junk.entries()) {
        exercised++;
        try {
          await exported(first, second);
        } catch (error) {
          assert.ok(
            error instanceof TraceVerificationError,
            `${name}(junk[${i}], junk[${j}]) threw ${error?.name}: ${error?.message}`,
          );
        }
      }
    }
  }
  assert.ok(exercised > 0);
});

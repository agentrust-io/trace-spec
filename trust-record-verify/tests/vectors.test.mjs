// The repository's own conformance vectors, run through this verifier.
//
// Each vector states the outcome it expects before this code runs, so these are
// the same assertions the Python test suite makes about the same bytes. The
// revocation vectors additionally state an evidence block, and this checks it
// member by member: an outcome that is right for the wrong reason is not right.

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { parentRecordHash, TraceVerificationError, verifyRecord } from "../dist/index.js";

const EXAMPLES = join(dirname(dirname(dirname(fileURLToPath(import.meta.url)))), "examples");

function vectors(directory) {
  const path = join(EXAMPLES, directory);
  return readdirSync(path)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => ({ name, vector: JSON.parse(readFileSync(join(path, name), "utf8")) }));
}

async function outcome(promise) {
  try {
    return { rejected: false, result: await promise };
  } catch (error) {
    assert.ok(error instanceof TraceVerificationError, `unexpected error type: ${error?.stack ?? error}`);
    return { rejected: true, code: error.code };
  }
}

test("canonicalization boundary vectors", async (t) => {
  for (const { name, vector } of vectors("canonicalization-boundary")) {
    await t.test(name, async () => {
      // These vectors fix the canonical form, not the clock: the freshness bound
      // is the caller's and is disabled so the vector tests what it is about.
      const got = await outcome(
        verifyRecord(vector.record, {
          trustedKey: vector.trusted_key,
          now: vector.record.iat,
          maxAgeSeconds: null,
        }),
      );
      if (vector.expected.outcome === "verified") {
        assert.equal(got.rejected, false, `expected verified, got ${got.code}`);
        assert.equal(got.result.revocation.outcome, "no_check_performed");
      } else {
        assert.equal(got.rejected, true, "expected a rejection");
        assert.equal(got.code, vector.expected.failure);
      }
    });
  }
});

test("revocation bundle vectors", async (t) => {
  for (const { name, vector } of vectors("revocation-bundle")) {
    await t.test(name, async () => {
      const context = vector.context;
      for (const record of vector.records) {
        const got = await outcome(
          verifyRecord(record, {
            trustedKey: context.trusted_key,
            now: context.now,
            revocationBundle: context.bundle,
            trustedBundleKeys: context.trusted_bundle_keys ?? [],
            maxBundleAgeSeconds: context.max_bundle_age_seconds,
            maxFutureSkewSeconds: context.max_future_skew_seconds,
          }),
        );
        assert.equal(got.rejected, vector.expected.rejected, `codes: ${got.code ?? "none"}`);
        if (vector.expected.rejected) {
          // A vector may list more codes than a verifier reports: the extra ones
          // name the property the vector demonstrates, not a second failure.
          assert.ok(
            vector.expected.codes.includes(got.code),
            `${got.code} is not among ${vector.expected.codes.join(", ")}`,
          );
          continue;
        }
        const revocation = got.result.revocation;
        assert.equal(revocation.outcome, vector.expected.outcome);
        assert.equal(revocation.cause, vector.expected.cause);
        for (const [member, value] of Object.entries(vector.expected.evidence ?? {})) {
          assert.deepEqual(revocation.evidence[member], value, `evidence.${member}`);
        }
      }
    });
  }
});

test("delegation-link vectors agree on the chain digest of section 3.1.3", async (t) => {
  // The chain walk is not normative in v0.2 and this package does not implement
  // it. The pre-image is normative, so every link a vector states is recomputed
  // here against the record the vector holds.
  let checked = 0;
  for (const { name, vector } of vectors("delegation-link")) {
    if (!Array.isArray(vector.records)) {
      continue;
    }
    await t.test(name, async () => {
      const byDigest = new Map();
      for (const record of vector.records) {
        for (const algorithm of ["sha256", "sha384"]) {
          byDigest.set(await parentRecordHash(record, algorithm), record);
        }
      }
      for (const record of vector.records) {
        const stated = record.delegation?.parent_record_hash;
        if (stated === undefined || !byDigest.has(stated)) {
          continue;
        }
        const parent = byDigest.get(stated);
        const algorithm = stated.slice(0, stated.indexOf(":"));
        assert.equal(await parentRecordHash(parent, algorithm), stated);
        checked++;
      }
    });
  }
  assert.ok(checked > 0, "no delegation link resolved, so nothing was checked");
});

test("trustedKeySource names the key that verified, even when the record embeds the same key", async () => {
  let picked;
  for (const { vector } of vectors("canonicalization-boundary")) {
    const got = await outcome(
      verifyRecord(vector.record, { trustedKey: vector.trusted_key, now: vector.record.iat, maxAgeSeconds: null }),
    );
    if (!got.rejected) {
      picked = { vector, result: got.result };
      break;
    }
  }
  assert.ok(picked, "no canonicalization-boundary vector verifies");
  const { vector, result } = picked;
  assert.equal(result.trustedKeySource, "caller");
  const embedded = await verifyRecord(vector.record, {
    allowEmbeddedKey: true,
    now: vector.record.iat,
    maxAgeSeconds: null,
  });
  assert.equal(embedded.trustedKeySource, "record");
  // The same key both ways, so the thumbprint cannot tell the two results apart
  // and only trustedKeySource can; the differential compares it for that reason.
  assert.equal(embedded.trustedKeyThumbprint, result.trustedKeyThumbprint);
});

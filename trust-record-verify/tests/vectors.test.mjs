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
import vm from "node:vm";

test("platform runtime copies retain every own JSON member without changing prototypes", async () => {
  for (const value of [null, 7, "value", { flag: true }]) {
    const runtime = JSON.parse('{"measurement":"m","__proto__":null,"nested":{"__proto__":7}}');
    Object.defineProperty(runtime, "__proto__", { value, enumerable: true });
    const before = JSON.stringify(runtime);
    let observed;
    const result = await checkPlatformMeasurement({ runtime }, (copy) => {
      observed = copy;
      return { measurement: "m", layers: { boot: "established" } };
    });
    assert.equal(result.outcome, "appraised");
    assert.equal(Object.getPrototypeOf(observed), Object.prototype);
    assert.equal(Object.hasOwn(observed, "__proto__"), true);
    assert.equal(Object.hasOwn(observed.nested, "__proto__"), true);
    assert.equal(JSON.stringify(observed), before);
    assert.notEqual(observed.nested, runtime.nested);
    assert.equal(JSON.stringify(runtime), before);
  }
});

test("platform layer results retain legal own names in membership and serialization", async () => {
  for (const name of ["boot", "__proto__", "constructor", "toString"]) {
    for (const status of ["established", "layer_not_measured"]) {
      const result = await checkPlatformMeasurement({ runtime: { measurement: "m" } }, () => ({
        measurement: "m", layers: Object.fromEntries([[name, status]]),
      }));
      assert.equal(result.outcome, "appraised");
      assert.equal(Object.hasOwn(result.layers, name), true);
      const expected = status === "established"
        ? { outcome: "established", cause: null }
        : { outcome: "not_established", cause: status };
      assert.deepEqual(result.layers[name], expected);
      assert.deepEqual(JSON.parse(JSON.stringify(result.layers)), Object.fromEntries([[name, expected]]));
      assert.equal(Object.getPrototypeOf(result.layers), Object.prototype);
    }
  }
});

import {
  ACCEPTED_PROFILES,
  checkCitations,
  checkPlatformMeasurement,
  LAYER_STATUSES,
  NOT_ATTEMPTED,
  parentRecordHash,
  SURFACES,
  TRACE_PROFILE_V0_2,
  TraceVerificationError,
  verifyRecord,
} from "../dist/index.js";

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

async function aVerifyingVector() {
  for (const { vector } of vectors("canonicalization-boundary")) {
    const options = { trustedKey: vector.trusted_key, now: vector.record.iat, maxAgeSeconds: null };
    const got = await outcome(verifyRecord(vector.record, options));
    if (!got.rejected) {
      return { vector, options, result: got.result };
    }
  }
  assert.fail("no canonicalization-boundary vector verifies");
}

test("the signature's encoding is judged before the schema, as the reference judges it", async () => {
  const { vector, options } = await aVerifyingVector();
  const signature = vector.record.signature;
  const respelled = {
    padded: `${signature}==`,
    "standard alphabet": `${signature.slice(0, -2)}+${signature.slice(-1)}`,
    "trailing newline": `${signature}\n`,
    "impossible length": signature.slice(0, -1),
  };
  // Each of these also fails the schema's pattern or would fail verification.
  // The encoding is the first thing wrong with them, and both implementations say so.
  for (const [name, value] of Object.entries(respelled)) {
    const got = await outcome(verifyRecord({ ...vector.record, signature: value }, options));
    assert.deepEqual(got, { rejected: true, code: "signature_malformed" }, name);
  }
  // The empty string decodes, to no bytes, so the schema's pattern is what refuses it.
  await assert.rejects(verifyRecord({ ...vector.record, signature: "" }, options), (error) => {
    assert.ok(error instanceof TraceVerificationError);
    assert.equal(error.code, "schema_invalid");
    assert.equal(error.path, "signature");
    return true;
  });
});

test("a record, its options and a revocation set made in another realm verify as they do here", async () => {
  const { vector, options, result } = await aVerifyingVector();
  // Another realm's JSON.parse returns objects and arrays of that realm, which is
  // what a record read in a frame or a worker is to the code that verifies it.
  const parse = vm.runInNewContext("JSON.parse");
  const record = parse(JSON.stringify(vector.record));
  const foreignOptions = parse(JSON.stringify(options));
  assert.notEqual(Object.getPrototypeOf(record), Object.prototype);
  const foreign = await verifyRecord(record, foreignOptions);
  assert.deepEqual(foreign, result);

  const makeSet = vm.runInNewContext("(items) => new Set(items)");
  const unrelated = makeSet(["not-this-key"]);
  assert.equal(unrelated instanceof Set, false);
  const here = await verifyRecord(vector.record, { ...options, revocation: new Set(["not-this-key"]) });
  assert.equal(here.revocation.outcome, "verified");
  assert.deepEqual(await verifyRecord(vector.record, { ...options, revocation: unrelated }), here);
  const revoking = makeSet([result.trustedKeyThumbprint]);
  assert.deepEqual(await outcome(verifyRecord(vector.record, { ...options, revocation: revoking })), {
    rejected: true,
    code: "key_revoked",
  });
  // An object that answers `has` is not a Set, here or there.
  const impostor = { [Symbol.toStringTag]: "Set", has: () => false, size: 0 };
  assert.deepEqual(await outcome(verifyRecord(vector.record, { ...options, revocation: impostor })), {
    rejected: true,
    code: "invalid_argument",
  });
});

function verifying() {
  const found = vectors("canonicalization-boundary").find(({ vector }) => vector.expected.outcome === "verified");
  assert.ok(found, "no verifying vector in canonicalization-boundary");
  return found.vector;
}

test("a verified result reports the profile and the complete accepted set (section 3.3)", async () => {
  const vector = verifying();
  const result = await verifyRecord(vector.record, {
    trustedKey: vector.trusted_key,
    now: vector.record.iat,
    maxAgeSeconds: null,
  });
  assert.equal(result.profile, TRACE_PROFILE_V0_2);
  assert.deepEqual([...result.acceptedProfiles], [...ACCEPTED_PROFILES]);
  assert.deepEqual([...ACCEPTED_PROFILES], [TRACE_PROFILE_V0_2]);
  assert.ok(Object.isFrozen(ACCEPTED_PROFILES));
});

test("an inherited member does not stand in for an absent one, at any depth", async (t) => {
  // A record from another realm is a plain object; that realm's Object.prototype
  // carries the member, so a prototype-chain read finds it and an own read does
  // not. The signature pre-image takes own members only, and so does the schema
  // (ownProperties), so every member the schema requires must be the record's own.
  const vector = verifying();
  const options = { trustedKey: vector.trusted_key, now: vector.record.iat, maxAgeSeconds: null };
  const inherit = (path, enumerable) =>
    vm.runInNewContext(
      "(json, path, enumerable) => { const r = JSON.parse(json); const keys = path.split('.'); " +
        "const name = keys.pop(); const holder = keys.reduce((o, k) => o[k], r); " +
        "Object.defineProperty(Object.prototype, name, { value: holder[name], enumerable, configurable: true }); " +
        "delete holder[name]; return r; }",
    )(JSON.stringify(vector.record), path, enumerable);
  const rejected = async (record, accept) =>
    assert.rejects(verifyRecord(record, options), (e) => e instanceof TraceVerificationError && accept(e));
  // A required member is missing to the schema; eat_profile is read by own()
  // before the schema and has its own code. An optional member is absent from
  // the pre-image, so the signature no longer covers the record as signed.
  const schema = JSON.parse(readFileSync(join(dirname(EXAMPLES), "schema", "trace-claim.json"), "utf8"));
  const expected = (name) =>
    name === "eat_profile" ? "profile_missing" : schema.required.includes(name) ? "schema_invalid" : "signature_invalid";
  const members = Object.keys(vector.record).filter((name) => name !== "signature");
  assert.ok(schema.required.every((name) => members.includes(name)), "the vector carries every required member");
  for (const name of members) {
    for (const enumerable of [false, true]) {
      await t.test(`${name}${enumerable ? " (enumerable)" : ""}`, () =>
        rejected(inherit(name, enumerable), (e) => e.code === expected(name)),
      );
    }
  }
  await t.test("cnf.jwk, one level down", () =>
    rejected(inherit("cnf.jwk", false), (e) => e.code === "schema_invalid" && e.path === "cnf"),
  );
  await t.test("the same record with every member its own still verifies", async () => {
    const own = vm.runInNewContext("(json) => JSON.parse(json)")(JSON.stringify(vector.record));
    const result = await verifyRecord(own, options);
    assert.equal(result.profile, TRACE_PROFILE_V0_2);
  });
});

test("citation-resolution vectors", async (t) => {
  const items = vectors("citation-resolution");
  assert.equal(items.length, 16);
  for (const { name, vector } of items) {
    await t.test(name, async () => {
      const context = vector.context;
      let citationResolver = null;
      if (Object.hasOwn(context, "resolutions")) {
        const table = context.resolutions;
        citationResolver = (uri) => {
          if (!Object.hasOwn(table, uri)) {
            const err = new Error(uri);
            err.name = "KeyError";
            throw err;
          }
          return new Uint8Array(Buffer.from(table[uri].bytes_base64, "base64"));
        };
      }
      const got = await outcome(
        verifyRecord(vector.records[0], {
          trustedKey: context.trusted_key,
          now: context.now,
          maxAgeSeconds: context.max_age_seconds,
          maxFutureSkewSeconds: context.max_future_skew_seconds,
          citationResolver,
        }),
      );
      assert.equal(got.rejected, vector.expected.rejected);
      const citations = got.result.citations;
      assert.deepEqual(Object.keys(citations), Object.keys(vector.expected.citations));
      for (const [surface, expectedRow] of Object.entries(vector.expected.citations)) {
        assert.equal(citations[surface].outcome, expectedRow.outcome, `${surface}.outcome`);
        assert.equal(citations[surface].cause, expectedRow.cause, `${surface}.cause`);
        assert.deepEqual(citations[surface].evidence, expectedRow.evidence, `${surface}.evidence`);
      }
      assert.deepEqual(got.result.platformMeasurement, NOT_ATTEMPTED);
    });
  }
});

test("platform-measurement vectors", async (t) => {
  const items = vectors("platform-measurement");
  assert.equal(items.length, 16);
  for (const { name, vector } of items) {
    await t.test(name, async () => {
      const context = vector.context;
      let platformAppraiser = null;
      if (Object.hasOwn(context, "appraisals")) {
        const table = context.appraisals;
        platformAppraiser = (runtime) => {
          if (!Object.hasOwn(table, runtime.measurement)) {
            const err = new Error(runtime.measurement);
            err.name = "KeyError";
            throw err;
          }
          return structuredClone(table[runtime.measurement]);
        };
      }
      const got = await outcome(
        verifyRecord(vector.records[0], {
          trustedKey: context.trusted_key,
          now: context.now,
          maxAgeSeconds: context.max_age_seconds,
          maxFutureSkewSeconds: context.max_future_skew_seconds,
          platformAppraiser,
        }),
      );
      assert.equal(got.rejected, vector.expected.rejected);
      const expected = vector.expected.platform_measurement;
      const pm = got.result.platformMeasurement;
      assert.equal(pm.outcome, expected.outcome);
      assert.equal(pm.cause, expected.cause);
      assert.deepEqual(pm.evidence, expected.evidence);
      assert.deepEqual(pm.layers, expected.layers);
    });
  }
});

test("citationResolver and platformAppraiser run only after signature and freshness checks", async () => {
  const { vector } = vectors("citation-resolution").find(({ name }) => name === "16-all-three-resolved.json");
  const context = vector.context;
  const record = vector.records[0];
  const calls = [];
  const citationResolver = (uri) => {
    calls.push(["citation", uri]);
    return new Uint8Array([1, 2, 3]);
  };
  const platformAppraiser = (runtime) => {
    calls.push(["platform", runtime.measurement]);
    return { measurement: runtime.measurement, layers: { "pcr:0": "established" } };
  };

  const tampered = {
    ...record,
    signature: `${record.signature[0] === "A" ? "B" : "A"}${record.signature.slice(1)}`,
  };
  assert.deepEqual(
    await outcome(
      verifyRecord(tampered, {
        trustedKey: context.trusted_key,
        now: context.now,
        citationResolver,
        platformAppraiser,
      }),
    ),
    { rejected: true, code: "signature_invalid" },
  );
  assert.deepEqual(
    await outcome(
      verifyRecord(record, {
        trustedKey: context.trusted_key,
        now: context.now + 10 * 86400,
        maxAgeSeconds: 86400,
        citationResolver,
        platformAppraiser,
      }),
    ),
    { rejected: true, code: "record_stale" },
  );
  assert.deepEqual(calls, []);

  const verified = await verifyRecord(record, {
    trustedKey: context.trusted_key,
    now: context.now,
    citationResolver,
    platformAppraiser,
  });
  assert.equal(verified.platformMeasurement.outcome, "appraised");
  assert.equal(calls.length, 4);
  assert.equal(calls[3][0], "platform");
});

test("citationResolver and platformAppraiser validate arguments and isolate caller state", async () => {
  const { vector } = vectors("platform-measurement").find(({ name }) => name === "15-rc13-layer-not-measured.json");
  const context = vector.context;
  const record = vector.records[0];

  for (const bad of ["not-a-fn", 123, true, {}, []]) {
    assert.deepEqual(await outcome(verifyRecord({}, { citationResolver: bad })), {
      rejected: true,
      code: "invalid_argument",
    });
    assert.deepEqual(await outcome(verifyRecord({}, { platformAppraiser: bad })), {
      rejected: true,
      code: "invalid_argument",
    });
    assert.deepEqual(await outcome(checkCitations(record, bad)), {
      rejected: true,
      code: "invalid_argument",
    });
    assert.deepEqual(await outcome(checkPlatformMeasurement(record, bad)), {
      rejected: true,
      code: "invalid_argument",
    });
  }

  for (const badRecord of [null, undefined, "str", 1, [], true]) {
    assert.deepEqual(await outcome(checkCitations(badRecord, null)), {
      rejected: true,
      code: "record_not_object",
    });
    assert.deepEqual(await outcome(checkPlatformMeasurement(badRecord, null)), {
      rejected: true,
      code: "record_not_object",
    });
  }

  // Deep-copy isolation: mutating runtime inside platformAppraiser does not mutate record.runtime.
  const copy = structuredClone(record);
  const before = structuredClone(record);
  const pm = await checkPlatformMeasurement(copy, (runtime) => {
    const m = runtime.measurement;
    runtime.measurement = "sha256:" + "f".repeat(64);
    return structuredClone(context.appraisals[m]);
  });
  assert.equal(pm.outcome, "appraised");
  assert.deepEqual(copy, before);

  // Cross-realm Uint8Array is accepted by checkCitations, and non-bytes is reported as an outcome.
  const foreignBytes = vm.runInNewContext("new Uint8Array([97, 98, 99])");
  const cited = { appraisal: { policy_ref: "https://policy.example/v1" } };
  const resolved = await checkCitations(cited, () => foreignBytes);
  assert.equal(resolved["appraisal.policy_ref"].outcome, "resolved");
  assert.equal(resolved["appraisal.policy_ref"].evidence.bytes, 3);

  const nonBytes = await checkCitations(cited, () => "not-bytes");
  assert.equal(nonBytes["appraisal.policy_ref"].outcome, "unresolvable");
  assert.equal(nonBytes["appraisal.policy_ref"].cause, "resolver_returned_non_bytes");

  assert.equal(SURFACES.length, 4);
  assert.equal(LAYER_STATUSES.length, 4);
});

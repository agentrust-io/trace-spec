// Unit tests for the pieces the verifier is assembled from: RFC 8785
// canonicalization, base64url, RFC 7638 thumbprints and the profile cutover.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import {
  bundleDigest,
  canonicalJson,
  checkRevocationBundle,
  decodeBase64url,
  encodeBase64url,
  jwkThumbprint,
  parentRecordHash,
  TRACE_PROFILE_V0_2,
  TraceVerificationError,
  verifyDelegationLink,
  verifyRecord,
} from "../dist/index.js";
import { importEcdsa } from "../dist/crypto.js";

async function rejects(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof TraceVerificationError, `expected a TraceVerificationError, got ${error}`);
    assert.equal(error.code, code);
    return true;
  });
}

test("canonicalJson orders members by UTF-16 code unit", () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  // The RFC 8785 sort is over UTF-16 code units. A supplementary-plane key
  // therefore sorts before U+FB33, which code-point order puts first.
  assert.equal(canonicalJson({ "\u{10480}": 1, "דּ": 2 }), '{"\u{10480}":1,"דּ":2}');
});

test("canonicalJson emits non-ASCII literally and escapes only what RFC 8785 escapes", () => {
  assert.equal(canonicalJson("modèle"), '"modèle"');
  assert.equal(canonicalJson("\b\f\n\r\t\"\\"), '"\\u0001\\b\\f\\n\\r\\t\\"\\\\"');
  assert.equal(canonicalJson(""), '""');
});

test("canonicalJson serializes numbers in the ES6 form", () => {
  assert.equal(canonicalJson(1), "1");
  assert.equal(canonicalJson(-0), "0");
  assert.equal(canonicalJson(1e-7), "1e-7");
  assert.equal(canonicalJson(0.1), "0.1");
  assert.equal(canonicalJson(9007199254740991), "9007199254740991");
});

test("canonicalJson refuses what has no canonical form", () => {
  assert.throws(() => canonicalJson(Number.NaN), TraceVerificationError);
  assert.throws(() => canonicalJson(Number.POSITIVE_INFINITY), TraceVerificationError);
  // Above 2^53-1 an integer literal is no longer the number it names.
  assert.throws(() => canonicalJson(9007199254740992), TraceVerificationError);
  // A lone surrogate has no UTF-8 encoding; encoding it would map two strings to one.
  assert.throws(() => canonicalJson("\ud800"), TraceVerificationError);
  assert.throws(() => canonicalJson({ "\ud800": 1 }), TraceVerificationError);
  assert.throws(() => canonicalJson(undefined), TraceVerificationError);
  assert.throws(() => canonicalJson(new Date(0)), TraceVerificationError);
  const cycle = {};
  cycle.self = cycle;
  assert.throws(() => canonicalJson(cycle), TraceVerificationError);
});

test("canonicalJson refuses a symbol-keyed member rather than dropping it", async () => {
  const sym = Symbol("s");
  const refused = (error) =>
    error instanceof TraceVerificationError && error.code === "canonicalization_failed";
  for (const value of [{ a: 1, [sym]: 2 }, { a: { b: 1, [sym]: 2 } }, [{ [sym]: 1 }]]) {
    assert.throws(() => canonicalJson(value), refused);
  }
  await rejects(parentRecordHash({ a: 1, [sym]: 2 }), "canonicalization_failed");
  // The same object without the symbol has a canonical form, so the refusal is
  // the symbol's and not the shape's.
  assert.equal(canonicalJson({ a: { b: 1 } }), '{"a":{"b":1}}');
});

test("encodeBase64url takes a Uint8Array and nothing else that views a buffer", () => {
  const refused = (error) => error instanceof TraceVerificationError && error.code === "invalid_argument";
  assert.equal(encodeBase64url(new Uint8Array([1, 2, 3])), "AQID");
  assert.equal(encodeBase64url(Buffer.from([1, 2, 3])), "AQID");
  // A Uint16Array holds 16-bit values: iterated as bytes it would encode
  // [1, 2] as "AQI" and lose two of its four bytes. A DataView is a view but
  // not iterable, so the loop would reach a native TypeError.
  for (const bad of [new Uint16Array([1, 2]), new DataView(new ArrayBuffer(4)), new ArrayBuffer(3), [1, 2, 3], "AQID"]) {
    assert.throws(() => encodeBase64url(bad), refused);
  }
});

test("encodeBase64url takes a Uint8Array made in another realm, and still nothing else", () => {
  const refused = (error) => error instanceof TraceVerificationError && error.code === "invalid_argument";
  // Another realm has its own Uint8Array, as a frame or a worker does in a
  // browser, so `instanceof` against this realm's constructor is false for it.
  const foreign = vm.runInNewContext("new Uint8Array([1, 2, 3])");
  assert.equal(foreign instanceof Uint8Array, false);
  assert.equal(encodeBase64url(foreign), "AQID");
  for (const source of ["new Uint16Array([1, 2])", "new DataView(new ArrayBuffer(4))", "new ArrayBuffer(3)", "[1, 2, 3]"]) {
    assert.throws(() => encodeBase64url(vm.runInNewContext(source)), refused, source);
  }
  // An object that only says it is one: the tag is its own property, and it
  // iterates, so a test on `Object.prototype.toString` would encode it.
  const impostor = { [Symbol.toStringTag]: "Uint8Array", length: 3, *[Symbol.iterator]() { yield* [1, 2, 3]; } };
  assert.equal(Object.prototype.toString.call(impostor), "[object Uint8Array]");
  assert.throws(() => encodeBase64url(impostor), refused);
});

test("verifyDelegationLink takes a plain options object, as verifyRecord does", async () => {
  class Options {}
  for (const options of [[], new Date(0), new Options(), Object.create({ supportedDigestAlgorithms: [] }), null, "sha256", 1]) {
    await rejects(verifyDelegationLink({}, {}, options), "invalid_argument");
  }
});

test("parentRecordHash, verifyDelegationLink and bundleDigest refuse non-object inputs", async () => {
  const validChild = {
    delegation: {
      parent_record_hash: "sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      credential_id: "cred-1",
    },
  };
  for (const bad of [null, undefined, 123, true, false, "record", [1, 2], new Date(0)]) {
    await rejects(parentRecordHash(bad), "record_not_object");
    await rejects(verifyDelegationLink(bad, {}), "record_not_object");
    await rejects(verifyDelegationLink({}, bad), "record_not_object");
    await rejects(verifyDelegationLink(validChild, bad), "record_not_object");
    await rejects(bundleDigest(bad), "invalid_argument");
  }
  await rejects(parentRecordHash(123, "md5"), "delegation_algorithm_unsupported");
});

test("checkRevocationBundle and verifyRecord report non-plain bundle objects as bundle_malformed", async () => {
  const examples = join(dirname(dirname(dirname(fileURLToPath(import.meta.url)))), "examples", "revocation-bundle");
  const v01 = JSON.parse(readFileSync(join(examples, "01-fresh-well-inside-both-bounds.json"), "utf8"));
  const v20 = JSON.parse(readFileSync(join(examples, "20-malformed-statement-on-another-log.json"), "utf8"));

  class Bundle {}
  for (const vec of [v01, v20]) {
    const opts = {
      trustedKeyIdentifiers: ["issuer-key-2026"],
      trustedBundleKeys: vec.context.trusted_bundle_keys,
      now: vec.context.now,
      maxBundleAgeSeconds: vec.context.max_bundle_age_seconds,
      maxFutureSkewSeconds: vec.context.max_future_skew_seconds,
    };
    for (const nonPlain of [
      Object.assign(new Bundle(), vec.context.bundle),
      Object.assign(Object.create({}), vec.context.bundle),
    ]) {
      const check = await checkRevocationBundle(nonPlain, opts);
      assert.equal(check.outcome, "unverified_for_revocation");
      assert.equal(check.cause, "bundle_malformed");
      assert.equal(check.evidence.path, "/");

      const res = await verifyRecord(vec.records[0], {
        trustedKey: vec.context.trusted_key,
        now: vec.context.now,
        maxAgeSeconds: null,
        revocationBundle: nonPlain,
        trustedBundleKeys: vec.context.trusted_bundle_keys,
      });
      assert.equal(res.revocation.outcome, "unverified_for_revocation");
      assert.equal(res.revocation.cause, "bundle_malformed");
      assert.equal(res.revocation.evidence.path, "/");
    }
  }
});

test("a plain object made in another realm is a plain object", async () => {
  // `{}` from another realm inherits from that realm's Object.prototype. The
  // options are accepted, so the call goes on to the child record and reports
  // what is wrong with that: it has no delegation block.
  const foreign = vm.runInNewContext("({})");
  assert.notEqual(Object.getPrototypeOf(foreign), Object.prototype);
  await rejects(verifyDelegationLink({}, {}, foreign), "delegation_absent");
  await rejects(verifyDelegationLink(vm.runInNewContext("({})"), {}, {}), "delegation_absent");
  assert.equal(canonicalJson(vm.runInNewContext('({ b: 1, a: { c: [true, null] } })')), '{"a":{"c":[true,null]},"b":1}');
  // What was refused in this realm is refused from the other one too.
  for (const source of ["[]", "new Date(0)", "new (class Options {})()", "Object.create({ supportedDigestAlgorithms: [] })"]) {
    await rejects(verifyDelegationLink({}, {}, vm.runInNewContext(source)), "invalid_argument");
  }
  assert.throws(() => canonicalJson(vm.runInNewContext("new Date(0)")), TraceVerificationError);
});

test("base64url decodes canonical input and refuses everything else", () => {
  assert.deepEqual([...decodeBase64url("")], []);
  assert.deepEqual([...decodeBase64url("AQID")], [1, 2, 3]);
  assert.deepEqual([...decodeBase64url("_w")], [255]);
  assert.equal(encodeBase64url(new Uint8Array([1, 2, 3])), "AQID");
  assert.equal(encodeBase64url(new Uint8Array([255])), "_w");
  for (const bad of ["AQI=", "A", "+w", "a/b", "AQ ID", "é", "_x"]) {
    assert.equal(decodeBase64url(bad), null, `accepted ${JSON.stringify(bad)}`);
  }
});

test("jwkThumbprint reproduces the RFC 7638 section 3.1 example", async () => {
  const rsa = {
    kty: "RSA",
    n:
      "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
      "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajr" +
      "n1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    e: "AQAB",
    alg: "RS256",
    kid: "2011-04-29",
  };
  assert.equal(await jwkThumbprint(rsa), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
});

test("jwkThumbprint refuses a key it cannot hash", async () => {
  await rejects(jwkThumbprint({ kty: "oct", k: "AQID" }), "jwk_invalid");
  await rejects(jwkThumbprint({ kty: "OKP", crv: "Ed25519" }), "jwk_invalid");
  await rejects(jwkThumbprint("not a key"), "jwk_invalid");
});

test("the profile is checked before anything else, and v0.1 is named as superseded", async () => {
  const key = { kty: "OKP", crv: "Ed25519", x: "Be97jkxfFpVXzj9B-gwpMzv5t8PH30Edd-J7AIlrdoA" };
  await rejects(verifyRecord(null, { trustedKey: key }), "record_not_object");
  await rejects(verifyRecord({}, { trustedKey: key }), "profile_missing");
  await rejects(verifyRecord({ eat_profile: 7 }, { trustedKey: key }), "profile_missing");
  await rejects(
    verifyRecord({ eat_profile: "tag:agentrust.io,2026:trace-v0.1" }, { trustedKey: key }),
    "profile_superseded",
  );
  await rejects(verifyRecord({ eat_profile: "urn:other" }, { trustedKey: key }), "profile_unsupported");
  // A record carrying the supported profile gets past the check and fails later.
  await rejects(verifyRecord({ eat_profile: TRACE_PROFILE_V0_2 }, { trustedKey: key }), "signature_missing");
});

test("verifyRecord refuses to guess a trust anchor", async () => {
  await rejects(
    verifyRecord({ eat_profile: TRACE_PROFILE_V0_2, signature: "AQID" }),
    "schema_invalid",
  );
});

// Match the Python verifier after #390: presence is separate from value/type.
test("signature_missing is reserved for an absent member", async () => {
  await rejects(verifyRecord({ eat_profile: TRACE_PROFILE_V0_2 }), "signature_missing");
});
for (const [label, signature] of [
  ["null", null], ["zero", 0], ["false", false], ["array", []],
  ["object", {}], ["undefined", undefined],
]) {
  test(`a present ${label} signature is malformed`, async () => {
    await rejects(verifyRecord({ eat_profile: TRACE_PROFILE_V0_2, signature }), "signature_malformed");
  });
}
test("an empty signature string reaches schema validation", async () => {
  await rejects(verifyRecord({ eat_profile: TRACE_PROFILE_V0_2, signature: "" }), "schema_invalid");
});

test("canonicalJson refuses a symbol-keyed member on an array as it does on an object", () => {
  const sym = Symbol("s");
  const refused = (error) =>
    error instanceof TraceVerificationError && error.code === "canonicalization_failed";
  assert.throws(() => canonicalJson(Object.assign([1, 2], { [sym]: 3 })), refused);
  assert.throws(() => canonicalJson({ a: Object.assign([], { [sym]: 1 }) }), refused);
  assert.equal(canonicalJson([1, 2]), "[1,2]");
});

test("a plain object is one whose prototype is null or a realm's Object.prototype, and nothing else", () => {
  const refused = (error) =>
    error instanceof TraceVerificationError && error.code === "canonicalization_failed";
  assert.equal(canonicalJson(Object.create(null)), "{}");
  assert.equal(canonicalJson(vm.runInNewContext("({ a: 1 })")), '{"a":1}');
  assert.equal(canonicalJson(vm.runInNewContext("Object.create(null)")), "{}");
  // One hop past a null prototype is not Object.prototype, in any realm.
  assert.throws(() => canonicalJson(Object.create(Object.create(null))), refused);
  assert.throws(() => canonicalJson(vm.runInNewContext("Object.create(Object.create(null))")), refused);
  assert.throws(() => canonicalJson(Object.create({})), refused);
  assert.throws(() => canonicalJson(new (class Record {})()), refused);
});

const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const SECRET_SENTINEL = "super-secret-private-material-999";
const FRESH_BUNDLE_VECTOR = JSON.parse(
  readFileSync(
    join(
      dirname(dirname(dirname(fileURLToPath(import.meta.url)))),
      "examples",
      "revocation-bundle",
      "01-fresh-well-inside-both-bounds.json",
    ),
    "utf8",
  ),
);

test("jwkThumbprint and verifyRecord refuse private JWK members without echoing secret values", async () => {
  const ctx = FRESH_BUNDLE_VECTOR.context;
  const record = FRESH_BUNDLE_VECTOR.records[0];

  for (const member of PRIVATE_JWK_MEMBERS) {
    const leakedTrustedKey = { ...ctx.trusted_key, [member]: SECRET_SENTINEL };
    await assert.rejects(jwkThumbprint(leakedTrustedKey), (error) => {
      assert.ok(error instanceof TraceVerificationError);
      assert.equal(error.code, "jwk_invalid");
      assert.match(error.message, /private key material/);
      assert.ok(error.message.includes(member));
      assert.equal(error.message.includes(SECRET_SENTINEL), false);
      return true;
    });

    await assert.rejects(
      verifyRecord(record, { trustedKey: leakedTrustedKey, now: ctx.now }),
      (error) => {
        assert.ok(error instanceof TraceVerificationError);
        assert.equal(error.code, "trusted_key_malformed");
        assert.match(error.message, /private key material/);
        assert.ok(error.message.includes(member));
        assert.equal(error.message.includes(SECRET_SENTINEL), false);
        return true;
      },
    );

    const leakedBundleKey = { ...ctx.trusted_bundle_keys[0], [member]: SECRET_SENTINEL };
    await assert.rejects(
      verifyRecord(record, {
        trustedKey: ctx.trusted_key,
        now: ctx.now,
        revocationBundle: ctx.bundle,
        trustedBundleKeys: [leakedBundleKey],
        maxBundleAgeSeconds: ctx.max_bundle_age_seconds,
        maxFutureSkewSeconds: ctx.max_future_skew_seconds,
      }),
      (error) => {
        assert.ok(error instanceof TraceVerificationError);
        assert.equal(error.code, "invalid_argument");
        assert.match(error.message, /private key material/);
        assert.ok(error.message.includes(member));
        assert.equal(error.message.includes(SECRET_SENTINEL), false);
        return true;
      },
    );
  }
});

test("checkRevocationBundle verifies ES256 and ES384 bundles and rejects mismatched or invalid EC keys", async () => {
  const examples = join(dirname(dirname(dirname(fileURLToPath(import.meta.url)))), "examples", "revocation-bundle");
  const v29 = JSON.parse(readFileSync(join(examples, "29-es256-bundle-verified.json"), "utf8"));
  const v30 = JSON.parse(readFileSync(join(examples, "30-es384-bundle-verified.json"), "utf8"));

  for (const vec of [v29, v30]) {
    const ctx = vec.context;
    const baseOpts = {
      trustedKeyIdentifiers: ["issuer-key-2026"],
      trustedBundleKeys: ctx.trusted_bundle_keys,
      now: ctx.now,
      maxBundleAgeSeconds: ctx.max_bundle_age_seconds,
      maxFutureSkewSeconds: ctx.max_future_skew_seconds,
    };
    const verified = await checkRevocationBundle(ctx.bundle, baseOpts);
    assert.equal(verified.outcome, "verified");

    const truncatedSig = {
      ...ctx.bundle,
      sig: { ...ctx.bundle.sig, value: encodeBase64url(new Uint8Array(32)) },
    };
    const invalid = await checkRevocationBundle(truncatedSig, baseOpts);
    assert.equal(invalid.outcome, "unverified_for_revocation");
    assert.equal(invalid.cause, "bundle_signature_invalid");
  }

  const one32 = encodeBase64url(Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0)));
  const offCurveJwk = { kty: "EC", crv: "P-256", x: one32, y: one32 };
  for (const [bundleTemplate, badKey] of [
    [v30.context.bundle, v29.context.trusted_bundle_keys[0]],
    [v29.context.bundle, v30.context.trusted_bundle_keys[0]],
    [v29.context.bundle, offCurveJwk],
  ]) {
    const bundle = { ...bundleTemplate, bundle_key_id: await jwkThumbprint(badKey) };
    const unsupported = await checkRevocationBundle(bundle, {
      trustedKeyIdentifiers: ["issuer-key-2026"],
      trustedBundleKeys: [badKey],
      now: v29.context.now,
      maxBundleAgeSeconds: v29.context.max_bundle_age_seconds,
      maxFutureSkewSeconds: v29.context.max_future_skew_seconds,
    });
    assert.equal(unsupported.outcome, "unverified_for_revocation");
    assert.equal(unsupported.cause, "bundle_signature_unsupported");
  }
});

test("importEcdsa and checkRevocationBundle refuse EC JWKs carrying private key material", async () => {
  const examples = join(dirname(dirname(dirname(fileURLToPath(import.meta.url)))), "examples", "revocation-bundle");
  const v29 = JSON.parse(readFileSync(join(examples, "29-es256-bundle-verified.json"), "utf8"));
  const v30 = JSON.parse(readFileSync(join(examples, "30-es384-bundle-verified.json"), "utf8"));
  const v11 = JSON.parse(
    readFileSync(join(examples, "11-statement-names-trusted-key-by-thumbprint.json"), "utf8"),
  );

  for (const [vec, curve] of [
    [v29, "P-256"],
    [v30, "P-384"],
  ]) {
    const ecJwk = vec.context.trusted_bundle_keys[0];
    assert.ok(await importEcdsa(ecJwk, curve, "bundle_key"));

    for (const member of PRIVATE_JWK_MEMBERS) {
      const leaked = { ...ecJwk, [member]: SECRET_SENTINEL };
      await assert.rejects(importEcdsa(leaked, curve, "bundle_key"), (error) => {
        assert.ok(error instanceof TraceVerificationError);
        assert.equal(error.code, "invalid_argument");
        assert.match(error.message, /private key material/);
        assert.ok(error.message.includes(member));
        assert.equal(error.message.includes(SECRET_SENTINEL), false);
        return true;
      });

      await assert.rejects(
        checkRevocationBundle(vec.context.bundle, {
          trustedKeyIdentifiers: ["issuer-key-2026"],
          trustedBundleKeys: [leaked],
          now: vec.context.now,
          maxBundleAgeSeconds: vec.context.max_bundle_age_seconds,
          maxFutureSkewSeconds: vec.context.max_future_skew_seconds,
        }),
        (error) => {
          assert.ok(error instanceof TraceVerificationError);
          assert.equal(error.code, "invalid_argument");
          assert.match(error.message, /private key material/);
          assert.ok(error.message.includes(member));
          assert.equal(error.message.includes(SECRET_SENTINEL), false);
          return true;
        },
      );
    }
  }

  for (const [mutator, expectedPath] of [
    [(b) => { b.sig.value += "\n"; }, "sig/value"],
    [(b) => { b.statements[0].sig.value += "\n"; }, "statements/0/sig/value"],
  ]) {
    const mutated = structuredClone(v11.context.bundle);
    mutator(mutated);
    const check = await checkRevocationBundle(mutated, {
      trustedKeyIdentifiers: ["issuer-key-2026"],
      trustedBundleKeys: v11.context.trusted_bundle_keys,
      now: v11.context.now,
      maxBundleAgeSeconds: v11.context.max_bundle_age_seconds,
      maxFutureSkewSeconds: v11.context.max_future_skew_seconds,
    });
    assert.equal(check.outcome, "unverified_for_revocation");
    assert.equal(check.cause, "bundle_malformed");
    assert.equal(check.evidence.path, expectedPath);
  }
});

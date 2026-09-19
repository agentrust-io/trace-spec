// Unit tests for the pieces the verifier is assembled from: RFC 8785
// canonicalization, base64url, RFC 7638 thumbprints and the profile cutover.

import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalJson,
  decodeBase64url,
  encodeBase64url,
  jwkThumbprint,
  TRACE_PROFILE_V0_2,
  TraceVerificationError,
  verifyRecord,
} from "../dist/index.js";

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

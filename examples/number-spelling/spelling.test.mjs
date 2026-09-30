// Number spelling from the JavaScript side (agentrust-io/trace-spec#247).
//
// Run with `node --test examples/number-spelling/`. Nothing to install: node:test,
// node:assert and node:crypto only.
//
// A JavaScript verifier is handed what JSON.parse produced, and JSON.parse keeps the
// value of a number and discards its spelling. The only integer decision it can make is
// on the value, so the rule proposed for section 3.2.2 is the one this runtime already
// follows. These tests show that, and check the vectors beside this file from this side:
// the outcome each expects follows from the value alone, and every signature in the set
// is valid, so no vector is rejected for anything but the rule it names.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SAFE = Number.MAX_SAFE_INTEGER; // 2 ** 53 - 1, the section 3.2.2 bound

// The decision a verifier can make on a parsed value, and the two failures it can name.
function integerValue(value) {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    return { ok: false, failure: "not_an_integer_value" };
  }
  if (!Number.isSafeInteger(value)) {
    return { ok: false, failure: "outside_safe_integer_range" };
  }
  return { ok: true, value };
}

// RFC 8785 for the values these records carry: object keys sorted by UTF-16 code unit,
// which is what Array.prototype.sort does to strings, and every string and number written
// by JSON.stringify, the ECMAScript serialization RFC 8785 section 3.2.2 adopts.
function jcs(value) {
  if (Array.isArray(value)) {
    return `[${value.map(jcs).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const members = Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`);
    return `{${members.join(",")}}`;
  }
  return JSON.stringify(value);
}

function vectors() {
  return readdirSync(here)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => {
      const text = readFileSync(join(here, name), "utf8");
      return { name, text, doc: JSON.parse(text) };
    });
}

function memberOf(record, path) {
  return path.split(".").reduce((node, name) => node[name], record);
}

test("JSON.parse gives the three spellings of 1785000000 one value", () => {
  const [plain, fraction, exponent] = ["1785000000", "1785000000.0", "1.785e9"].map((t) =>
    JSON.parse(t),
  );
  assert.equal(plain, 1785000000);
  assert.ok(Object.is(plain, fraction) && Object.is(plain, exponent));
  assert.ok(Number.isSafeInteger(fraction) && Number.isSafeInteger(exponent));
});

test("the spelling does not survive re-serialization", () => {
  // String(Number(x)) is the number serialization RFC 8785 applies.
  assert.equal(String(Number("1785000000.0")), "1785000000");
  assert.equal(String(Number("1.785e9")), "1785000000");
  assert.equal(String(Number("17850000005e-1")), "1785000000.5");
  assert.equal(String(Number("1.0e+21")), "1e+21");
  assert.equal(String(Number("-0.0")), "0");
  assert.equal(String(Number("1785000000.0000000001")), "1785000000");
  const forms = ["1785000000", "1785000000.0", "1.785e9"].map((t) =>
    jcs({ iat: JSON.parse(t), subject: "x" }),
  );
  assert.equal(new Set(forms).size, 1);
  assert.equal(forms[0], '{"iat":1785000000,"subject":"x"}');
});

test("the safe-integer boundary, as the double sees it", () => {
  assert.equal(SAFE, 2 ** 53 - 1);
  assert.ok(Number.isSafeInteger(2 ** 53 - 1));
  assert.ok(!Number.isSafeInteger(2 ** 53));
  assert.ok(Number.isSafeInteger(JSON.parse("9007199254740991.0")));
  // Both parse to 2 ** 53: the written value and the parsed one differ, and both are out.
  assert.equal(JSON.parse("9.007199254740993e15"), 2 ** 53);
  assert.equal(JSON.parse("9007199254740993"), 2 ** 53);
  assert.ok(!Number.isSafeInteger(JSON.parse("9.007199254740993e15")));
  assert.ok(Number.isInteger(1e21) && !Number.isSafeInteger(1e21));
  assert.ok(!Number.isInteger(JSON.parse("1785000000.5")));
  assert.ok(Object.is(JSON.parse("-0.0"), -0) && Number.isSafeInteger(-0) && -0 === 0);
});

test("boundary cases, decided by value", () => {
  const cases = [
    ["1785000000", true],
    ["1785000000.0", true],
    ["1.785e9", true],
    ["1785000000.0000000001", true], // more digits than a double carries: the double decides
    ["1785000000.5", "not_an_integer_value"],
    ["17850000005e-1", "not_an_integer_value"],
    ["9007199254740991", true],
    ["9007199254740991.0", true],
    ["-9007199254740991", true],
    ["9007199254740992", "outside_safe_integer_range"],
    ["-9007199254740992", "outside_safe_integer_range"],
    ["9.007199254740993e15", "outside_safe_integer_range"],
    ["1e21", "outside_safe_integer_range"],
    ["1.0e+21", "outside_safe_integer_range"],
    ["0", true],
    ["-0.0", true],
    ["true", "not_an_integer_value"],
    ["false", "not_an_integer_value"],
    ['"1785000000"', "not_an_integer_value"],
    ["null", "not_an_integer_value"],
  ];
  for (const [text, expected] of cases) {
    const decided = integerValue(JSON.parse(text));
    if (expected === true) {
      assert.ok(decided.ok, `${text} should be an integer`);
    } else {
      assert.deepEqual(decided, { ok: false, failure: expected }, text);
    }
  }
  // A floor is a bound on the value, so 0 and -0.0 fall below iat's in the same way.
  const iatFloor = 1700000000;
  for (const text of ["0", "-0.0"]) {
    const decided = integerValue(JSON.parse(text));
    assert.ok(decided.ok && decided.value < iatFloor, text);
  }
});

test("the vector set is complete", () => {
  assert.deepEqual(
    vectors().map((v) => v.name),
    [
      "01-integer-spelling-verified.json",
      "02-fraction-spelling-verified.json",
      "03-exponent-spelling-verified.json",
      "04-fractional-value-rejected.json",
      "05-fractional-value-exponent-spelling-rejected.json",
      "06-above-range-integer-spelling-rejected.json",
      "07-above-range-exponent-spelling-rejected.json",
    ],
  );
});

test("each file carries its spelling in the text, which JSON.parse then discards", () => {
  for (const { name, text, doc } of vectors()) {
    const last = doc.member.split(".").at(-1);
    const written = text.match(new RegExp(`"${last}": ([^,\\n]+)`));
    assert.ok(written, name);
    assert.equal(written[1], doc.spelling, name);
    assert.ok(Object.is(memberOf(doc.record, doc.member), JSON.parse(doc.spelling)), name);
  }
});

test("each vector's outcome follows from the value alone", () => {
  for (const { name, doc } of vectors()) {
    const decided = integerValue(memberOf(doc.record, doc.member));
    if (doc.expected.outcome === "verified") {
      assert.ok(decided.ok, name);
      assert.equal(doc.expected.failure, null, name);
    } else {
      assert.equal(doc.expected.outcome, "rejected", name);
      assert.deepEqual(decided, { ok: false, failure: doc.expected.failure }, name);
    }
  }
});

test("the three accepted records are one record here, with one signature", () => {
  const byName = Object.fromEntries(vectors().map((v) => [v.name, v.doc]));
  const first = byName["01-integer-spelling-verified.json"].record;
  for (const other of ["02-fraction-spelling-verified.json", "03-exponent-spelling-verified.json"]) {
    assert.deepStrictEqual(byName[other].record, first, other);
  }
  // 05 re-spells 04's value, so it is 04's record and 04's signature too.
  assert.deepStrictEqual(
    byName["05-fractional-value-exponent-spelling-rejected.json"].record,
    byName["04-fractional-value-rejected.json"].record,
  );
});

test("every signature in the set is valid over its record's RFC 8785 form", () => {
  for (const { name, doc } of vectors()) {
    const { signature, ...unsigned } = doc.record;
    const key = createPublicKey({ key: doc.trusted_key, format: "jwk" });
    const valid = verify(
      null,
      Buffer.from(jcs(unsigned), "utf8"),
      key,
      Buffer.from(signature, "base64url"),
    );
    assert.ok(valid, `${name}: the signature does not verify, so a rejection proves nothing`);
  }
});

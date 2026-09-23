/**
 * RFC 8785 JSON Canonicalization Scheme, with the integer bound of section 3.2.2.
 *
 * Section 3.2.2 fixes the signature pre-image as the RFC 8785 form of the record.
 * The rules implemented here:
 *
 * - Object members are sorted by the UTF-16 code units of their names
 *   (RFC 8785 section 3.2.3). JavaScript string comparison is exactly that order.
 * - No whitespace between tokens.
 * - Strings are emitted as UTF-8 with only U+0022, U+005C and U+0000 to U+001F
 *   escaped, using the short forms for backspace, tab, line feed, form feed and
 *   carriage return and lowercase `\u00xx` otherwise (RFC 8785 section 3.2.2.2).
 * - Numbers use the ECMAScript Number-to-String form (RFC 8785 section
 *   3.2.2.3), which is what `String(number)` produces; negative zero becomes `0`.
 *
 * Refused, each as `canonicalization_failed`:
 *
 * - an integer outside -9007199254740991 to 9007199254740991, which section
 *   3.2.2 raises from RFC 8785's SHOULD to a MUST;
 * - NaN and the infinities, which have no JSON form;
 * - a string or member name holding an unpaired surrogate, which has no UTF-8
 *   form (RFC 8785 section 3.1 requires I-JSON input, RFC 7493 section 2.1);
 * - anything that is not JSON data: `undefined`, functions, symbols, bigints,
 *   class instances, array holes, cyclic structures, and an object with a
 *   symbol-keyed member, which `Object.keys` would silently leave out.
 */

import { fail } from "./errors.js";
import { isPlainObject, unpairedSurrogateAt, utf8 } from "./text.js";

/** The widest integer range section 3.2.2 lets a canonicalized object carry. */
export const JCS_SAFE_INTEGER = 9007199254740991;

const SHORT_ESCAPES: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

function serializeString(value: string, where: string): string {
  const bad = unpairedSurrogateAt(value);
  if (bad !== -1) {
    fail(
      "canonicalization_failed",
      `${where} holds an unpaired surrogate at offset ${bad}; it has no UTF-8 form`,
    );
  }
  let out = '"';
  let start = 0;
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit < 0x20 || unit === 0x22 || unit === 0x5c) {
      out += value.slice(start, i);
      out += SHORT_ESCAPES[unit] ?? `\\u00${unit.toString(16).padStart(2, "0")}`;
      start = i + 1;
    }
  }
  return `${out}${value.slice(start)}"`;
}

function serializeNumber(value: number, where: string): string {
  if (!Number.isFinite(value)) {
    fail("canonicalization_failed", `${where} is ${String(value)}, which has no JSON form`);
  }
  if (Number.isInteger(value) && Math.abs(value) > JCS_SAFE_INTEGER) {
    fail(
      "canonicalization_failed",
      `${where} is an integer outside -${JCS_SAFE_INTEGER} to ${JCS_SAFE_INTEGER}; ` +
        "section 3.2.2 requires such a value to be rejected, because distinct integers " +
        "past that bound share one canonical form",
    );
  }
  return Object.is(value, -0) ? "0" : String(value);
}

function describe(path: readonly (string | number)[]): string {
  return path.length === 0 ? "the value" : `the value at ${path.map(String).join(".")}`;
}

function serialize(
  value: unknown,
  path: (string | number)[],
  ancestors: Set<object>,
  parts: string[],
): void {
  if (value === null) {
    parts.push("null");
    return;
  }
  switch (typeof value) {
    case "boolean":
      parts.push(value ? "true" : "false");
      return;
    case "string":
      parts.push(serializeString(value, describe(path)));
      return;
    case "number":
      parts.push(serializeNumber(value, describe(path)));
      return;
    case "object":
      break;
    default:
      fail("canonicalization_failed", `${describe(path)} is a ${typeof value}, which is not JSON`);
  }
  const node = value as object;
  if (ancestors.has(node)) {
    fail("canonicalization_failed", `${describe(path)} contains itself`);
  }
  ancestors.add(node);
  if (Array.isArray(node)) {
    parts.push("[");
    for (let i = 0; i < node.length; i++) {
      if (!Object.hasOwn(node, i)) {
        fail("canonicalization_failed", `${describe([...path, i])} is an array hole`);
      }
      if (i > 0) {
        parts.push(",");
      }
      path.push(i);
      serialize(node[i], path, ancestors, parts);
      path.pop();
    }
    parts.push("]");
  } else if (isPlainObject(node)) {
    if (Object.getOwnPropertySymbols(node).length > 0) {
      fail("canonicalization_failed", `${describe(path)} has a symbol-keyed member, which has no JSON form`);
    }
    const names = Object.keys(node).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    parts.push("{");
    names.forEach((name, index) => {
      if (index > 0) {
        parts.push(",");
      }
      parts.push(serializeString(name, `a member name in ${describe(path)}`));
      parts.push(":");
      path.push(name);
      serialize(node[name], path, ancestors, parts);
      path.pop();
    });
    parts.push("}");
  } else {
    fail("canonicalization_failed", `${describe(path)} is not a plain JSON object or array`);
  }
  ancestors.delete(node);
}

/** The RFC 8785 text of *value*. */
export function canonicalJson(value: unknown): string {
  const parts: string[] = [];
  try {
    serialize(value, [], new Set(), parts);
  } catch (error) {
    if (error instanceof RangeError) {
      fail("canonicalization_failed", "the value is nested too deeply to canonicalize", {
        cause: error,
      });
    }
    throw error;
  }
  return parts.join("");
}

/** The RFC 8785 bytes of *value*: the UTF-8 encoding of `canonicalJson(value)`. */
export function canonicalize(value: unknown): Uint8Array {
  return utf8(canonicalJson(value));
}

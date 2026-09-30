/** String helpers shared by the canonicalizer, the schema validator and the verifier. */

const encoder = new TextEncoder();

/** UTF-8 bytes of a string already known to be well formed. */
export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

/**
 * Offset of the first unpaired surrogate in *value*, or -1.
 *
 * A JavaScript string is a sequence of UTF-16 code units and may hold a lone
 * surrogate, which has no UTF-8 encoding. `TextEncoder` would silently replace
 * it with U+FFFD, so two different strings would produce the same bytes.
 */
export function unpairedSurrogateAt(value: string): number {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
      return i;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      return i;
    }
  }
  return -1;
}

/**
 * Number of Unicode code points in *value*, counting a lone surrogate as one.
 *
 * JSON Schema measures string length in code points, not UTF-16 code units, so
 * `minLength` and `maxLength` need this rather than `.length`.
 */
export function codePointLength(value: string): number {
  let length = 0;
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < value.length) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
      }
    }
    length++;
  }
  return length;
}

/** Compare two strings by Unicode code point, the order Python uses for `str`. */
export function compareCodePoints(a: string, b: string): number {
  const left = Array.from(a, (ch) => ch.codePointAt(0) as number);
  const right = Array.from(b, (ch) => ch.codePointAt(0) as number);
  const shared = Math.min(left.length, right.length);
  for (let i = 0; i < shared; i++) {
    const diff = (left[i] as number) - (right[i] as number);
    if (diff !== 0) {
      return diff < 0 ? -1 : 1;
    }
  }
  return left.length === right.length ? 0 : left.length < right.length ? -1 : 1;
}

/**
 * Compare two strings without an early exit on the first differing code unit.
 *
 * Code units rather than UTF-8 bytes: encoding first would map every lone
 * surrogate to U+FFFD and make distinct strings compare equal. The length is
 * not hidden, as with any constant-time comparison of variable-length input.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/*
 * What kind of value this is, asked in a way that does not depend on the realm
 * the value was made in. A record parsed by another frame's `JSON.parse`, an
 * options object built there, a `Uint8Array` or a `Set` handed across: each has
 * that frame's prototype, which is a different object from this module's with the
 * same role, so `instanceof` and a comparison with `Object.prototype` call them
 * all foreign. The three tests below read the shape or an internal slot instead.
 */

/**
 * True for an object written as `{...}` or made by `Object.create(null)`, in any
 * realm: it has no prototype, or a prototype that has none of its own, which is
 * what `Object.prototype` is everywhere. An array, a `Date`, a class instance
 * and `Object.create({})` each have a longer chain.
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === null || Object.getPrototypeOf(proto) === null;
}

// The %TypedArray%.prototype[@@toStringTag] getter reads the [[TypedArrayName]]
// slot: the constructor's name for a typed array of any realm, and undefined for
// everything else, an object carrying its own Symbol.toStringTag included.
const typedArrayName = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object,
  Symbol.toStringTag,
)?.get as ((this: unknown) => string | undefined) | undefined;

/** True for a `Uint8Array` of any realm, Node's `Buffer` included, and nothing else. */
export function isUint8Array(value: unknown): value is Uint8Array {
  return typedArrayName !== undefined && typedArrayName.call(value) === "Uint8Array";
}

// The `size` getter throws unless its receiver has [[SetData]], which a Set of
// any realm has and nothing else does.
const setSize = Object.getOwnPropertyDescriptor(Set.prototype, "size")?.get as
  | ((this: unknown) => number)
  | undefined;

/** True for a `Set` of any realm and nothing else. */
export function isSet(value: unknown): value is ReadonlySet<unknown> {
  if (setSize === undefined) {
    return false;
  }
  try {
    setSize.call(value);
    return true;
  } catch {
    return false;
  }
}

/** Own-property read, so an inherited member never stands in for an absent one. */
export function own(object: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(object, key) ? object[key] : undefined;
}

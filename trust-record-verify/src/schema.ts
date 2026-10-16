/**
 * JSON Schema (Draft 2020-12) validation against the repository's own schemas.
 *
 * The validators are generated at build time by `scripts/generate-validators.mjs`
 * from `schema/trace-claim.json`, `schema/trace-revocation-bundle.json` and
 * `schema/trace-revocation.json`, compiled ahead of time so nothing is evaluated
 * at run time and nothing is fetched: the statement schema the bundle schema
 * refers to by URL is compiled in beside it. Patterns follow ECMA-262, the
 * dialect JSON Schema 2020-12 specifies for `pattern`, and `format: uri` is
 * asserted, not treated as an annotation.
 */

import { schemaDigests, validateBundle, validateRecord } from "./generated/validators.js";
import { compareCodePoints } from "./text.js";

export interface SchemaViolation {
  /** Location of the offending value, one entry per property name or array index. */
  readonly path: readonly string[];
  /** The failing keyword, for example `required`, `pattern` or `additionalProperties`. */
  readonly keyword: string;
  readonly message: string;
}

interface GeneratedError {
  instancePath: string;
  keyword: string;
  message?: string;
  params?: Record<string, unknown>;
}

type GeneratedValidator = ((data: unknown) => boolean) & { errors?: GeneratedError[] | null };

function pointerSegments(pointer: string): string[] {
  if (pointer === "") {
    return [];
  }
  return pointer
    .slice(1)
    .split("/")
    .map((segment) => segment.replace(/~1/g, "/").replace(/~0/g, "~"));
}

function describeError(error: GeneratedError): string {
  const base = error.message ?? `fails "${error.keyword}"`;
  const extra = error.params?.["additionalProperty"];
  return typeof extra === "string" ? `${base} (${JSON.stringify(extra)})` : base;
}

function run(validator: GeneratedValidator, value: unknown): SchemaViolation[] {
  let ok: boolean;
  try {
    ok = validator(value);
  } catch (error) {
    if (error instanceof RangeError) {
      return [{ path: [], keyword: "depth", message: "the value is nested too deeply to validate" }];
    }
    throw error;
  }
  if (ok) {
    return [];
  }
  return (validator.errors ?? []).map((error) => ({
    path: pointerSegments(error.instancePath),
    keyword: error.keyword,
    message: describeError(error),
  }));
}

/**
 * Every violation of the Trust Record schema, in evaluation order. The first
 * entry is the one `verifyRecord` reports. Empty when the record is valid.
 */
export function recordSchemaViolations(record: unknown): SchemaViolation[] {
  return run(validateRecord as GeneratedValidator, record);
}

/**
 * Every violation of the revocation bundle schema, sorted by location.
 *
 * The sort compares locations as sequences of strings, element by element, in
 * code-point order, with a location sorting before any location it is a prefix
 * of. That is the order the Python reference sorts its errors in before naming
 * the first one, so both report the same location for the same bundle.
 */
export function bundleSchemaViolations(bundle: unknown): SchemaViolation[] {
  const violations = run(validateBundle as GeneratedValidator, bundle);
  return violations
    .map((violation, index) => ({ violation, index }))
    .sort((a, b) => {
      const left = a.violation.path;
      const right = b.violation.path;
      const shared = Math.min(left.length, right.length);
      for (let i = 0; i < shared; i++) {
        const order = compareCodePoints(left[i] as string, right[i] as string);
        if (order !== 0) {
          return order;
        }
      }
      return left.length - right.length || a.index - b.index;
    })
    .map(({ violation }) => violation);
}

/** SHA-256 of each schema file the validators were generated from, keyed by file name. */
export const SCHEMA_DIGESTS: Readonly<Record<string, string>> = schemaDigests;

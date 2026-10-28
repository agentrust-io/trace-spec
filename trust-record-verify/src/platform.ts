/**
 * Platform-measurement consumer for `verifyRecord` (the platform-measurement row
 * of agentrust-io/trace-spec#279, raised in agentrust-io/trace-spec#431).
 *
 * A Trust Record carries `runtime.platform` and `runtime.measurement`. This module
 * records what a caller-supplied appraiser reported about the measurement the
 * record carries, per layer, and nothing else:
 *
 * - Every layer outcome is the appraiser's report, carried as reported.
 * - The appraiser is caller-supplied only, never selected from the record.
 * - The appraiser receives a deep copy of `record.runtime` and cannot mutate the record.
 * - A report whose `measurement` differs from `runtime.measurement` is rejected with
 *   `appraisal_rejected` and cause `measurement_mismatch`.
 * - `not_attempted` is distinct from `appraised`; no outcome or layer outcome is a
 *   pass-like value or an `appraisal.status`.
 * - It runs last in `verifyRecord`, after signature verification and every check
 *   that can reject.
 */

import { exceptionName, typeName } from "./citation.js";
import { fail } from "./errors.js";
import { compareCodePoints, isPlainObject, own } from "./text.js";

/** What happened to the measurement as a whole. */
export type PlatformOutcome = "appraised" | "appraisal_rejected" | "not_attempted";

/** Why the measurement reports anything other than `appraised`. */
export type PlatformCause =
  | "no_appraiser"
  | "field_absent"
  | "appraiser_raised"
  | "appraiser_returned_invalid"
  | "measurement_mismatch";

/** What the appraiser reported for one layer. */
export type LayerOutcome = "established" | "not_established";

/** Why a layer is `not_established`. */
export type LayerCause =
  | "layer_not_measured"
  | "measured_not_appraised"
  | "evidence_spans_multiple_boots";

/** The statuses an appraiser may report for a layer. */
export type LayerStatus = "established" | LayerCause;

/**
 * The statuses an appraiser may report for a layer: `established`, or one of the
 * `LayerCause` values, which the module records as `not_established` with that cause.
 */
export const LAYER_STATUSES: readonly LayerStatus[] = Object.freeze([
  "established",
  "layer_not_measured",
  "measured_not_appraised",
  "evidence_spans_multiple_boots",
]);

/** The appraiser's report for one layer. */
export interface LayerCheck {
  readonly outcome: LayerOutcome;
  readonly cause: LayerCause | null;
}

/**
 * What the appraiser reported about `runtime.measurement`.
 *
 * `layers` is keyed by the appraiser's own layer names and is empty unless
 * `outcome` is `appraised`. `evidence` is JSON-serializable by construction.
 */
export interface PlatformMeasurementCheck {
  readonly outcome: PlatformOutcome;
  readonly cause: PlatformCause | null;
  readonly evidence: Readonly<Record<string, unknown>>;
  readonly layers: Readonly<Record<string, LayerCheck>>;
}

/** Caller-supplied platform measurement appraiser. */
export type PlatformAppraiser = (runtime: Record<string, unknown>) => unknown | Promise<unknown>;

/** What a result reports when no appraiser was supplied. */
export const NOT_ATTEMPTED: PlatformMeasurementCheck = Object.freeze({
  outcome: "not_attempted",
  cause: "no_appraiser",
  evidence: Object.freeze({}),
  layers: Object.freeze({}),
});

const FIELD_ABSENT: PlatformMeasurementCheck = Object.freeze({
  outcome: "not_attempted",
  cause: "field_absent",
  evidence: Object.freeze({}),
  layers: Object.freeze({}),
});

function rejected(cause: PlatformCause, evidence: Record<string, unknown>): PlatformMeasurementCheck {
  return Object.freeze({
    outcome: "appraisal_rejected",
    cause,
    evidence: Object.freeze(evidence),
    layers: Object.freeze({}),
  });
}

function cloneValue(value: unknown, seen: WeakMap<object, unknown>): unknown {
  if (Array.isArray(value)) {
    if (seen.has(value)) {
      return seen.get(value);
    }
    const copy: unknown[] = [];
    seen.set(value, copy);
    for (const item of value) {
      copy.push(cloneValue(item, seen));
    }
    return copy;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) {
      return seen.get(value);
    }
    const copy: Record<string, unknown> = {};
    seen.set(value, copy);
    for (const key of Object.keys(value)) {
      // Assignment would invoke Object.prototype's legacy __proto__ setter.
      Object.defineProperty(copy, key, {
        value: cloneValue(own(value, key), seen),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return copy;
  }
  return value;
}

/**
 * Record what `appraiser` reported about the record's `runtime.measurement`.
 *
 * Throws `TraceVerificationError` with `record_not_object` when `record` is not a
 * plain JSON object, or `invalid_argument` when `appraiser` is neither a function,
 * `null`, nor `undefined`. Every appraiser exception, malformed report, or
 * measurement mismatch is recorded as `appraisal_rejected` rather than thrown.
 */
export async function checkPlatformMeasurement(
  record: unknown,
  appraiser?: PlatformAppraiser | null,
): Promise<PlatformMeasurementCheck> {
  if (!isPlainObject(record)) {
    fail("record_not_object", "a Trust Record is a JSON object");
  }
  if (appraiser !== undefined && appraiser !== null && typeof appraiser !== "function") {
    fail("invalid_argument", "platformAppraiser must be a function or null");
  }
  if (appraiser === undefined || appraiser === null) {
    return NOT_ATTEMPTED;
  }

  const runtime = own(record, "runtime");
  if (!isPlainObject(runtime)) {
    return FIELD_ABSENT;
  }
  const measurement = own(runtime, "measurement");
  if (measurement === undefined || measurement === null) {
    return FIELD_ABSENT;
  }

  const runtimeCopy = cloneValue(runtime, new WeakMap()) as Record<string, unknown>;
  let report: unknown;
  try {
    report = await appraiser(runtimeCopy);
  } catch (err) {
    return rejected("appraiser_raised", {
      measurement,
      exception: exceptionName(err),
    });
  }

  if (!isPlainObject(report)) {
    return rejected("appraiser_returned_invalid", {
      measurement,
      member: "report",
      returned: typeName(report),
    });
  }
  const reportMembers = Object.keys(report).sort(compareCodePoints);
  if (
    reportMembers.length !== 2 ||
    reportMembers[0] !== "layers" ||
    reportMembers[1] !== "measurement"
  ) {
    return rejected("appraiser_returned_invalid", {
      measurement,
      member: "report",
      members: Object.freeze(reportMembers),
    });
  }
  const appraised = own(report, "measurement");
  if (appraised !== measurement) {
    return rejected("measurement_mismatch", {
      measurement,
      appraised: typeof appraised === "string" ? appraised : typeName(appraised),
    });
  }
  const layers = own(report, "layers");
  if (!isPlainObject(layers)) {
    return rejected("appraiser_returned_invalid", {
      measurement,
      member: "layers",
      returned: typeName(layers),
    });
  }
  const layerNames = Object.keys(layers);
  if (layerNames.length === 0) {
    return rejected("appraiser_returned_invalid", {
      measurement,
      member: "layers",
      returned: "empty",
    });
  }

  const checks: Record<string, LayerCheck> = {};
  for (const name of layerNames) {
    if (name === "") {
      return rejected("appraiser_returned_invalid", {
        measurement,
        member: "layer name",
        returned: "empty string",
      });
    }
    const status = own(layers, name);
    if (typeof status !== "string" || !(LAYER_STATUSES as readonly string[]).includes(status)) {
      return rejected("appraiser_returned_invalid", {
        measurement,
        member: "layer status",
        layer: name,
        returned: typeof status === "string" ? status : typeName(status),
      });
    }
    Object.defineProperty(checks, name, {
      value: Object.freeze(
        status === "established"
          ? { outcome: "established", cause: null }
          : { outcome: "not_established", cause: status as LayerCause },
      ),
      enumerable: true,
    });
  }

  return Object.freeze({
    outcome: "appraised",
    cause: null,
    evidence: Object.freeze({ measurement, layers: layerNames.length }),
    layers: Object.freeze(checks),
  });
}

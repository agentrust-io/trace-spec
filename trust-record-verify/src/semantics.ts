/** Cross-field TRACE record rules that JSON Schema cannot express. */

import { isPlainObject, own } from "./text.js";

export interface RecordSemanticViolation {
  readonly code: "measurement_mismatch";
  readonly path: "appraisal.platform_measurement.measurement";
  readonly message: string;
}

/**
 * Return cross-field violations after a record has passed its JSON Schema.
 *
 * Values are compared exactly as supplied. No parsing, coercion or rewriting can
 * turn a different appraisal measurement into the record's runtime measurement.
 */
export function recordSemanticViolations(record: unknown): RecordSemanticViolation[] {
  if (!isPlainObject(record)) {
    return [];
  }
  const runtime = own(record, "runtime");
  const appraisal = own(record, "appraisal");
  if (!isPlainObject(runtime) || !isPlainObject(appraisal)) {
    return [];
  }
  const platformMeasurement = own(appraisal, "platform_measurement");
  if (platformMeasurement === undefined) {
    return [];
  }
  if (!isPlainObject(platformMeasurement)) {
    return [];
  }
  const runtimeMeasurement = own(runtime, "measurement");
  const appraisalMeasurement = own(platformMeasurement, "measurement");
  if (appraisalMeasurement === runtimeMeasurement) {
    return [];
  }
  return [
    {
      code: "measurement_mismatch",
      path: "appraisal.platform_measurement.measurement",
      message:
        "must equal runtime.measurement; a result about another measurement is not " +
        "about this record",
    },
  ];
}

"""Cross-field TRACE record rules that JSON Schema cannot express."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _require_platform_measurement_binding(
    runtime_measurement: object, appraisal_measurement: object
) -> None:
    """Require a platform appraisal to describe this record's measurement exactly."""
    if appraisal_measurement != runtime_measurement:
        raise ValueError(
            "measurement_mismatch: appraisal.platform_measurement.measurement must equal "
            "runtime.measurement; a result about another measurement is not about this record"
        )


def _validate_record_semantics(record: Mapping[str, Any]) -> None:
    """Validate cross-field rules after the record has passed its JSON Schema.

    Values are compared as supplied. This validator does not parse, coerce, or rewrite
    either digest before deciding whether the appraisal belongs to the record.
    """
    appraisal = record["appraisal"]
    platform_measurement = appraisal.get("platform_measurement")
    if platform_measurement is None:
        return
    _require_platform_measurement_binding(
        record["runtime"]["measurement"], platform_measurement["measurement"]
    )

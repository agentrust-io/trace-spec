"""Platform-measurement consumer for ``verify_record`` (the platform-measurement row of
agentrust-io/trace-spec#279, raised in agentrust-io/trace-spec#431).

A Trust Record carries ``runtime.platform`` and ``runtime.measurement``: which kind of
platform produced the evidence, and one digest over it. For a measured-boot platform
that digest is a composite over many layers, and a matching composite says nothing
about which of those layers were measured, which were appraised, or whether the
evidence describes one boot. ``verify_record`` never sees the quote, the event log or
the reference values, so it cannot decide any of that itself. This module records what
a caller-supplied appraiser reported about the measurement the record carries, per
layer, and nothing else.

What this module asserts, and what it does not:

- It asserts nothing about the platform. Every layer outcome is the appraiser's report,
  carried as reported. The module checks only the report's shape and that it describes
  the measurement this record carries; it never derives a layer outcome, never turns a
  ``not_established`` layer into an ``established`` one, and never produces an
  ``appraisal.status``. That field stays closed to "not established", as #279 and
  agentrust-io/trace-spec#190 hold it.
- The appraiser is caller-supplied only. Nothing in the record selects or configures
  it, for the reason section 3.1.2 gives for TR-POL-003's resolver: a record that names
  its own checker can name one that agrees with it.
- The appraiser is handed a copy of ``runtime`` and nothing else. What evidence it
  reads (a quote, an event log, a reference manifest) and how it obtains that evidence
  are the caller's; this module never reads them.
- A report about another measurement is refused. The appraiser returns the measurement
  it appraised, and a report whose measurement differs from ``runtime.measurement`` is
  ``appraisal_rejected`` with cause ``measurement_mismatch``, so a correct appraisal of
  the wrong evidence cannot be attached to this record.
- ``not_attempted`` is not a pass. Anything that summarises this field keeps it
  distinct from ``appraised``, and no outcome or layer outcome here is a pass-like
  value.
- The outcome and cause names are not accepted normative text (#279). They describe
  what the appraiser reported; the specification has not adopted them, and a consumer
  that adopts different names is not thereby wrong.
- It runs last in ``verify_record``, after the signature has verified and after every
  check that can raise, so an appraiser never sees a ``runtime`` block from a record
  that was not authenticated.
- It imports no network library, and is held to that by the import sweep in
  ``tests/test_revocation_bundle.py``.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

Outcome = Literal["appraised", "appraisal_rejected", "not_attempted"]
"""What happened to the measurement as a whole."""

Cause = Literal[
    "no_appraiser",
    "field_absent",
    "appraiser_raised",
    "appraiser_returned_invalid",
    "measurement_mismatch",
]
"""Why the measurement reports anything other than ``appraised``."""

LayerOutcome = Literal["established", "not_established"]
"""What the appraiser reported for one layer."""

LayerCause = Literal[
    "layer_not_measured",
    "measured_not_appraised",
    "evidence_spans_multiple_boots",
]
"""Why a layer is ``not_established``. Each is a verifier outcome, never a pass and
never a failure: the layer was not measured; it was measured and nothing shows it was
appraised; or the evidence does not describe a single boot."""

#: The statuses an appraiser may report for a layer: ``established``, or one of the
#: ``LayerCause`` values, which the module records as ``not_established`` with that cause.
LAYER_STATUSES: tuple[str, ...] = ("established", *LayerCause.__args__)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class LayerCheck:
    """The appraiser's report for one layer."""

    outcome: LayerOutcome
    cause: LayerCause | None = None


@dataclass(frozen=True)
class PlatformMeasurementCheck:
    """What the appraiser reported about ``runtime.measurement``.

    ``layers`` is keyed by the appraiser's own layer names (for a TPM, ``pcr:0`` and so
    on) and is empty unless ``outcome`` is ``appraised``. ``evidence`` is
    JSON-serialisable by construction: the measurement as the record carries it, a
    count, or a class name, never message text.
    """

    outcome: Outcome
    cause: Cause | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    layers: dict[str, LayerCheck] = field(default_factory=dict)


NOT_ATTEMPTED = PlatformMeasurementCheck(outcome="not_attempted", cause="no_appraiser")
"""What a result reports when no appraiser was supplied."""


def _rejected(cause: Cause, **evidence: Any) -> PlatformMeasurementCheck:
    return PlatformMeasurementCheck(outcome="appraisal_rejected", cause=cause, evidence=evidence)


def check_platform_measurement(
    record: dict[str, Any], appraiser: Callable[[dict[str, Any]], Any] | None
) -> PlatformMeasurementCheck:
    """Record what ``appraiser`` reported about the record's ``runtime.measurement``.

    ``appraiser`` is called once with a deep copy of ``record["runtime"]`` and must return
    a JSON object with exactly two members: ``measurement``, the string it appraised, and
    ``layers``, a non-empty object mapping each layer name (a non-empty string) to
    one of ``LAYER_STATUSES``. ``None`` means no appraiser was supplied, and the result is
    ``not_attempted`` with cause ``no_appraiser``. A record without ``runtime.measurement``
    reports ``not_attempted`` with cause ``field_absent``.

    An appraiser that raises yields ``appraisal_rejected`` with cause
    ``appraiser_raised`` and the exception's class name; one that returns anything else
    than the shape above, including a ``layers`` object with no layer in it, yields
    cause ``appraiser_returned_invalid`` and, in the evidence, which member was
    wrong; one whose ``measurement`` is not the record's yields cause
    ``measurement_mismatch`` with both values. None of these propagates,
    and none is evidence of a defect in the record. A well-formed report about this
    measurement yields ``appraised``, the measurement and the layer count in the
    evidence, and one ``LayerCheck`` per reported layer.

    Raises ``ValueError`` when ``record`` is not a JSON object or ``appraiser`` is neither
    callable nor ``None``: those are the caller's mistakes, refused at entry.
    """
    if not isinstance(record, dict):
        raise ValueError(f"record must be a JSON object, got {type(record).__name__}")
    if appraiser is not None and not callable(appraiser):
        raise ValueError("appraiser must be callable or None")

    if appraiser is None:
        return NOT_ATTEMPTED
    runtime = record.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("measurement") is None:
        return PlatformMeasurementCheck(outcome="not_attempted", cause="field_absent")
    measurement = runtime["measurement"]

    try:
        report = appraiser(copy.deepcopy(runtime))
    except Exception as exc:
        return _rejected("appraiser_raised", measurement=measurement, exception=type(exc).__name__)

    if not isinstance(report, dict):
        return _rejected(
            "appraiser_returned_invalid", measurement=measurement, member="report",
            returned=type(report).__name__,
        )
    if set(report) != {"measurement", "layers"}:
        return _rejected(
            "appraiser_returned_invalid", measurement=measurement, member="report",
            members=sorted(str(k) for k in report),
        )
    if report["measurement"] != measurement:
        appraised = report["measurement"]
        return _rejected(
            "measurement_mismatch", measurement=measurement,
            appraised=appraised if isinstance(appraised, str) else type(appraised).__name__,
        )
    layers = report["layers"]
    if not isinstance(layers, dict):
        return _rejected(
            "appraiser_returned_invalid", measurement=measurement, member="layers",
            returned=type(layers).__name__,
        )
    if not layers:
        # A report that names no layer established nothing; carrying it as
        # `appraised` would read as an appraisal by default.
        return _rejected(
            "appraiser_returned_invalid", measurement=measurement, member="layers",
            returned="empty",
        )

    checks: dict[str, LayerCheck] = {}
    for name, status in layers.items():
        if not isinstance(name, str) or not name:
            return _rejected(
                "appraiser_returned_invalid", measurement=measurement, member="layer name",
                returned=type(name).__name__ if not isinstance(name, str) else "empty string",
            )
        if status not in LAYER_STATUSES:
            return _rejected(
                "appraiser_returned_invalid", measurement=measurement, member="layer status",
                layer=name,
                returned=status if isinstance(status, str) else type(status).__name__,
            )
        checks[name] = (
            LayerCheck(outcome="established")
            if status == "established"
            else LayerCheck(outcome="not_established", cause=status)
        )

    return PlatformMeasurementCheck(
        outcome="appraised",
        evidence={"measurement": measurement, "layers": len(checks)},
        layers=checks,
    )

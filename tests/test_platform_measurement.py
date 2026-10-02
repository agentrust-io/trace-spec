"""The platform-measurement consumer: vectors, invariants, and the package surface.

`examples/platform-measurement/` carries sixteen signed vectors: each cause with a
twin that differs only in the condition producing it, and two from published
evidence. The runner maps each
vector's `context` onto `verify_record`, builds the harness appraiser from
`context.appraisals` (a report per measurement, returned as given, raising `KeyError`
for a measurement the table lacks), and compares the `platform_measurement` field
alone: revocation, thumbprint, citations and the raise/no-raise behaviour of
`verify_record` are held unchanged by the invariants below rather than re-asserted per
vector.

The invariants are numbered P1 to P10. The network import sweep in
`tests/test_revocation_bundle.py` walks every module under `src/agentrust_trace/`, so
it already holds `platform_measurement` to importing no network library.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import pathlib
import subprocess
import sys
from collections.abc import Callable
from typing import Any

import pytest

from agentrust_trace.citation import check_citations
from agentrust_trace.platform_measurement import (
    LAYER_STATUSES,
    NOT_ATTEMPTED,
    LayerCheck,
    PlatformMeasurementCheck,
    check_platform_measurement,
)
from agentrust_trace.revocation import NO_CHECK, VerificationResult
from agentrust_trace.sign import generate_key, key_to_jwk, verify_record

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples" / "platform-measurement"
FILES = sorted(VECTORS.glob("*.json"))
assert FILES, "no platform-measurement vectors on disk; the runner would measure nothing"

REVOCATION_VECTORS = sorted((ROOT / "examples" / "revocation-bundle").glob("*.json"))


def _load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _appraiser(ctx: dict[str, Any]) -> Callable[[dict[str, Any]], Any] | None:
    """The harness appraiser. Absent `appraisals` means no appraiser; a present table
    that lacks the measurement raises `KeyError`, which is the vectors' `appraiser_raised`."""
    if "appraisals" not in ctx:
        return None
    table = ctx["appraisals"]

    def appraise(runtime: dict[str, Any]) -> Any:
        return copy.deepcopy(table[runtime["measurement"]])

    return appraise


def _run(doc: dict[str, Any], **overrides: Any) -> VerificationResult:
    ctx = doc["context"]
    kwargs: dict[str, Any] = {
        "now": ctx["now"],
        "max_age_seconds": ctx["max_age_seconds"],
        "max_future_skew_seconds": ctx["max_future_skew_seconds"],
        "platform_appraiser": _appraiser(ctx),
    }
    kwargs.update(overrides)
    return verify_record(doc["records"][0], ctx["trusted_key"], **kwargs)


def _row(check: PlatformMeasurementCheck) -> dict[str, Any]:
    return dataclasses.asdict(check)


def _vector(name: str) -> dict[str, Any]:
    return _load(VECTORS / name)


# ---- the vectors ---------------------------------------------------------------------


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_vector(path: pathlib.Path) -> None:
    doc = _load(path)
    expected = doc["expected"]
    assert expected["rejected"] is False and expected["codes"] == [], path.name
    assert _row(_run(doc).platform_measurement) == expected["platform_measurement"], path.name


def test_the_set_carries_every_outcome_and_every_layer_cause() -> None:
    """An outcome or a layer cause the set never reaches shows here rather than as
    eight identical passes."""
    seen: set[tuple[str, str | None]] = set()
    layer_causes: set[str | None] = set()
    for path in FILES:
        row = _load(path)["expected"]["platform_measurement"]
        seen.add((row["outcome"], row["cause"]))
        layer_causes.update(layer["cause"] for layer in row["layers"].values())
    assert ("not_attempted", "no_appraiser") in seen
    assert ("appraisal_rejected", "appraiser_raised") in seen
    assert ("appraisal_rejected", "measurement_mismatch") in seen
    assert ("appraisal_rejected", "appraiser_returned_invalid") in seen
    assert ("appraised", None) in seen
    assert layer_causes >= {
        None, "layer_not_measured", "measured_not_appraised", "evidence_spans_multiple_boots",
    }


def test_every_vector_is_either_sourced_or_labelled_synthetic() -> None:
    """A vector with a measurement from published evidence names where it is; every
    other vector says it is synthetic, so no reader takes a made-up report as a
    platform's."""
    for path in FILES:
        doc = _load(path)
        assert ("source" in doc) != ("synthetic" in doc), path.name
        if "synthetic" in doc:
            assert doc["synthetic"] is True, path.name
    sourced = {p.name for p in FILES if "source" in _load(p)}
    assert sourced == {"15-rc13-layer-not-measured.json", "16-dev-measured-not-appraised.json"}


def _causes(row: dict[str, Any]) -> set[str]:
    """Every cause a row carries, at the measurement and at any layer."""
    found = {row["cause"]} if row["cause"] else set()
    return found | {layer["cause"] for layer in row["layers"].values() if layer["cause"]}


def test_every_cause_has_a_twin_that_differs_only_in_its_condition() -> None:
    """Each cause the set produces has a vector that produces it and a twin with the
    same signed record and the same context except the appraisal table, which does
    not produce it. A fixture that only shows a cause appearing cannot show the
    consumer keyed it to the right condition; the twin can."""
    by_id = {_load(p)["id"]: _load(p) for p in FILES}
    twinned: set[str] = set()
    for twin in by_id.values():
        if "twin_of" not in twin:
            continue
        original = by_id[twin["twin_of"]]
        assert twin["records"] == original["records"], twin["name"]
        strip = ("appraisals",)
        assert {k: v for k, v in twin["context"].items() if k not in strip} == {
            k: v for k, v in original["context"].items() if k not in strip
        }, twin["name"]
        cause = _causes(original["expected"]["platform_measurement"])
        assert len(cause) == 1, original["name"]
        assert not cause & _causes(twin["expected"]["platform_measurement"]), twin["name"]
        twinned |= cause
    produced = set().union(*(_causes(_load(p)["expected"]["platform_measurement"]) for p in FILES))
    assert produced <= twinned, f"causes with no twin: {sorted(produced - twinned)}"


# ---- invariants ----------------------------------------------------------------------


def test_P1_every_record_that_verified_before_still_verifies_with_the_same_result() -> None:
    """The revocation vectors are records `verify_record` accepted before this field
    existed. Each still returns its expected revocation outcome, and reports
    `not_attempted` / `no_appraiser`; a result built by hand defaults to the same."""
    for path in REVOCATION_VECTORS:
        doc = _load(path)
        if doc["expected"]["rejected"]:
            continue
        ctx = doc["context"]
        result = verify_record(
            doc["records"][0], ctx["trusted_key"], now=ctx["now"],
            max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
            max_future_skew_seconds=ctx["max_future_skew_seconds"],
            revocation_bundle=ctx["bundle"], trusted_bundle_keys=ctx["trusted_bundle_keys"],
        )
        assert result.revocation.outcome == doc["expected"]["outcome"], path.name
        assert result.platform_measurement == NOT_ATTEMPTED, path.name
    by_hand = VerificationResult(revocation=NO_CHECK, trusted_key_thumbprint="thumb")
    assert by_hand.platform_measurement == NOT_ATTEMPTED


def test_P2_no_platform_outcome_moves_revocation_the_thumbprint_or_citations() -> None:
    for path in FILES:
        doc = _load(path)
        with_appraiser = _run(doc)
        without = _run(doc, platform_appraiser=None)
        assert with_appraiser.revocation == without.revocation == NO_CHECK, path.name
        assert with_appraiser.trusted_key_thumbprint == without.trusted_key_thumbprint
        assert with_appraiser.citations == without.citations
        assert with_appraiser.citations == check_citations(doc["records"][0], None)


def test_P3_the_appraiser_gets_a_copy_and_cannot_change_the_record() -> None:
    doc = _vector("15-rc13-layer-not-measured.json")
    record = doc["records"][0]
    before = copy.deepcopy(record)
    seen: list[dict[str, Any]] = []

    def meddling(runtime: dict[str, Any]) -> Any:
        seen.append(runtime)
        report = copy.deepcopy(doc["context"]["appraisals"][runtime["measurement"]])
        runtime["measurement"] = "sha256:" + "ff" * 32
        return report

    result = _run(doc, platform_appraiser=meddling)
    assert record == before
    assert seen and seen[0] is not record["runtime"]
    assert result.platform_measurement.outcome == "appraised"


def test_P4_every_outcome_other_than_appraised_names_a_cause_and_layers_follow_status() -> None:
    for path in FILES:
        check = _run(_load(path)).platform_measurement
        if check.outcome == "appraised":
            assert check.cause is None, path.name
        else:
            assert check.cause is not None and check.layers == {}, path.name
        for name, layer in check.layers.items():
            if layer.outcome == "established":
                assert layer.cause is None, (path.name, name)
            else:
                assert layer.cause in LAYER_STATUSES[1:], (path.name, name)


def test_P4b_not_attempted_is_never_a_pass() -> None:
    """Wherever the field is summarised, `not_attempted` stays distinct from a pass: no
    outcome or layer outcome is a pass-like value, and the default is not `appraised`."""
    passes = {"pass", "passed", "ok", "verified", "affirming", "success"}
    assert NOT_ATTEMPTED.outcome == "not_attempted" and NOT_ATTEMPTED.outcome != "appraised"
    for path in FILES:
        check = _run(_load(path)).platform_measurement
        assert check.outcome not in passes, path.name
        assert all(layer.outcome not in passes for layer in check.layers.values()), path.name


def test_P5_every_result_serialises_as_json() -> None:
    for path in FILES:
        json.dumps(_row(_run(_load(path)).platform_measurement))


MESSAGE = "appraiser-message-text-must-not-leak"


@pytest.mark.parametrize("exc", [KeyError(MESSAGE), ValueError(MESSAGE), RuntimeError(MESSAGE),
                                 OSError(MESSAGE)])
def test_P6_a_raising_appraiser_is_reported_not_propagated(exc: Exception) -> None:
    def raising(runtime: dict[str, Any]) -> Any:
        raise exc

    doc = _vector("02-no-appraiser-twin.json")
    check = _run(doc, platform_appraiser=raising).platform_measurement
    assert (check.outcome, check.cause) == ("appraisal_rejected", "appraiser_raised")
    assert check.evidence["exception"] == type(exc).__name__
    assert MESSAGE not in json.dumps(check.evidence)


_GOOD = "sha256:" + "5a" * 32


@pytest.mark.parametrize(
    ("returned", "member"),
    [
        (None, "report"),
        ([1, 2], "report"),
        ("established", "report"),
        ({"measurement": _GOOD}, "report"),
        ({"measurement": _GOOD, "layers": {}, "extra": 1}, "report"),
        ({"measurement": _GOOD, "layers": [["pcr:0", "established"]]}, "layers"),
        ({"measurement": _GOOD, "layers": {"": "established"}}, "layer name"),
        ({"measurement": _GOOD, "layers": {"pcr:0": "affirming"}}, "layer status"),
        ({"measurement": _GOOD, "layers": {"pcr:0": "pass"}}, "layer status"),
        ({"measurement": _GOOD, "layers": {"pcr:0": None}}, "layer status"),
        ({"measurement": _GOOD, "layers": {"pcr:0": "not_established"}}, "layer status"),
    ],
)
def test_P7_a_report_of_another_shape_is_an_outcome_not_a_crash(returned: Any, member: str) -> None:
    check = _run(
        _vector("02-no-appraiser-twin.json"), platform_appraiser=lambda runtime: returned,
    ).platform_measurement
    assert (check.outcome, check.cause) == ("appraisal_rejected", "appraiser_returned_invalid")
    assert check.evidence["member"] == member
    json.dumps(check.evidence)


def test_P8_a_report_about_another_measurement_is_never_attached() -> None:
    other = "sha256:" + "0e" * 32
    report = {"measurement": other, "layers": {"pcr:0": "established"}}
    check = _run(
        _vector("02-no-appraiser-twin.json"), platform_appraiser=lambda runtime: report,
    ).platform_measurement
    assert (check.outcome, check.cause) == ("appraisal_rejected", "measurement_mismatch")
    assert check.evidence == {"measurement": _GOOD, "appraised": other}
    assert check.layers == {}


@pytest.mark.parametrize("junk", ["a-string", 123, True, {}, [1]])
def test_P9_a_non_callable_appraiser_is_refused_at_entry(junk: Any) -> None:
    doc = _vector("01-no-appraiser.json")
    with pytest.raises(ValueError):
        _run(doc, platform_appraiser=junk)
    with pytest.raises(ValueError):
        check_platform_measurement(doc["records"][0], junk)


def test_P9_a_non_object_record_is_refused_and_a_missing_measurement_is_field_absent() -> None:
    with pytest.raises(ValueError):
        check_platform_measurement(["not", "a", "record"], None)  # type: ignore[arg-type]
    absent = check_platform_measurement({"runtime": {}}, lambda runtime: None)
    assert (absent.outcome, absent.cause) == ("not_attempted", "field_absent")


def test_P10_a_record_that_fails_verification_never_reaches_the_appraiser() -> None:
    """The appraiser is called last. A record whose signature does not verify, whose
    signer is not the trusted key, or whose `iat` is stale raises before the appraiser
    sees anything; a valid record calls it exactly once."""
    from cryptography.exceptions import InvalidSignature

    doc = _vector("15-rc13-layer-not-measured.json")
    ctx = doc["context"]
    record = doc["records"][0]
    calls: list[str] = []

    def appraiser(runtime: dict[str, Any]) -> Any:
        calls.append(runtime["measurement"])
        return copy.deepcopy(ctx["appraisals"][runtime["measurement"]])

    tampered = json.loads(json.dumps(record))
    first = tampered["signature"][0]
    tampered["signature"] = ("A" if first != "A" else "B") + tampered["signature"][1:]
    with pytest.raises((ValueError, InvalidSignature)):
        verify_record(tampered, ctx["trusted_key"], now=ctx["now"], platform_appraiser=appraiser)
    with pytest.raises(ValueError):
        verify_record(record, key_to_jwk(generate_key()), now=ctx["now"],
                      platform_appraiser=appraiser)
    with pytest.raises(ValueError):
        verify_record(record, ctx["trusted_key"], now=ctx["now"] + 10 * 86400,
                      max_age_seconds=86400, platform_appraiser=appraiser)
    assert calls == []
    _run(doc, platform_appraiser=appraiser)
    assert calls == [record["runtime"]["measurement"]]


def test_P11_no_report_yields_a_status_the_appraiser_did_not_give() -> None:
    """Each reported status maps to exactly one layer outcome; nothing is upgraded, and
    no layer outcome is an `appraisal.status` value."""
    for status in LAYER_STATUSES:
        report = {"measurement": _GOOD, "layers": {"pcr:0": status}}
        check = _run(
            _vector("02-no-appraiser-twin.json"), platform_appraiser=lambda r, rep=report: rep,
        ).platform_measurement
        layer = check.layers["pcr:0"]
        expected = (
            LayerCheck("established") if status == "established"
            else LayerCheck("not_established", status)
        )
        assert layer == expected
        assert layer.outcome not in ("affirming", "warning", "contraindicated", "none")


# ---- the package surface -------------------------------------------------------------


def test_the_platform_measurement_surface_is_exported() -> None:
    import agentrust_trace
    from agentrust_trace import platform_measurement as module

    for name in ("check_platform_measurement", "PlatformMeasurementCheck", "LayerCheck"):
        assert name in agentrust_trace.__all__, f"{name} is not in __all__"
        assert getattr(agentrust_trace, name) is getattr(module, name), name


# ---- the generator -------------------------------------------------------------------


def test_the_generator_reproduces_the_committed_vectors_byte_for_byte(
    tmp_path: pathlib.Path,
) -> None:
    import os
    import shutil

    target = tmp_path / "examples" / "platform-measurement"
    shutil.copytree(VECTORS, target)
    subprocess.run(
        [sys.executable, "examples/platform-measurement/gen_platform_vectors.py"],
        cwd=tmp_path, check=True, capture_output=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    for path in FILES:
        assert (target / path.name).read_bytes() == path.read_bytes(), path.name

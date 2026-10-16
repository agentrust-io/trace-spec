"""Retained verifier-side appraisal context: same signed record, different result.

Informative regression for TRACE #279/#431 and reference appraisal by trusted
values (#524). No new normative record field, shared enum or verifier API.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from agentrust_trace.sign import verify_record

CASE = (
    Path(__file__).resolve().parents[1]
    / "examples/platform-measurement/15-rc13-layer-not-measured.json"
)


def _bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _frozen_case() -> tuple[dict, dict, dict]:
    document = json.loads(CASE.read_text(encoding="utf-8"))
    return document["records"][0], document["context"]["trusted_key"], document["context"]


def _appraiser(table: dict):
    frozen = copy.deepcopy(table)

    def appraise(runtime: dict) -> dict:
        return copy.deepcopy(frozen[runtime["measurement"]])

    return appraise


def _decision(record: dict, trusted: dict, context: dict):
    # The appraiser closure is supplied by the verifier, NEVER by the Trust Record.
    return verify_record(
        copy.deepcopy(record),
        copy.deepcopy(trusted),
        now=context["now"],
        max_age_seconds=context["max_age_seconds"],
        max_future_skew_seconds=context["max_future_skew_seconds"],
        platform_appraiser=_appraiser(context["appraisals"]),
    )


def test_same_signed_record_changes_when_required_appraisal_context_changes() -> None:
    record, trusted, context = _frozen_case()
    original = _bytes(record)
    first = _decision(record, trusted, context)
    changed = copy.deepcopy(context)
    measurement = record["runtime"]["measurement"]
    changed["appraisals"][measurement]["layers"]["pcr:2"] = "established"
    second = _decision(record, trusted, changed)

    assert _bytes(record) == original
    assert first.trusted_key_thumbprint == second.trusted_key_thumbprint
    assert first.platform_measurement.layers["pcr:2"].outcome == "not_established"
    assert second.platform_measurement.layers["pcr:2"].outcome == "established"
    assert hashlib.sha256(_bytes(context)).digest() != hashlib.sha256(_bytes(changed)).digest()


def test_absent_verifier_appraiser_is_not_a_positive_platform_appraisal() -> None:
    record, trusted, context = _frozen_case()
    result = verify_record(
        record,
        trusted,
        now=context["now"],
        max_age_seconds=context["max_age_seconds"],
        max_future_skew_seconds=context["max_future_skew_seconds"],
    )
    assert result.platform_measurement.outcome == "not_attempted"
    assert result.platform_measurement.cause == "no_appraiser"


def test_verification_time_and_freshness_are_verifier_side_inputs() -> None:
    record, trusted, context = _frozen_case()
    accepted = _decision(record, trusted, context)
    assert accepted.platform_measurement.outcome == "appraised"
    changed = copy.deepcopy(context)
    changed["now"] = record["iat"] + changed["max_age_seconds"] + 1
    with pytest.raises(ValueError, match="stale"):
        _decision(record, trusted, changed)


def test_context_manifest_digest_does_not_recover_missing_appraiser_bytes() -> None:
    _, _, context = _frozen_case()
    evidence = _bytes(context["appraisals"])
    pinned = hashlib.sha256(evidence).hexdigest()
    assert hashlib.sha256(evidence).hexdigest() == pinned
    # The hash is a binding, not the missing reference-value document.
    assert hashlib.sha256(b"").hexdigest() != pinned

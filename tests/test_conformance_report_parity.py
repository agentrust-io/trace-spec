"""Regression tests for conformance report Level 0 modules, trace guard, and digest (#557)."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE_SRC = ROOT / "conformance" / "src"
if str(CONFORMANCE_SRC) not in sys.path:
    sys.path.insert(0, str(CONFORMANCE_SRC))

inclusion_mod = importlib.import_module("trace_tests.inclusion")
report_mod = importlib.import_module("trace_tests.report")
result_mod = importlib.import_module("trace_tests.result")
runner_mod = importlib.import_module("trace_tests.runner")

InclusionError = inclusion_mod.InclusionError
canonical_claim_bytes = inclusion_mod.canonical_claim_bytes
Finding = result_mod.Finding
Status = result_mod.Status
_LEVEL_MODULES = runner_mod._LEVEL_MODULES

VECTORS = ROOT / "conformance" / "tests" / "vectors"


def _load_vector(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((VECTORS / name).read_text(encoding="utf-8"))
    return loaded


def test_report_level_modules_include_tr_apr_at_level_zero() -> None:
    assert report_mod.LEVEL_MODULES[0] == ("TR-ENV", "TR-SIG", "TR-POL", "TR-APR")
    assert report_mod.LEVEL_MODULES[0] == _LEVEL_MODULES[0]
    cumulative = {
        lv: tuple(m for k in range(lv + 1) for m in report_mod.LEVEL_MODULES[k])
        for lv in sorted(report_mod.LEVEL_MODULES)
    }
    assert cumulative == dict(_LEVEL_MODULES)


@pytest.mark.parametrize(
    "bad_trace",
    ["not-a-dict", 123, None, [1, 2], True],
    ids=["str", "int", "none", "list", "bool"],
)
def test_report_build_guards_non_dict_trace(bad_trace: object) -> None:
    try:
        data = report_mod.build(
            record={"trace": bad_trace},
            record_path="r.json",
            record_format="cmcp-runtime",
            results_by_level={
                0: {"TR-ENV": [Finding("TR-ENV-001", Status.FAIL, "trace is not an object")]}
            },
            suite_version="0.5.0",
            library_version=None,
            generated_at="now",
        )
    except AttributeError:
        pytest.fail(f"report.build crashed on non-dict trace value {bad_trace!r}")
    assert data.transparency is None
    assert "unanchored" in report_mod.to_html(data)


@pytest.mark.parametrize(
    "bad_value",
    [float("nan"), float("inf"), float("-inf"), 1.5, 10**20, -(10**20)],
    ids=["nan", "inf", "neg-inf", "float", "above-safe-int", "below-safe-int"],
)
def test_report_record_digest_enforces_anchor_leaf_profile(bad_value: object) -> None:
    record = _load_vector("valid_level0.json")
    expected = "sha256:" + hashlib.sha256(canonical_claim_bytes(record)).hexdigest()
    assert report_mod.record_digest(record) == expected

    record["data_class"] = bad_value
    with pytest.raises(InclusionError):
        report_mod.record_digest(record)

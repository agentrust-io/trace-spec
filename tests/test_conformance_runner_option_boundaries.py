"""Behavioral boundary checks for conformance runner entry validation (#626)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

_CONFORMANCE_SRC = str(Path(__file__).resolve().parents[1] / "conformance" / "src")
if sys.path[:1] != [_CONFORMANCE_SRC]:
    sys.path.insert(0, _CONFORMANCE_SRC)

from trace_tests.runner import _run_levels, run  # type: ignore[import-untyped] # noqa: E402


@pytest.mark.parametrize("bad_level", [True, False, 1.0, "0", None, -1])
def test_run_rejects_boolean_and_non_int_level(bad_level: Any) -> None:
    with pytest.raises(ValueError, match="Unknown conformance level"):
        run({}, "trace", level=bad_level)


@pytest.mark.parametrize("bad_record", [None, [], "not-a-dict", 123])
def test_runner_rejects_non_dict_record(bad_record: Any) -> None:
    with pytest.raises(ValueError, match="record must be a JSON object"):
        run(bad_record, "trace", level=0)
    with pytest.raises(ValueError, match="record must be a JSON object"):
        _run_levels(bad_record, "trace", (0,))


@pytest.mark.parametrize("bad_fmt", ["", "json", "plain", None, 123, [], {}])
def test_runner_rejects_unknown_format(bad_fmt: Any) -> None:
    with pytest.raises(ValueError, match="Unknown record format"):
        run({}, bad_fmt, level=0)
    with pytest.raises(ValueError, match="Unknown record format"):
        _run_levels({}, bad_fmt, (0,))


@pytest.mark.parametrize("bad_max_age", [True, False, 0, -1, 86400.0, "86400", None])
def test_runner_rejects_invalid_max_age_seconds(bad_max_age: Any) -> None:
    with pytest.raises(ValueError, match="max_age_seconds must be a positive integer"):
        run({}, "trace", level=0, max_age_seconds=bad_max_age)
    with pytest.raises(ValueError, match="max_age_seconds must be a positive integer"):
        _run_levels({}, "trace", (0,), max_age_seconds=bad_max_age)


def test_runner_rejects_invalid_optional_arguments() -> None:
    with pytest.raises(ValueError, match="expected_nonce must be a string"):
        run({}, "trace", level=0, expected_nonce=123)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="expected_nonce must be a string"):
        _run_levels({}, "trace", (0,), expected_nonce=123)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="receipt must be a JSON object"):
        run({}, "trace", level=0, receipt=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="receipt must be a JSON object"):
        _run_levels({}, "trace", (0,), receipt=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="entry must be a JSON object"):
        run({}, "trace", level=0, entry="bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="entry must be a JSON object"):
        _run_levels({}, "trace", (0,), entry="bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="policy_resolver must be callable"):
        run({}, "trace", level=0, policy_resolver="not-callable")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="policy_resolver must be callable"):
        _run_levels({}, "trace", (0,), policy_resolver="not-callable")  # type: ignore[arg-type]

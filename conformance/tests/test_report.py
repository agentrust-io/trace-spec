"""Tests for the shareable report.

The report is an artifact people will forward without re-running anything, so
the failure that matters is not a crash: it is a report that reads as more
authoritative than it is, or that disagrees with the suite it came from.
"""

from __future__ import annotations

import json
import re

import pytest

from trace_tests import report as report_mod
from trace_tests.result import Finding, Status
from trace_tests.runner import run

from .conftest import _build_signed_cmcp_record, load_vector

#: Wide enough that a fixture's age never decides a test about reporting.
_MAX_AGE = 10 ** 9


def _passing_record():
    """A genuinely conformant record.

    The ``valid_level0.json`` vector is a structural fixture: its ``iat`` is from
    2025 and it carries no signature, so it fails Level 0 on staleness. Using it
    to test "what does a passing report look like" would have asserted the wrong
    thing about the code under test.
    """
    record, _key = _build_signed_cmcp_record()
    return record


def _build(record, fmt="trace", max_level=2):
    results = {lv: run(record, fmt, lv, max_age_seconds=_MAX_AGE) for lv in range(max_level + 1)}
    return report_mod.build(
        record=record,
        record_path="record.json",
        record_format=fmt,
        results_by_level=results,
        suite_version="0.5.0",
        library_version="0.7.0",
        generated_at="2026-08-09 05:00 UTC",
    )


# --- verdict ---------------------------------------------------------------


def test_highest_level_is_the_highest_that_passed() -> None:
    data = _build(_passing_record(), fmt="cmcp-runtime")
    assert data.highest_level is not None
    assert data.verdict.startswith(f"Level {data.highest_level}")
    # Every level below the highest passing one must also have passed, or
    # "highest" is meaningless.
    for lv in data.levels:
        if lv.level < data.highest_level:
            assert lv.passed, f"level {lv.level} failed below the reported highest"


def test_stale_unsigned_fixture_fails_level_zero() -> None:
    """Guards the assumption the rest of these tests rest on."""
    results = {lv: run(load_vector("valid_level0.json"), "trace", lv) for lv in range(1)}
    data = report_mod.build(
        record=load_vector("valid_level0.json"),
        record_path="r.json",
        record_format="trace",
        results_by_level=results,
        suite_version="0.5.0",
        library_version=None,
        generated_at="now",
    )
    assert data.highest_level is None


def test_failing_level_zero_is_stated_as_such() -> None:
    # Wrong profile, not missing runtime: TR-RTE only runs from Level 1, so a
    # record missing `runtime` still clears Level 0 and is the wrong fixture for
    # this assertion.
    data = _build(load_vector("invalid_wrong_profile.json"))
    assert data.highest_level is None
    assert data.verdict == "FAIL at Level 0"


def test_unverified_is_a_failure_from_level_one_up() -> None:
    """Matching the CLI. A report calling an unverified record PASS at Level 1
    would be worse than no report at all."""
    data = report_mod.build(
        record={"transparency": None},
        record_path="r.json",
        record_format="trace",
        results_by_level={
            0: {"TR-SIG": [Finding("TR-SIG-001", Status.UNVERIFIED, "no signature")]},
            1: {"TR-SIG": [Finding("TR-SIG-001", Status.UNVERIFIED, "no signature")]},
        },
        suite_version="0.5.0",
        library_version=None,
        generated_at="now",
    )
    assert data.levels[0].passed is True  # level 0 tolerates it, as the CLI does
    assert data.levels[1].passed is False
    assert data.highest_level == 0


# --- the two renderings must not disagree ---------------------------------


def test_json_and_html_carry_the_same_verdict() -> None:
    data = _build(load_vector("valid_level0.json"))
    parsed = json.loads(report_mod.to_json(data))
    assert parsed["verdict"] == data.verdict
    assert data.verdict in report_mod.to_html(data)


def test_json_reports_every_finding() -> None:
    data = _build(load_vector("valid_level0.json"))
    parsed = json.loads(report_mod.to_json(data))
    expected = sum(len(fs) for results in data.findings.values() for fs in results.values())
    assert len(parsed["findings"]) == expected


# --- the digest, which is what makes the report checkable ------------------


def test_digest_identifies_the_record() -> None:
    record = load_vector("valid_level0.json")
    data = _build(record)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", data.digest)
    assert data.digest == report_mod.record_digest(record)


def test_digest_changes_when_the_record_changes() -> None:
    record = load_vector("valid_level0.json")
    before = report_mod.record_digest(record)
    record["data_class"] = record.get("data_class", "internal") + "-modified"
    assert report_mod.record_digest(record) != before


def test_digest_is_key_order_independent() -> None:
    """Two serializations of the same record must not look like two records."""
    record = load_vector("valid_level0.json")
    reordered = dict(reversed(list(record.items())))
    assert report_mod.record_digest(reordered) == report_mod.record_digest(record)


def test_html_shows_the_digest_and_how_to_reproduce() -> None:
    data = _build(load_vector("valid_level0.json"))
    out = report_mod.to_html(data)
    assert data.digest in out
    assert "trace-tests verify" in out
    assert "pip install agentrust-trace-tests==0.5.0" in out


# --- the disclaimer is part of the artifact, not the docs ------------------


def test_html_says_it_is_not_evidence() -> None:
    out = report_mod.to_html(_build(load_vector("valid_level0.json")))
    assert "not evidence" in out.lower()


def test_json_carries_the_same_disclaimer() -> None:
    parsed = json.loads(report_mod.to_json(_build(load_vector("valid_level0.json"))))
    assert "not signed" in parsed["disclaimer"]


# --- self-contained ---------------------------------------------------------


def test_html_makes_no_network_requests() -> None:
    """An artifact whose point is needing no third party must not fetch one."""
    out = report_mod.to_html(_build(load_vector("valid_level0.json")))
    # The SVG xmlns is a namespace identifier, not a resource the page loads, so
    # the assertion is about fetching rather than about the string "http".
    for pattern in ("<script", "src=", "@import", "<link", "xlink:href", "<image", "url("):
        assert pattern not in out, f"report reaches outside itself: {pattern}"


def test_html_escapes_record_content() -> None:
    record = load_vector("valid_level0.json")
    record["transparency"] = "https://x/<script>alert(1)</script>"
    out = report_mod.to_html(_build(record))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


# --- badge -----------------------------------------------------------------


@pytest.mark.parametrize(
    "vector,expected",
    [("valid_level0.json", "Level 0"), ("invalid_wrong_profile.json", "fails Level 0")],
)
def test_badge_states_the_level(vector: str, expected: str) -> None:
    svg = report_mod.badge_svg(_build(load_vector(vector)))
    assert svg.startswith("<svg")
    assert expected in svg


def test_badge_is_static_svg() -> None:
    """No fetch. The xmlns URI is a namespace name and is never requested."""
    svg = report_mod.badge_svg(_build(load_vector("valid_level0.json")))
    for pattern in ("<image", "xlink:href", "url(", "<script"):
        assert pattern not in svg, f"badge resolves elsewhere: {pattern}"


# --- unanchored records ----------------------------------------------------


def test_unanchored_record_says_so_rather_than_showing_blank() -> None:
    record = load_vector("valid_level0.json")
    record.pop("transparency", None)
    out = report_mod.to_html(_build(record))
    assert "unanchored" in out

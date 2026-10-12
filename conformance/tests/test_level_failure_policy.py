"""CLI and portable reports share one level-failure projection."""

from __future__ import annotations

import pytest

from trace_tests import cli as cli_module
from trace_tests import report as report_module
from trace_tests.cli import _print_report
from trace_tests.modules.unverified import finding_counts_as_level_failure
from trace_tests.report import _tally
from trace_tests.result import Finding, Status


@pytest.mark.parametrize("level", [0, 1, 2])
@pytest.mark.parametrize("status", list(Status))
def test_cli_report_and_policy_agree_for_every_status_and_level(
    status: Status,
    level: int,
) -> None:
    finding = Finding("TR-NEW-001", status, "synthetic")
    expected = finding_counts_as_level_failure(finding, level)
    results = {"TR-X": [finding]}

    report_failures, _ = _tally(results, level)
    cli_exit = _print_report("record.json", "trace", level, results)

    assert bool(report_failures) is expected
    assert bool(cli_exit) is expected


@pytest.mark.parametrize(
    ("status", "forced_contribution"),
    [
        (Status.PASS, True),
        (Status.FAIL, False),
        (Status.SKIP, True),
        (Status.UNVERIFIED, False),
    ],
)
def test_each_projection_delegates_once_even_for_wrong_branch_differentials(
    monkeypatch: pytest.MonkeyPatch,
    status: Status,
    forced_contribution: bool,
) -> None:
    finding = Finding("TR-X-001", status, "synthetic")
    results = {"TR-X": [finding]}
    cli_calls: list[tuple[str, int]] = []
    report_calls: list[tuple[str, int]] = []

    def cli_policy(item: Finding, level: int) -> bool:
        cli_calls.append((item.code, level))
        return forced_contribution

    def report_policy(item: Finding, level: int) -> bool:
        report_calls.append((item.code, level))
        return forced_contribution

    monkeypatch.setattr(cli_module, "finding_counts_as_level_failure", cli_policy)
    monkeypatch.setattr(report_module, "finding_counts_as_level_failure", report_policy)

    assert bool(_print_report("record.json", "trace", 2, results)) is forced_contribution
    assert bool(_tally(results, 2)[0]) is forced_contribution
    assert cli_calls == [("TR-X-001", 2)]
    assert report_calls == [("TR-X-001", 2)]

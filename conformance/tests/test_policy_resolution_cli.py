"""What supplying a resolver changes, end to end, and at which level.

Two paths publish a verdict: the CLI's exit code and the report artifact. Both
are exercised here on the same record, by running the suite and reading what it
produced. Nothing constructs a ``Finding``: a test that builds its own finding
and hands it to the reporting layer tests whichever code it happened to name,
and stays green while the table it is supposed to be guarding is wrong.

The measurement is a difference. The record is unsigned and carries no
transcript, so it fails for reasons that have nothing to do with policy
resolution — constant across both legs, and cancelling in the delta. What is
left is the one finding under test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from trace_tests import report as report_mod
from trace_tests.cli import main
from trace_tests.runner import run

VECTOR_DIR = Path(__file__).parent / "vectors" / "policy-resolution"
UNREACHABLE = VECTOR_DIR / "05-referent-unreachable-no-route.json"
RESOLVES = VECTOR_DIR / "02-resolved-and-matches.json"
MALFORMED = VECTOR_DIR / "08-policy-uri-is-a-relative-reference.json"

# A century, so the frozen iat in the vectors cannot confound the exit code.
# The alternative is refreshing iat, which would move the committed bytes and
# break the set's own byte-reproduction guard.
MAX_AGE = "3153600000"
NONCE = "Zm9yLXRoZS1yZWNvcmQtbm9uY2U"

_RESULT = re.compile(r"Result: (PASS|FAIL)\s+\((\d+) checks(?:, (\d+) failure\(s\))?")


def _record_path(tmp_path: Path, vector: Path) -> str:
    record = json.loads(vector.read_text(encoding="utf-8"))["record"]
    p = tmp_path / "record.json"
    p.write_text(json.dumps(record), encoding="utf-8")
    return str(p)


def _verify(record_path: str, level: int, *, with_policy_dir: bool):
    args = [
        "verify", "--record", record_path, "--level", str(level),
        "--max-age", MAX_AGE, "--expected-nonce", NONCE,
    ]
    if with_policy_dir:
        args += ["--policy-dir", str(VECTOR_DIR)]
    return CliRunner().invoke(main, args)


def _failures(output: str) -> int:
    match = _RESULT.search(output)
    assert match, f"no result line in output:\n{output}"
    return int(match.group(3) or 0)


def _resolver():
    manifest = json.loads((VECTOR_DIR / "resolutions.json").read_text(encoding="utf-8"))

    def _resolve(uri: str) -> bytes:
        return (VECTOR_DIR / manifest[uri]).read_bytes()

    return _resolve


@pytest.mark.level0
@pytest.mark.parametrize("level,delta", [(0, 0), (1, 0), (2, 1)])
def test_supplying_a_resolver_changes_the_failure_count_only_from_level_two(
    tmp_path, level, delta
):
    """The registered level, observed through the CLI rather than asserted.

    An unreachable bundle is unverified at every level. Whether that *counts*
    is the table's business, and TR-POL-003 is registered at 2, so the same
    finding is tolerated at 0 and 1 and fails at 2.
    """
    record = _record_path(tmp_path, UNREACHABLE)
    without = _verify(record, level, with_policy_dir=False)
    with_dir = _verify(record, level, with_policy_dir=True)

    assert _failures(with_dir.output) - _failures(without.output) == delta, (
        f"level {level}\n--- without --policy-dir ---\n{without.output}"
        f"\n--- with --policy-dir ---\n{with_dir.output}"
    )


@pytest.mark.level0
@pytest.mark.parametrize("with_policy_dir", [False, True])
def test_level_zero_exits_zero_either_way(tmp_path, with_policy_dir):
    """An unresolvable bundle must not sink a Level 0 record.

    The record is unsigned, so TR-SIG-005 is unverified here too. Both codes
    are tolerated at Level 0 and neither is a pass; the exit code is the
    difference between "not proven" and "wrong".
    """
    record = _record_path(tmp_path, UNREACHABLE)
    result = _verify(record, 0, with_policy_dir=with_policy_dir)
    assert result.exit_code == 0, result.output
    assert "UNVERIFIED" in result.output


@pytest.mark.level0
def test_a_resolvable_bundle_reports_a_pass_through_the_cli(tmp_path):
    """The must-accept leg: supplying a resolver must not cost a record anything."""
    record = _record_path(tmp_path, RESOLVES)
    with_dir = _verify(record, 0, with_policy_dir=True)
    assert with_dir.exit_code == 0, with_dir.output
    assert "TR-POL-003" not in with_dir.output, (
        "a passing TR-POL-003 names no code in its message, by house convention"
    )


@pytest.mark.level0
@pytest.mark.parametrize("level", [0, 1, 2])
def test_a_malformed_reference_fails_with_and_without_a_resolver(tmp_path, level):
    """The ordering, observed: a record defect is not conditional on the network.

    This is the constant the differential rests on. If the malformed check ran
    after the resolver check, this record would report nothing at all offline,
    and an offline verification would be blind to a defect on the record's face.
    """
    record = _record_path(tmp_path, MALFORMED)
    for with_dir in (False, True):
        result = _verify(record, level, with_policy_dir=with_dir)
        assert result.exit_code == 1, result.output
        assert "TR-POL-003" in result.output
        assert "relative reference" in result.output


@pytest.mark.level0
@pytest.mark.parametrize("level,delta", [(0, 0), (1, 0), (2, 1)])
def test_the_report_path_carries_the_same_deltas(level, delta):
    """The second publisher. A report that disagreed with the CLI would be worse
    than no report, so the two are measured against the same record."""
    record = json.loads(UNREACHABLE.read_text(encoding="utf-8"))["record"]

    def build(resolver):
        by_level = {
            lv: run(record, "trace", lv, max_age_seconds=10**9,
                    expected_nonce=NONCE, policy_resolver=resolver)
            for lv in range(level + 1)
        }
        return report_mod.build(
            record=record,
            record_path=str(UNREACHABLE),
            record_format="trace",
            results_by_level=by_level,
            suite_version="test",
            library_version=None,
            generated_at="1970-01-01T00:00:00Z",
        )

    without = build(None)
    with_resolver = build(_resolver())
    got = _level_failures(with_resolver, level) - _level_failures(without, level)
    assert got == delta, f"level {level}: report delta {got}, expected {delta}"


def _level_failures(report, level: int) -> int:
    entry = next(lv for lv in report.levels if lv.level == level)
    return entry.failures

"""The measurement harness's own guards, checked the way it checks everything else.

`measurement/scripts/mutate_modules.py` exists to answer one question: would this
repository's suite notice if a conformance check silently stopped working? Its answer is
only worth reading if the run that produced it actually measured something, so the script
carries guards against the ways a run can produce a confident number while measuring
nothing.

Until this file, those guards had no test. Deleting `assert_suite_imports_this_checkout()`
from `main()` left the whole suite green, which is precisely the property the script was
written to detect, one level up.

**Method.** Each test builds a synthetic checkout — the smallest tree with the shape the
script requires — breaks one precondition, runs the script as a subprocess, and asserts
it refuses rather than reports. The synthetic tree carries one guarded check and one
unguarded one, so the reporting path is exercised too and not only the aborts.

**Why a subprocess and not an import.** The script reads `sys.argv` and resolves
`TRACE_TESTS` at module scope, then runs pytest against that tree. Importing it would
bind those to this repository. Running it is also what a person does, so it is what the
guard has to survive.

**Exit codes are not enough on their own.** A refusal exits 1 and so does a completed run
that found an unverified check, so every test here asserts on the message as well.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "measurement" / "scripts" / "mutate_modules.py"

MODULE = '''\
from __future__ import annotations
from typing import Any
from trace_tests.result import Finding, Status


def check(record: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if record.get("guarded") != "ok":
        findings.append(Finding("TR-FAK-001", Status.FAIL, "TR-FAK-001: guarded is wrong"))
    if record.get("unguarded") != "ok":
        findings.append(Finding("TR-FAK-002", Status.FAIL, "TR-FAK-002: unguarded is wrong"))
    return findings
'''

# Asserts on the outcome, not on the code being present. A test that only checks the code
# is unmoved by Status.FAIL becoming Status.PASS, and the site would measure as unverified
# for a reason that has nothing to do with coverage.
SUITE = '''\
from trace_tests.modules.tr_fak import check


def test_guarded_failure_path_is_covered():
    failed = [f for f in check({"guarded": "no", "unguarded": "ok"}) if f.failed()]
    assert any(f.code == "TR-FAK-001" for f in failed)


def test_control_passes():
    assert check({"guarded": "ok", "unguarded": "ok"}) == []
'''

RESULT = '''\
from __future__ import annotations
import enum
from dataclasses import dataclass


class Status(enum.Enum):
    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True)
class Finding:
    code: str
    status: Status
    message: str

    def failed(self) -> bool:
        return self.status is Status.FAIL
'''


def _checkout(root: Path, *, module: str = MODULE, suite: str = SUITE) -> Path:
    """The smallest tree the script will accept: a package, a tr_ module, and a suite."""
    package = root / "src" / "trace_tests"
    (package / "modules").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\npythonpath = ["src"]\n'
    )
    (package / "__init__.py").write_text("")
    (package / "result.py").write_text(RESULT)
    (package / "modules" / "__init__.py").write_text("")
    (package / "modules" / "tr_fak.py").write_text(module)
    (root / "tests" / "test_fake.py").write_text(suite)
    return root


def _run(checkout: Path, *, pythonpath: str = "src") -> subprocess.CompletedProcess[str]:
    """Run the harness against *checkout*, as a person would.

    `PYTHONPATH` is relative and resolved by each subprocess against its own working
    directory, which the script sets to the checkout — so "src" reaches that tree's
    package and stands in for the editable install a real checkout has.
    """
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(checkout)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": pythonpath},
    )


# --- the reporting path, so the aborts are not the only thing covered ---------------


def test_a_run_reports_the_guarded_check_and_names_the_unguarded_one(tmp_path: Path) -> None:
    """The positive control.

    The synthetic tree has one check a test notices and one nothing notices. A harness
    that reported both the same way would be useless in either direction, so this asserts
    the two are distinguished and that the unguarded one is named.
    """
    result = _run(_checkout(tmp_path))
    assert "TR-FAK-001" in result.stdout and "margin 1" in result.stdout
    assert "TR-FAK-002" in result.stdout
    assert "unverified      : 1  ['TR-FAK-002']" in result.stdout
    assert result.returncode == 1, "a run that found an unverified check must exit non-zero"


def test_a_fully_guarded_tree_exits_zero(tmp_path: Path) -> None:
    """The other half of the control: the harness must be able to say yes."""
    suite = SUITE + '''

def test_unguarded_failure_path_is_covered_too():
    failed = [f for f in check({"guarded": "ok", "unguarded": "no"}) if f.failed()]
    assert any(f.code == "TR-FAK-002" for f in failed)
'''
    result = _run(_checkout(tmp_path, suite=suite))
    assert "unverified      : 0" in result.stdout
    assert result.returncode == 0, result.stdout


def test_the_module_is_restored_after_the_run(tmp_path: Path) -> None:
    """Every site is rewritten and put back. A harness that leaves the tree mutated has
    corrupted the thing it was measuring."""
    checkout = _checkout(tmp_path)
    module = checkout / "src" / "trace_tests" / "modules" / "tr_fak.py"
    before = module.read_text()
    _run(checkout)
    assert module.read_text() == before


# --- the guards, one broken precondition each ---------------------------------------


def test_a_directory_without_the_package_is_refused(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    result = _run(tmp_path)
    assert result.returncode != 0
    assert "checkout not found" in result.stderr


def test_a_module_with_no_fail_sites_is_refused(tmp_path: Path) -> None:
    """Zero sites would otherwise be reported as perfect coverage."""
    module = MODULE.replace("Status.FAIL", "Status.PASS")
    result = _run(_checkout(tmp_path, module=module))
    assert result.returncode != 0
    assert "no FAIL sites found" in result.stderr


def test_a_fail_finding_whose_status_line_is_out_of_reach_is_refused(tmp_path: Path) -> None:
    """The rewrite targets the line carrying `Status.FAIL`, searched within six lines of
    the call. Past that the script refuses rather than guessing, because a mis-targeted
    mutation measures a site nobody asked about and reports it under the wrong code."""
    module = '''\
from __future__ import annotations
from typing import Any
from trace_tests.result import Finding, Status


def check(record: dict[str, Any]) -> list[Finding]:
    if record.get("guarded") == "ok":
        return []
    return [
        Finding(
            "TR-FAK-001",
            "a"
            "b"
            "c"
            "d"
            "e"
            "f",
            Status.FAIL,
        )
    ]
'''
    result = _run(_checkout(tmp_path, module=module))
    assert result.returncode != 0
    assert "Refusing to guess which line to rewrite" in result.stderr


def test_a_fail_status_reached_through_a_name_is_not_collected(tmp_path: Path) -> None:
    """A limit of the walk, asserted so it is a known shape rather than a surprise.

    `fail_sites` recognises `Status.FAIL` as a literal attribute in the call's arguments.
    A module that binds it to a name first constructs a failing Finding the walk does not
    see, and the run reports on the sites it did find without mentioning the omission.

    Nothing in this repository writes them that way, and the count in the report is
    checkable against `grep -c Status.FAIL`, so this is recorded rather than fixed. If a
    conformance module ever does bind the status indirectly, this test fails and says so.
    """
    module = '''\
from __future__ import annotations
from typing import Any
from trace_tests.result import Finding, Status

_FAIL = Status.FAIL


def check(record: dict[str, Any]) -> list[Finding]:
    if record.get("guarded") == "ok":
        return []
    return [Finding("TR-FAK-001", _FAIL, "indirect")]
'''
    result = _run(_checkout(tmp_path, module=module))
    assert result.returncode != 0
    assert "no FAIL sites found" in result.stderr, (
        "the walk now sees an indirectly bound Status.FAIL; the docstring above is stale"
    )


def test_a_suite_that_imports_another_tree_is_refused(tmp_path: Path) -> None:
    """The defect reported on #57 and fixed by #59.

    A stale editable install leaves the baseline green and every mutation unobserved:
    pytest never imports the file being rewritten, so every site reports that nothing
    noticed — which reads exactly like a suite that guards nothing.
    """
    measured = _checkout(tmp_path / "measured")
    imported = _checkout(tmp_path / "imported")
    result = _run(measured, pythonpath=str(imported / "src"))
    assert result.returncode != 0
    assert "imports trace_tests from" in result.stderr
    assert str(imported / "src" / "trace_tests") in result.stderr


def test_an_uninstallable_package_is_refused_rather_than_measured(tmp_path: Path) -> None:
    """The probe's own failure is a refusal too, not something to measure past."""
    checkout = _checkout(tmp_path)
    (checkout / "src" / "trace_tests" / "__init__.py").write_text("raise ImportError('broken')\n")
    result = _run(checkout)
    assert result.returncode != 0
    assert "could not import trace_tests" in result.stderr


def test_a_red_baseline_is_refused(tmp_path: Path) -> None:
    """Mutating an already-red suite measures nothing: a failure cannot be attributed."""
    suite = SUITE + "\n\ndef test_already_failing():\n    assert False\n"
    result = _run(_checkout(tmp_path, suite=suite))
    assert result.returncode != 0
    assert "baseline is not green" in result.stderr


def test_caches_are_purged_before_every_suite_run(tmp_path: Path) -> None:
    """`Status.FAIL` and `Status.PASS` are the same length, so a rewrite changes no file
    size and a run can end up measuring the previous iteration's bytecode. That inflates
    margins and reports unguarded checks as verified, which is the one direction this
    instrument must never fail in.

    Asserted on the behaviour rather than on the downstream symptom: a `__pycache__` left
    in the tree must not survive the run.
    """
    checkout = _checkout(tmp_path)
    cache = checkout / "src" / "trace_tests" / "modules" / "__pycache__"
    cache.mkdir()
    sentinel = cache / "stale.pyc"
    sentinel.write_bytes(b"stale")
    _run(checkout)
    assert not sentinel.exists(), "a stale __pycache__ survived the run"


@pytest.mark.parametrize("missing", ["src", "src/trace_tests"])
def test_a_partial_checkout_is_refused(tmp_path: Path, missing: str) -> None:
    """`Path("")` and `Path(".")` both resolve to wherever the caller stands, which is how
    a measurement ends up reporting on the wrong tree."""
    checkout = _checkout(tmp_path)
    target = checkout / missing
    for child in sorted(target.rglob("*"), reverse=True):
        child.unlink() if child.is_file() else child.rmdir()
    target.rmdir()
    result = _run(checkout)
    assert result.returncode != 0
    assert "checkout not found" in result.stderr

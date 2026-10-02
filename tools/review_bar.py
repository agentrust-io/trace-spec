#!/usr/bin/env python3
"""Approximate the library-fix check CONTRIBUTING.md asks a pull request to describe.

"Before a pull request is reviewed" asks a change to code or a schema that fixes
a bug, or makes it reject input it used to accept, to show a test that fails
when the change is switched off, keeping any names it adds. A description can
say that without anyone having run it. For Python under ``src/``, this tool runs
the nearest thing it can run mechanically and reports what it saw. It exits 0
whatever it finds: what it finds is evidence for the reviewer, not a verdict.

The pull request's changed tests run on its head first. A test that fails there
proves nothing either way, so it is left out, and a test that passes there is
the only kind whose failure on the base means something.

The changed test files, with any other file the change adds or edits under
``tests/``, are then put on top of the merge base and run against the code as it
was. This switches off the whole change, names included, so it approximates the
check rather than running it. Each failure is sorted by its message: behaviour
(an assertion, ``pytest.raises`` not raising, a wrong exception), or a name,
module or file the change adds (an import error, an unexpected keyword, a
collection failure, or a message naming something the change defines or adds).
The sorting can be wrong both ways.

The tests and ``conftest.py`` come from the pull request, and so does the
workflow file that decides which copy of this tool runs, so a pull request can
shape its own report. Read it as evidence the change brought, not as a gate.

Usage: ``python tools/review_bar.py --base BASE --head HEAD [--repo PATH] [--timeout SECONDS]
[--summary PATH]``.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import signal
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# A failure message that says a name is missing. Anything else that fails is
# behaviour: an AssertionError, pytest's "DID NOT RAISE", or a wrong exception.
# An attribute missing from None is behaviour too: something returned None.
MISSING_NAME = re.compile(
    r"\b(ImportError|ModuleNotFoundError|NameError)\b"
    r"|\bAttributeError: (?!'NoneType')\S.*\bhas no attribute\b"
    r"|\bTypeError\b.*(unexpected keyword argument|missing \d+ required"
    r"|takes \d+ positional arguments? but \d+ (were|was) given)"
)

# Environment the child test runs must not inherit: a test could otherwise write
# the job summary, or the workflow's outputs, as if it were this tool.
WITHHELD = ("GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH")


def missing_name(message: str, new_names: frozenset[str] = frozenset()) -> bool:
    """Whether a failure message says a name is missing, or names one the change adds.

    Only the message is read, not the traceback or the echoed test source, where
    a local variable can share a name with something the change defines.
    """
    if MISSING_NAME.search(message):
        return True
    return any(re.search(rf"(?<!\w){re.escape(n)}(?!\w)", message) for n in new_names)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout


def show(repo: Path, rev: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), "show", f"{rev}:{path}"], capture_output=True, check=True
    ).stdout


def export(repo: Path, rev: str, dest: Path) -> None:
    """Check *rev* out at *dest* as a detached worktree, so tests that ask git still work."""
    git(repo, "worktree", "add", "--detach", "--force", str(dest), rev)
    _WORKTREES.append(dest)


_WORKTREES: list[Path] = []


def _remove_worktrees(repo: Path) -> None:
    """Remove the worktrees this run made, and only those."""
    while _WORKTREES:
        dest = _WORKTREES.pop()
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(dest)],
                       capture_output=True)


def _name_status(repo: Path, base: str, head: str) -> list[tuple[str, str]]:
    raw = git(repo, "diff", "--no-ext-diff", "--no-color", "-z", "--name-status",
              "--no-renames", base, head)
    parts = [p for p in raw.split("\0") if p]
    return list(zip(parts[0::2], parts[1::2], strict=True))


def changed(repo: Path, base: str, head: str) -> tuple[list[str], list[str]]:
    """Test files and src Python files added or modified between base and head."""
    tests, _support, src = changed_all(repo, base, head)
    return tests, src


def changed_all(repo: Path, base: str, head: str) -> tuple[list[str], list[str], list[str]]:
    """As ``changed``, plus the other files under tests/ the change adds or edits.

    A new fixture in ``conftest.py`` or a new helper module has to travel with the
    tests that use it, or they fail on the base for a reason that is neither the
    bug nor a name in ``src/``.
    """
    tests, support, src = [], [], []
    for status, path in _name_status(repo, base, head):
        if status not in ("A", "M"):
            continue
        name = path.rsplit("/", 1)[-1]
        if path.startswith("tests/") and name.startswith("test_") and name.endswith(".py"):
            tests.append(path)
        elif path.startswith("tests/"):
            support.append(path)
        elif path.startswith("src/") and path.endswith(".py"):
            src.append(path)
    return sorted(tests), sorted(support), sorted(src)


def _names(source: str) -> set[str]:
    """Functions, classes, parameters and module-level names a module defines."""
    found: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            found.update(x.arg for x in [*a.posonlyargs, *a.args, *a.kwonlyargs])
    for node in tree.body:
        if isinstance(node, ast.Assign):
            found.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return found


def added_names(repo: Path, base: str, head: str, src: list[str]) -> set[str]:
    """Names the change adds: definitions under ``src/`` and the names of added files."""
    added: set[str] = set()
    for path in src:
        try:
            after = _names(show(repo, head, path).decode("utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        try:
            before = _names(show(repo, base, path).decode("utf-8"))
        except (RuntimeError, subprocess.CalledProcessError, SyntaxError, UnicodeDecodeError):
            before = set()
        added |= after - before
    for status, path in _name_status(repo, base, head):
        if status == "A":
            added.add(path.rsplit("/", 1)[-1])
    # Short names are too common to tell a message about them from anything else.
    return {n for n in added if len(n) >= 4}


@dataclass
class Outcome:
    test: str
    result: str  # passed, skipped, behaviour, name
    detail: str = ""

    @property
    def failed(self) -> bool:
        return self.result in ("behaviour", "name")


def run_tests(
    tree: Path, tests: list[str], timeout: int, new_names: frozenset[str] = frozenset()
) -> tuple[int, list[Outcome]]:
    """Run *tests* in *tree*; return pytest's exit code and each test's outcome."""
    junit = tree / ".review-bar-junit.xml"
    env = {k: v for k, v in os.environ.items() if k not in WITHHELD}
    env.update(PYTHONPATH=str(tree / "src"), PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "-o", "addopts=", "--continue-on-collection-errors",
             f"--junitxml={junit}", *tests],
            cwd=tree, env=env, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        junit.unlink(missing_ok=True)
        return -1, []
    outcomes = []
    if junit.exists():
        for case in ET.parse(junit).getroot().iter("testcase"):
            name = f"{case.get('classname', '')}::{case.get('name', '')}".strip(":")
            bad = case.find("failure")
            if bad is None:
                bad = case.find("error")
            if bad is not None:
                message = bad.get("message") or ""
                kind = "name" if missing_name(message, new_names) else "behaviour"
                first = message.splitlines()[:1]
                outcomes.append(Outcome(name, kind, first[0][:160] if first else ""))
            elif case.find("skipped") is not None:
                outcomes.append(Outcome(name, "skipped"))
            else:
                outcomes.append(Outcome(name, "passed"))
        junit.unlink()
    return proc.returncode, outcomes


def _capped(lines: list[str], limit: int = 25) -> list[str]:
    return lines if len(lines) <= limit else [*lines[:limit], f"- and {len(lines) - limit} more"]


@dataclass
class Report:
    base: str
    head: str
    tests: list[str]
    src: list[str]
    base_ran: bool = False
    base_outcomes: list[Outcome] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def markdown(self) -> str:
        out = [f"## Review bar: {self.base[:7]}..{self.head[:7]}", ""]
        if self.notes:
            out += [f"- {n}" for n in self.notes] + [""]
        if self.base_ran:
            behaviour = [o for o in self.base_outcomes if o.result == "behaviour"]
            name = [o for o in self.base_outcomes if o.result == "name"]
            rest = [o for o in self.base_outcomes if o.result in ("passed", "skipped")]
            out += ["### Changed tests that pass on the head, run against the merge base", ""]
            out.append(
                f"{len(behaviour)} fail on behaviour, {len(name)} fail on a missing name "
                f"or file, {len(rest)} pass or skip."
            )
            out.append(
                "The sorting reads each failure's message. A test can fail on a signature"
                " the change adds without naming it, and a message can mention a new name"
                " by chance, so read the messages before relying on the sorting."
            )
            out.append("")
            groups = (("Fail on behaviour", behaviour), ("Fail on a missing name or file", name))
            for title, group in groups:
                if group:
                    shown = [f"- `{o.test}`: `{o.detail.replace('`', chr(39))}`" for o in group]
                    out += [f"{title}:", ""] + _capped(shown) + [""]
        return "\n".join(out).rstrip() + "\n"


def review(repo: Path, base: str, head: str, timeout: int = 120) -> Report:
    head = git(repo, "rev-parse", head).strip()
    merge_base = git(repo, "merge-base", base, head).strip()
    tests, support, src = changed_all(repo, merge_base, head)
    report = Report(merge_base, head, tests, src)
    if not tests:
        report.notes.append("No test file under tests/ is added or changed, so nothing was run.")
        return report
    names = frozenset(added_names(repo, merge_base, head, src))
    try:
        _run(repo, merge_base, head, tests, support, names, report, timeout)
    finally:
        _remove_worktrees(repo)
    return report


def _run(
    repo: Path, merge_base: str, head: str, tests: list[str], support: list[str],
    names: frozenset[str], report: Report, timeout: int,
) -> None:
    with tempfile.TemporaryDirectory(prefix="review-bar-") as tmp:
        after = Path(tmp) / "head"
        export(repo, head, after)
        code, head_outcomes = run_tests(after, tests, timeout, names)
        if code == -1:
            report.notes.append(f"The changed tests timed out on the head after {timeout} s.")
            return
        passed = {o.test for o in head_outcomes if o.result == "passed"}
        failing = sorted(o.test for o in head_outcomes if o.failed)
        if failing:
            report.notes.append(
                f"{len(failing)} changed test(s) fail on the head itself, so they are left "
                "out: " + ", ".join(f"`{t}`" for t in failing[:10])
                + (" and more." if len(failing) > 10 else ".")
            )
        if not passed:
            report.notes.append(
                f"No changed test passes on the head (pytest exited {code}), so the base run"
                " was not started."
            )
            return
        before = Path(tmp) / "base"
        export(repo, merge_base, before)
        for path in [*tests, *support]:
            target = before / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(show(repo, head, path))
        code, base_outcomes = run_tests(before, tests, timeout, names)
        if code == -1:
            report.notes.append(f"The base run timed out after {timeout} s.")
        else:
            report.base_ran = True
            # A test that passes on the head but has no outcome on the base was not
            # collected there: its file needs something the change adds.
            by_test = {o.test: o for o in base_outcomes}
            report.base_outcomes = [
                by_test.get(t, Outcome(t, "name", "not collected on the base"))
                for t in sorted(passed)
            ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--timeout", type=int, default=120, help="seconds per test run")
    parser.add_argument("--summary", type=Path, help="append the report here as well")
    args = parser.parse_args(argv)
    # A cancelled job sends SIGTERM; exiting through Python runs the cleanup.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        text = review(args.repo, args.base, args.head, args.timeout).markdown()
    except Exception as exc:  # noqa: BLE001 - the report must never fail the build
        text = f"## Review bar\n\nThe review bar could not finish: {type(exc).__name__}: {exc}\n"
    print(text)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

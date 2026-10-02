#!/usr/bin/env python3
"""Approximate the two library-fix checks CONTRIBUTING.md asks a pull request to describe.

"Before a pull request is reviewed" asks a change to code or a schema that fixes
a bug, or makes it reject input it used to accept, to show a test that fails
when the change is switched off, keeping any names it adds, and one other fix
run against the tests. A description can say both without anyone having run
either. For Python under ``src/``, this tool runs the nearest things it can run
mechanically and reports what it saw. It exits 0 whatever it finds: what it
finds is evidence for the reviewer, not a verdict.

The pull request's changed tests run on its head first. A test that fails there
proves nothing either way, so it is left out of both sections below, and a test
that passes there is the only kind whose failure elsewhere means something.

Base run
    The changed test files, with any other file the change adds or edits under
    ``tests/``, are put on top of the merge base and run against the code as it
    was. This switches off the whole change, names included, so it approximates
    the first check rather than running it. Each failure is sorted by its
    message: behaviour (an assertion, ``pytest.raises`` not raising, a wrong
    exception), or a name, module or file the change adds (an import error, an
    unexpected keyword, a collection failure, or a message naming something the
    change defines or adds). The sorting can be wrong both ways, so this section
    is the weaker evidence.

Mutants
    Each line the pull request adds under ``src/`` is a site for small edits a
    reviewer might have written instead: a ``raise`` deleted, a comparison
    with its boundary moved or its sense negated, ``and`` and ``or`` swapped. A
    mutant counts as caught when a changed test that passed on the head fails on
    it, or is no longer collected because its module failed to import. A mutant
    no changed test catches is a fix those tests cannot tell apart from the one
    submitted, unless it changes nothing a test could see.

The tests and ``conftest.py`` come from the pull request, and so does the
workflow file that decides which copy of this tool runs, so a pull request can
shape its own report. Read it as evidence the change brought, not as a gate.

Usage: ``python tools/review_bar.py --base BASE --head HEAD [--summary PATH]``.
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
import time
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


SWAPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.In: ast.NotIn, ast.NotIn: ast.In,
    ast.Is: ast.IsNot, ast.IsNot: ast.Is,
}
OP_TEXT = {
    ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!=",
    ast.In: "in", ast.NotIn: "not in", ast.Is: "is", ast.IsNot: "is not",
}


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


def added_lines(repo: Path, base: str, head: str, path: str) -> set[int]:
    """Line numbers in *head*'s copy of *path* that the diff adds."""
    lines: set[int] = set()
    for hunk in re.finditer(
        r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@",
        git(repo, "diff", "--no-ext-diff", "--no-color", "-U0", base, head, "--", path),
        re.M,
    ):
        start, count = int(hunk.group(1)), int(hunk.group(2) or "1")
        lines.update(range(start, start + count))
    return lines


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


def judge(
    head_passed: set[str], code: int, outcomes: list[Outcome],
    head_failed: frozenset[str] = frozenset(),
) -> str:
    """Whether a mutant is caught: a test that passed on the head fails on it.

    A test that passed on the head and has no outcome on the mutant counts too,
    but only when its module failed to collect, which is what a broken import
    looks like, and did collect on the head. A test id can also vanish because
    the mutant changed a value a parametrize list is built from, and that alone
    is not a failure.
    """
    if code == -1:
        return "timeout"
    if not outcomes:
        return "unjudged"
    if any(o.failed for o in outcomes if o.test in head_passed):
        return "caught"
    seen = {o.test for o in outcomes}
    broken = {o.test for o in outcomes if o.failed and "::" not in o.test} - head_failed
    def module_broke(test: str) -> bool:
        # A test in a class has the class in its id: tests.test_mod.TestA::a.
        owner = test.split("::", 1)[0]
        return any(owner == m or owner.startswith(m + ".") for m in broken)

    if any(module_broke(t) for t in head_passed - seen):
        return "caught"
    return "survived"


@dataclass
class Mutant:
    path: str
    line: int
    col: int
    edit: str
    status: str = ""  # caught, survived, timeout, unjudged, not run


class _Sites(ast.NodeVisitor):
    """Mutation sites on statements and expressions that touch an added line."""

    def __init__(self, lines: set[int]) -> None:
        self.lines = lines
        self.sites: list[tuple[int, int, str, ast.AST | _Op]] = []

    def _touches(self, node: ast.expr | ast.stmt) -> bool:
        end = node.end_lineno or node.lineno
        return any(n in self.lines for n in range(node.lineno, end + 1))

    def visit_Raise(self, node: ast.Raise) -> None:
        if self._touches(node):
            self.sites.append((node.lineno, node.col_offset, "delete the raise", node))
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if self._touches(node):
            for i, op in enumerate(node.ops):
                swap = SWAPS.get(type(op))
                if swap is not None:
                    edit = f"{OP_TEXT[type(op)]} becomes {OP_TEXT[swap]}"
                    self.sites.append((node.lineno, node.col_offset, edit, _Op(node, i, swap)))
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if self._touches(node):
            edit = "and becomes or" if isinstance(node.op, ast.And) else "or becomes and"
            self.sites.append((node.lineno, node.col_offset, edit, node))
        self.generic_visit(node)


@dataclass
class _Op:
    node: ast.Compare
    index: int
    swap: type[ast.cmpop]


def _mutate(source: str, lines: set[int], site: int) -> str | None:
    """*source* with the *site*-th mutation applied, or None if it does not compile."""
    tree = ast.parse(source)
    sites = _Sites(lines)
    sites.visit(tree)
    target = sites.sites[site][3]
    if isinstance(target, _Op):
        target.node.ops[target.index] = target.swap()
    elif isinstance(target, ast.BoolOp):
        target.op = ast.Or() if isinstance(target.op, ast.And) else ast.And()
    else:
        for parent in ast.walk(tree):
            for _field, value in ast.iter_fields(parent):
                if isinstance(value, list) and target in value:
                    value[value.index(target)] = ast.copy_location(ast.Pass(), target)
    text = ast.unparse(ast.fix_missing_locations(tree))
    try:
        compile(text, "<mutant>", "exec")
    except SyntaxError:
        return None
    return text


def mutants(
    repo: Path, base: str, head: str, src: list[str], notes: list[str]
) -> list[tuple[Mutant, str]]:
    """Every mutant on a line *head* adds, with the mutated source it needs."""
    out = []
    for path in src:
        try:
            source = show(repo, head, path).decode("utf-8")
            ast.parse(source)
        except (SyntaxError, UnicodeDecodeError) as exc:
            notes.append(f"`{path}` does not parse on the head ({type(exc).__name__}), "
                         "so it has no mutants.")
            continue
        lines = added_lines(repo, base, head, path)
        sites = _Sites(lines)
        sites.visit(ast.parse(source))
        for index, (line, col, edit, _) in enumerate(sites.sites):
            mutated = _mutate(source, lines, index)
            if mutated is not None:
                out.append((Mutant(path, line, col, edit), mutated))
    return out


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
    mutants: list[Mutant] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def markdown(self) -> str:
        out = [f"## Review bar: {self.base[:7]}..{self.head[:7]}", ""]
        if self.notes:
            out += [f"- {n}" for n in self.notes] + [""]
        ran = [m for m in self.mutants if m.status != "not run"]
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
                " by chance, so this is the weaker evidence."
                + (" The mutants below are the stronger." if ran else "")
            )
            out.append("")
            groups = (("Fail on behaviour", behaviour), ("Fail on a missing name or file", name))
            for title, group in groups:
                if group:
                    shown = [f"- `{o.test}`: `{o.detail.replace('`', chr(39))}`" for o in group]
                    out += [f"{title}:", ""] + _capped(shown) + [""]
        if self.mutants:
            count = {s: [m for m in self.mutants if m.status == s] for s in
                     ("caught", "survived", "timeout", "unjudged", "not run")}
            out += ["### Mutants on the lines this pull request adds", ""]
            out.append(
                f"{len(ran)} run: {len(count['caught'])} caught by the changed tests, "
                f"{len(count['survived'])} not caught, {len(count['timeout'])} timed out, "
                f"{len(count['unjudged'])} could not be judged, "
                f"{len(count['not run'])} not run (over the limit or out of time)."
            )
            out.append("")
            for title, key in (
                ("Not caught, so the changed tests cannot tell these apart from the change",
                 "survived"),
                ("Timed out", "timeout"),
                ("Could not be judged", "unjudged"),
                ("Not run", "not run"),
            ):
                if count[key]:
                    out += [f"{title}:", ""]
                    # Columns are 1-based. On a line with non-ASCII text they count bytes.
                    sites = [f"- `{m.path}:{m.line}:{m.col + 1}`: {m.edit}" for m in count[key]]
                    out += _capped(sites)
                    out += [""]
            if count["survived"]:
                out.append(
                    "A mutant can also change nothing a test could see, such as a raise whose"
                    " error is raised again further on, so read each one before asking for a test."
                )
        return "\n".join(out).rstrip() + "\n"


def review(
    repo: Path, base: str, head: str, max_mutants: int = 40,
    timeout: int = 120, deadline: float = 1200.0,
) -> Report:
    start = time.monotonic()
    head = git(repo, "rev-parse", head).strip()
    merge_base = git(repo, "merge-base", base, head).strip()
    tests, support, src = changed_all(repo, merge_base, head)
    report = Report(merge_base, head, tests, src)
    if not tests:
        report.notes.append("No test file under tests/ is added or changed, so nothing was run.")
        return report
    names = frozenset(added_names(repo, merge_base, head, src))
    try:
        _run(repo, merge_base, head, tests, support, src, names, report,
             max_mutants, timeout, deadline, start)
    finally:
        _remove_worktrees(repo)
    return report


def _run(
    repo: Path, merge_base: str, head: str, tests: list[str], support: list[str],
    src: list[str], names: frozenset[str], report: Report, max_mutants: int,
    timeout: int, deadline: float, start: float,
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
                "out below: " + ", ".join(f"`{t}`" for t in failing[:10])
                + (" and more." if len(failing) > 10 else ".")
            )
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
        if not src:
            report.notes.append("No Python file under src/ is added or changed, so no mutants.")
            return
        if not passed:
            report.notes.append("No changed test passes on the head, so no mutant can be judged.")
            return
        candidates = mutants(repo, merge_base, head, src, report.notes)
        if not candidates:
            report.notes.append(
                "No mutation site on the lines added under src/. The edits tried are deleting"
                " a raise, changing a comparison and swapping and/or."
            )
        for number, (mutant, mutated) in enumerate(candidates):
            report.mutants.append(mutant)
            if number >= max_mutants or time.monotonic() - start > deadline:
                mutant.status = "not run"
                continue
            original = (after / mutant.path).read_bytes()
            (after / mutant.path).write_text(mutated)
            try:
                code, outcomes = run_tests(after, tests, timeout)
            finally:
                (after / mutant.path).write_bytes(original)
            mutant.status = judge(passed, code, outcomes, frozenset(failing))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--max-mutants", type=int, default=40)
    parser.add_argument("--timeout", type=int, default=120, help="seconds per test run")
    parser.add_argument("--deadline", type=float, default=1200.0, help="seconds before "
                        "the remaining mutants are left unrun")
    parser.add_argument("--summary", type=Path, help="append the report here as well")
    args = parser.parse_args(argv)
    # A cancelled job sends SIGTERM; exiting through Python runs the cleanup.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        text = review(args.repo, args.base, args.head, args.max_mutants,
                      args.timeout, args.deadline).markdown()
    except Exception as exc:  # noqa: BLE001 - the report must never fail the build
        text = f"## Review bar\n\nThe review bar could not finish: {type(exc).__name__}: {exc}\n"
    print(text)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

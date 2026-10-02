"""tools/review_bar.py on a two-commit repository built here.

The head commit adds a refusal (``x > 100``), a new function, two new modules, a
data file and a conftest fixture, tightens a range check, and brings tests of
each kind: ones that fail on the base for behaviour, ones that fail there only
because something the change adds is missing, one that needs the new fixture,
one that needs a git checkout, and one that fails on the head itself.
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_bar", ROOT / "tools" / "review_bar.py")
assert spec is not None and spec.loader is not None
review_bar = importlib.util.module_from_spec(spec)
sys.modules["review_bar"] = review_bar
spec.loader.exec_module(review_bar)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

BASE_CORE = '''def check(x):
    if x < 0:
        raise ValueError("negative")
    return x
'''
HEAD_CORE = '''def check(x):
    if x < 0:
        raise ValueError("negative")
    if x > 100:
        raise ValueError("too big")
    return x


def limit(cap=100):
    return cap
'''
BASE_RANGES = '''def in_range(x):
    return (x >= 0
            and x < 1000)
'''
HEAD_RANGES = '''def in_range(x):
    return (x >= 0
            and x <= 100)
'''
BASE_TESTS = '''from pkg.core import check


def test_zero():
    assert check(0) == 0
'''
HEAD_TESTS = '''import pytest

from pkg.core import check


def test_zero():
    assert check(0) == 0


def test_too_big_is_refused():
    limit = 1000
    with pytest.raises(ValueError):
        check(limit)


def test_limit_is_one_hundred():
    from pkg.core import limit

    assert limit() == 100


def test_fails_on_the_head_too():
    assert check(5) == 6
'''
RANGES_TEST = '''from pkg.ranges import in_range


def test_in_range():
    assert in_range(50) and not in_range(500)
'''
FIXTURE_TEST = '''def test_uses_a_new_fixture(hundred):
    assert hundred == 100
'''
NEW_FILE_TEST = '''from pathlib import Path


def test_data():
    assert (Path(__file__).parent.parent / "data.txt").read_text() == "x\\n"
'''
NEW_MODULE_TEST = '''from pkg.extra import VALUE


def test_value():
    assert VALUE == 1
'''
MODE_MODULE = 'MODE = "strict"\n'
MODE_TEST = '''from pkg.mode import MODE


def test_mode():
    assert MODE == "strict"
'''
GIT_TEST = '''import subprocess
from pathlib import Path


def test_inside_a_git_checkout():
    out = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=Path(__file__).parent, capture_output=True, text=True,
    )
    assert out.stdout.strip() == "true"
'''
CONFTEST = "import pytest\n\n\n@pytest.fixture\ndef hundred():\n    return 100\n"


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for path, text in files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", message],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()


def _init(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str, str]:
    root = tmp_path_factory.mktemp("review-bar-repo")
    _init(root)
    base = _commit(root, {
        "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["src"]\n',
        "src/pkg/__init__.py": "",
        "src/pkg/core.py": BASE_CORE,
        "src/pkg/ranges.py": BASE_RANGES,
        "tests/test_core.py": BASE_TESTS,
    }, "base")
    head = _commit(root, {
        "src/pkg/core.py": HEAD_CORE,
        "src/pkg/ranges.py": HEAD_RANGES,
        "src/pkg/extra.py": "VALUE = 1\n",
        "src/pkg/mode.py": MODE_MODULE,
        "tests/test_mode.py": MODE_TEST,
        "data.txt": "x\n",
        "tests/conftest.py": CONFTEST,
        "tests/test_core.py": HEAD_TESTS,
        "tests/test_ranges.py": RANGES_TEST,
        "tests/test_extra.py": NEW_MODULE_TEST,
        "tests/test_data.py": NEW_FILE_TEST,
        "tests/test_fixture.py": FIXTURE_TEST,
        "tests/test_git.py": GIT_TEST,
    }, "head")
    return root, base, head


@pytest.fixture(scope="module")
def report(repo: tuple[Path, str, str]) -> object:
    root, base, head = repo
    return review_bar.review(root, base, head, timeout=120)


def _by_name(report: object) -> dict[str, str]:
    return {o.test.rsplit("::", 1)[-1]: o.result for o in report.base_outcomes}


def test_changed_files_are_the_added_and_modified_tests_support_and_src(repo):
    root, base, head = repo
    assert review_bar.changed_all(root, base, head) == (
        ["tests/test_core.py", "tests/test_data.py", "tests/test_extra.py",
         "tests/test_fixture.py", "tests/test_git.py", "tests/test_mode.py",
         "tests/test_ranges.py"],
        ["tests/conftest.py"],
        ["src/pkg/core.py", "src/pkg/extra.py", "src/pkg/mode.py", "src/pkg/ranges.py"],
    )


def test_a_test_path_git_would_quote_is_still_found(tmp_path):
    _init(tmp_path)
    base = _commit(tmp_path, {"README": "x\n"}, "base")
    head = _commit(tmp_path, {"tests/test_été.py": "def test_x():\n    pass\n"}, "head")
    assert review_bar.changed(tmp_path, base, head) == (["tests/test_été.py"], [])


def test_added_names_are_new_definitions_and_new_files(repo):
    # `cap` is added too, and left out: a three-letter name is too common to match on.
    root, base, head = repo
    src = ["src/pkg/core.py", "src/pkg/extra.py", "src/pkg/mode.py", "src/pkg/ranges.py"]
    assert review_bar.added_names(root, base, head, src) == {
        "limit", "VALUE", "MODE", "data.txt", "extra.py", "mode.py", "conftest.py",
        "test_ranges.py", "test_extra.py", "test_data.py", "test_fixture.py", "test_git.py",
        "test_mode.py",
    }


def test_a_test_that_fails_on_the_head_is_left_out_and_named(report):
    assert "test_fails_on_the_head_too" not in _by_name(report)
    assert "1 changed test(s) fail on the head itself" in report.markdown()


def test_a_test_that_fails_on_the_base_for_behaviour_is_reported_as_behaviour(report):
    outcomes = _by_name(report)
    assert outcomes["test_too_big_is_refused"] == "behaviour"
    assert outcomes["test_in_range"] == "behaviour"
    assert outcomes["test_zero"] == "passed"


def test_a_local_variable_named_like_a_new_name_does_not_make_it_a_missing_name(report):
    # test_too_big_is_refused has `limit = 1000` in its source; only the message counts.
    assert _by_name(report)["test_too_big_is_refused"] == "behaviour"


def test_a_test_that_fails_only_on_a_new_name_is_not_reported_as_behaviour(report):
    outcomes = _by_name(report)
    assert outcomes["test_limit_is_one_hundred"] == "name"
    assert outcomes["test_value"] == "name"


def test_a_test_that_reads_a_file_the_change_adds_is_not_behaviour(report):
    assert _by_name(report)["test_data"] == "name"


def test_a_changed_test_that_needs_a_git_checkout_runs_in_one(report):
    assert _by_name(report)["test_inside_a_git_checkout"] == "passed"


def test_the_worktrees_it_makes_are_removed_afterwards(repo, report):
    root, _, _ = repo
    listed = subprocess.run(
        ["git", "-C", str(root), "worktree", "list"], capture_output=True, text=True, check=True
    ).stdout
    assert len(listed.splitlines()) == 1


def test_a_fixture_the_change_adds_in_conftest_travels_with_the_tests(report):
    assert _by_name(report)["test_uses_a_new_fixture"] == "passed"


def test_the_report_names_the_counts_and_nothing_about_other_fixes(report):
    text = report.markdown()
    assert "2 fail on behaviour, 4 fail on a missing name or file, 3 pass or skip." in text
    assert "so read the messages before relying on the sorting." in text
    assert "utant" not in text


@pytest.mark.parametrize(
    ("message", "kind"),
    [
        ("ImportError: cannot import name 'limit' from 'pkg.core'", "name"),
        ("ModuleNotFoundError: No module named 'pkg.extra'", "name"),
        ("NameError: name 'limit' is not defined", "name"),
        ("AttributeError: module 'pkg.core' has no attribute 'limit'", "name"),
        ("TypeError: check() got an unexpected keyword argument 'strict'", "name"),
        ("TypeError: check() missing 1 required positional argument: 'cap'", "name"),
        ("TypeError: check() takes 1 positional argument but 2 were given", "name"),
        ("AttributeError: 'NoneType' object has no attribute 'get'", "behaviour"),
        ("Failed: DID NOT RAISE <class 'ValueError'>", "behaviour"),
        ("AssertionError: assert 1000 == 100", "behaviour"),
    ],
)
def test_failures_are_sorted_by_what_their_message_says(message, kind):
    assert ("name" if review_bar.missing_name(message) else "behaviour") == kind


@pytest.mark.parametrize(
    ("message", "kind"),
    [
        ("KeyError: 'trusted_observer'", "name"),
        ("AssertionError: KEYWORD_CALLS names ['m.f.trusted_observer']", "name"),
        ("AssertionError: assert 'trusted_observers' == 'x'", "behaviour"),
        ("AssertionError: assert check.trusted_observer_x == 1", "behaviour"),
    ],
)
def test_a_message_that_names_a_name_the_change_adds_is_a_missing_name(message, kind):
    names = frozenset({"trusted_observer"})
    assert ("name" if review_bar.missing_name(message, names) else "behaviour") == kind


def test_with_no_changed_test_file_nothing_runs_and_the_report_says_so(tmp_path):
    _init(tmp_path)
    base = _commit(tmp_path, {"src/pkg/core.py": BASE_CORE}, "base")
    head = _commit(tmp_path, {"src/pkg/core.py": HEAD_CORE}, "head")
    report = review_bar.review(tmp_path, base, head)
    assert not report.base_ran and report.base_outcomes == []
    assert "No test file under tests/ is added or changed" in report.markdown()


def test_a_src_file_that_does_not_parse_does_not_stop_the_report(tmp_path):
    _init(tmp_path)
    base = _commit(tmp_path, {
        "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["src"]\n',
        "src/pkg/__init__.py": "", "src/pkg/core.py": BASE_CORE, "tests/test_core.py": BASE_TESTS,
    }, "base")
    head = _commit(tmp_path, {
        "src/pkg/broken.py": "def oops(:\n", "tests/test_more.py": "def test_x():\n    pass\n",
    }, "head")
    report = review_bar.review(tmp_path, base, head)
    assert report.base_ran and [o.result for o in report.base_outcomes] == ["passed"]


def test_the_command_line_writes_the_summary_and_never_fails_the_build(repo, tmp_path):
    root, base, head = repo
    summary = tmp_path / "summary.md"
    code = review_bar.main(
        ["--repo", str(root), "--base", base, "--head", head, "--summary", str(summary)]
    )
    assert code == 0
    heading = "### Changed tests that pass on the head, run against the merge base"
    assert heading in summary.read_text()


def test_an_error_inside_the_tool_still_writes_a_report_and_exits_zero(tmp_path):
    summary = tmp_path / "summary.md"
    code = review_bar.main(
        ["--repo", str(tmp_path / "missing"), "--base", "x", "--head", "y",
         "--summary", str(summary)]
    )
    assert code == 0
    assert "The review bar could not finish" in summary.read_text()


def test_child_test_runs_do_not_inherit_the_workflow_file_variables(tmp_path, monkeypatch):
    for name in ("GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH"):
        monkeypatch.setenv(name, str(tmp_path / name))
    tree = tmp_path / "tree"
    (tree / "tests").mkdir(parents=True)
    (tree / "tests" / "test_w.py").write_text(
        "import os\n\n\ndef test_w():\n"
        "    assert not {'GITHUB_STEP_SUMMARY', 'GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_PATH'}"
        " & set(os.environ)\n"
    )
    code, outcomes = review_bar.run_tests(tree, ["tests/test_w.py"], 60)
    assert [o.result for o in outcomes] == ["passed"]


def test_a_test_run_over_its_time_limit_reports_a_timeout(tmp_path):
    tree = tmp_path / "tree"
    (tree / "tests").mkdir(parents=True)
    (tree / "tests" / "test_slow.py").write_text(
        "import time\n\n\ndef test_slow():\n    time.sleep(30)\n"
    )
    assert review_bar.run_tests(tree, ["tests/test_slow.py"], 2) == (-1, [])


def _small_repo(path: Path) -> tuple[str, str]:
    base = _commit(path, {
        "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["src"]\n',
        "src/pkg/__init__.py": "", "src/pkg/core.py": BASE_CORE, "tests/test_core.py": BASE_TESTS,
    }, "base")
    head = _commit(path, {"src/pkg/core.py": HEAD_CORE, "tests/test_core.py": HEAD_TESTS}, "head")
    return base, head


def test_only_the_worktrees_it_made_are_removed(tmp_path):
    _init(tmp_path)
    base, head = _small_repo(tmp_path)
    stale = tmp_path.parent / f"{tmp_path.name}-stale"
    subprocess.run(["git", "-C", str(tmp_path), "worktree", "add", "-q", "--detach", str(stale),
                    base], check=True)
    shutil.rmtree(stale)
    review_bar.review(tmp_path, base, head)
    listed = subprocess.run(["git", "-C", str(tmp_path), "worktree", "list"],
                            capture_output=True, text=True, check=True).stdout
    assert str(stale) in listed and len(listed.splitlines()) == 2


def test_changed_files_are_found_with_colour_forced_on(tmp_path):
    _init(tmp_path)
    for key in ("color.ui", "color.diff"):
        subprocess.run(["git", "-C", str(tmp_path), "config", key, "always"], check=True)
    base, head = _small_repo(tmp_path)
    assert review_bar.changed(tmp_path, base, head) == (["tests/test_core.py"], ["src/pkg/core.py"])
    report = review_bar.review(tmp_path, base, head)
    assert _by_name(report)["test_too_big_is_refused"] == "behaviour"


def test_long_lists_in_the_report_are_capped_with_a_count():
    lines = [f"- {n}" for n in range(30)]
    assert review_bar._capped(lines) == [*lines[:25], "- and 5 more"]
    assert review_bar._capped(lines[:25]) == lines[:25]


def test_a_skipped_test_is_not_a_failure():
    assert not review_bar.Outcome("a", "skipped").failed
    assert not review_bar.Outcome("a", "passed").failed
    assert review_bar.Outcome("a", "behaviour").failed and review_bar.Outcome("a", "name").failed


def test_a_timeout_on_the_head_stops_before_the_base_run(tmp_path, monkeypatch):
    _init(tmp_path)
    base, head = _small_repo(tmp_path)
    calls = []

    def timed_out(tree, tests, timeout, new_names=frozenset()):
        calls.append(tree.name)
        return -1, []

    monkeypatch.setattr(review_bar, "run_tests", timed_out)
    report = review_bar.review(tmp_path, base, head, timeout=5)
    assert calls == ["head"] and not report.base_ran
    assert "timed out on the head after 5 s" in report.markdown()


def _fake_runs(monkeypatch, head, base):
    calls = []

    def run(tree, tests, timeout, new_names=frozenset()):
        calls.append(tree.name)
        found = head if tree.name == "head" else base
        return found if isinstance(found, tuple) else (0, found)

    monkeypatch.setattr(review_bar, "run_tests", run)
    return calls


def test_a_test_skipped_on_the_head_is_left_out_of_the_base_section(tmp_path, monkeypatch):
    _init(tmp_path)
    base, head = _small_repo(tmp_path)
    Outcome = review_bar.Outcome
    _fake_runs(monkeypatch, [Outcome("t::a", "passed"), Outcome("t::b", "skipped")],
               [Outcome("t::a", "behaviour"), Outcome("t::b", "behaviour")])
    report = review_bar.review(tmp_path, base, head)
    assert [o.test for o in report.base_outcomes] == ["t::a"]


def test_with_no_changed_test_passing_on_the_head_the_base_is_not_run(tmp_path, monkeypatch):
    _init(tmp_path)
    base, head = _small_repo(tmp_path)
    calls = _fake_runs(monkeypatch, (2, []), [])
    report = review_bar.review(tmp_path, base, head)
    assert calls == ["head"] and not report.base_ran
    assert "No changed test passes on the head (pytest exited 2)" in report.markdown()
    # Tests that ran and all failed on the head are the same case.
    calls = _fake_runs(monkeypatch, [review_bar.Outcome("t::a", "behaviour")], [])
    report = review_bar.review(tmp_path, base, head)
    assert calls == ["head"] and not report.base_ran


def test_a_timeout_on_the_base_is_reported_and_not_read_as_a_result(tmp_path, monkeypatch):
    _init(tmp_path)
    base, head = _small_repo(tmp_path)
    _fake_runs(monkeypatch, [review_bar.Outcome("t::a", "passed")], (-1, []))
    report = review_bar.review(tmp_path, base, head, timeout=7)
    assert not report.base_ran and report.base_outcomes == []
    assert "The base run timed out after 7 s." in report.markdown()

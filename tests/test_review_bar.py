"""tools/review_bar.py on a two-commit repository built here.

The head commit adds a refusal (``x > 100``), a new function, a new module, a
data file and a conftest fixture, tightens a range check whose ``and`` sits on
an unchanged line, and brings tests of each kind: one that fails on the base for
behaviour, ones that fail there only because something the change adds is
missing, one that needs the new fixture, and one that fails on the head itself.
Its tests check 1000 but not 100, so weakening ``>`` to ``>=`` is a fix they
cannot tell apart, and the report has to say so.
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
MODE_MODULE = '''MODE = "strict"
if MODE not in ("strict", "lax"):
    raise ImportError("unknown mode")
'''
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


def test_added_lines_are_the_new_refusal_and_function(repo):
    # Line 6, `return x`, is the base's line 4 moved down, so git does not count it.
    root, base, head = repo
    assert review_bar.added_lines(root, base, head, "src/pkg/core.py") == {4, 5, 7, 8, 9, 10}


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


def test_mutants_touch_added_lines_and_untested_boundaries_survive(report):
    found = {(m.path.rsplit("/", 1)[-1], m.line, m.edit): m.status for m in report.mutants}
    assert found == {
        ("core.py", 4, "> becomes >="): "survived",
        ("core.py", 5, "delete the raise"): "caught",
        # The `and` starts on line 2, which is unchanged; its right operand is added.
        ("ranges.py", 2, "and becomes or"): "caught",
        ("ranges.py", 3, "<= becomes <"): "survived",
        # Flipping the import-time check makes the module refuse to import, so the
        # test is no longer collected: caught. Deleting the raise changes nothing
        # a test can see, because the raise never runs: an equivalent mutant.
        ("mode.py", 2, "not in becomes in"): "caught",
        ("mode.py", 3, "delete the raise"): "survived",
    }


def test_the_report_names_the_counts_and_the_survivors(report):
    text = report.markdown()
    assert "2 fail on behaviour, 4 fail on a missing name or file, 3 pass or skip." in text
    assert "so this is the weaker evidence. The mutants below are the stronger." in text
    assert "6 run: 3 caught by the changed tests, 3 not caught" in text
    assert "A mutant can also change nothing a test could see" in text
    assert "`src/pkg/core.py:4:8`: > becomes >=" in text
    assert "`src/pkg/ranges.py:3:17`: <= becomes <" in text


def test_mutants_over_the_limit_are_named_as_not_run(repo):
    root, base, head = repo
    report = review_bar.review(root, base, head, max_mutants=1)
    assert [m.status for m in report.mutants].count("not run") == 5
    assert "5 not run (over the limit or out of time)" in report.markdown()
    assert "Not run:" in report.markdown()


@pytest.mark.parametrize(
    ("head_passed", "code", "outcomes", "status"),
    [
        ({"a"}, -1, [], "timeout"),
        ({"a"}, 1, [("a", "behaviour")], "caught"),
        ({"a"}, 1, [("a", "name")], "caught"),
        # A test that already failed on the head says nothing about the mutant.
        ({"a"}, 1, [("a", "passed"), ("b", "behaviour")], "survived"),
        ({"a"}, 0, [("a", "passed")], "survived"),
        ({"a"}, 4, [], "unjudged"),
        # A mutant that breaks an import leaves the head's tests uncollected.
        ({"tests.test_mod::a", "tests.test_mod::b"}, 2, [("tests.test_mod", "name")], "caught"),
        # pytest writes the collection error as "collection failure", sorted as behaviour.
        ({"tests.test_mod.TestA::a"}, 2, [("tests.test_mod", "behaviour")], "caught"),
        ({"tests.test_mod_b::a"}, 2, [("tests.test_mod", "behaviour")], "survived"),
        # Ids that change because a parametrize list moved are not a failure.
        ({"tests.test_mod::a[sgx]"}, 0, [("tests.test_mod::a[software-only]", "passed")],
         "survived"),
        ({"tests.test_mod::a[sgx]"}, 1,
         [("tests.test_mod::a[x]", "passed"), ("tests.test_other", "name")], "survived"),
        ({"a"}, 0, [("a", "skipped")], "survived"),
        ({"a"}, 0, [("a", "passed"), ("c", "skipped")], "survived"),
    ],
)
def test_a_mutant_is_caught_only_when_a_test_that_passed_on_the_head_fails(
    head_passed, code, outcomes, status
):
    found = [review_bar.Outcome(t, r) for t, r in outcomes]
    assert review_bar.judge(head_passed, code, found) == status


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
    assert not report.base_ran and report.mutants == []
    assert "No test file under tests/ is added or changed" in report.markdown()


def test_a_src_file_that_does_not_parse_is_named_and_does_not_stop_the_report(tmp_path):
    _init(tmp_path)
    base = _commit(tmp_path, {
        "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["src"]\n',
        "src/pkg/__init__.py": "", "src/pkg/core.py": BASE_CORE, "tests/test_core.py": BASE_TESTS,
    }, "base")
    head = _commit(tmp_path, {
        "src/pkg/broken.py": "def oops(:\n", "tests/test_more.py": "def test_x():\n    pass\n",
    }, "head")
    text = review_bar.review(tmp_path, base, head).markdown()
    assert "`src/pkg/broken.py` does not parse on the head (SyntaxError)" in text


def test_the_command_line_writes_the_summary_and_never_fails_the_build(repo, tmp_path):
    root, base, head = repo
    summary = tmp_path / "summary.md"
    code = review_bar.main(
        ["--repo", str(root), "--base", base, "--head", head, "--summary", str(summary)]
    )
    assert code == 0
    assert "### Mutants on the lines this pull request adds" in summary.read_text()


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


def test_past_the_deadline_no_mutant_is_started_and_each_is_named(repo):
    root, base, head = repo
    report = review_bar.review(root, base, head, deadline=0)
    assert report.mutants and all(m.status == "not run" for m in report.mutants)


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


def test_coloured_git_output_does_not_hide_the_sites(tmp_path):
    _init(tmp_path)
    for key in ("color.ui", "color.diff"):
        subprocess.run(["git", "-C", str(tmp_path), "config", key, "always"], check=True)
    base, head = _small_repo(tmp_path)
    report = review_bar.review(tmp_path, base, head)
    assert {m.edit for m in report.mutants} >= {"> becomes >=", "delete the raise"}


def test_a_module_that_already_fails_on_the_head_catches_nothing():
    # tests/test_a.py fails to collect on the head; tests/test_a/test_b.py loses a
    # parametrize id on the mutant. The old failure is not the mutant's doing.
    head_passed = {"tests.test_a.test_b::test_v[1]"}
    outcomes = [review_bar.Outcome("tests.test_a", "behaviour", "collection failure")]
    assert review_bar.judge(head_passed, 2, outcomes, frozenset({"tests.test_a"})) == "survived"
    assert review_bar.judge(head_passed, 2, outcomes) == "caught"


def test_a_module_failing_on_the_head_does_not_catch_through_a_same_named_directory(tmp_path):
    # tests/test_a.py fails to import on the head and on every mutant; the mutant only
    # changes which ids tests/test_a/test_b.py parametrizes over.
    _init(tmp_path)
    base = _commit(tmp_path, {
        "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["src"]\n',
        "src/pkg/__init__.py": "",
    }, "base")
    head = _commit(tmp_path, {
        "src/pkg/vals.py": "VALUES = tuple(v for v in (1, 2, 3) if v != 3)\n",
        "tests/test_a.py": "import pkg.not_there\n\n\ndef test_x():\n    pass\n",
        "tests/test_a/test_b.py": (
            "import pytest\n\nfrom pkg.vals import VALUES\n\n\n"
            "@pytest.mark.parametrize(\"v\", VALUES)\ndef test_v(v):\n    assert v in (1, 2, 3)\n"
        ),
    }, "head")
    report = review_bar.review(tmp_path, base, head)
    assert [(m.edit, m.status) for m in report.mutants] == [("!= becomes ==", "survived")]


def test_timed_out_and_unjudged_mutants_are_located_with_one_based_columns():
    report = review_bar.Report("a" * 40, "b" * 40, ["tests/test_core.py"], ["src/pkg/core.py"])
    report.mutants = [
        review_bar.Mutant("src/pkg/core.py", 3, 0, "> becomes >=", "timeout"),
        review_bar.Mutant("src/pkg/core.py", 5, 4, "delete the raise", "unjudged"),
    ]
    text = report.markdown()
    assert "Timed out:" in text and "`src/pkg/core.py:3:1`: > becomes >=" in text
    assert "Could not be judged:" in text and "`src/pkg/core.py:5:5`: delete the raise" in text


def test_long_lists_in_the_report_are_capped_with_a_count():
    lines = [f"- {n}" for n in range(30)]
    assert review_bar._capped(lines) == [*lines[:25], "- and 5 more"]
    assert review_bar._capped(lines[:25]) == lines[:25]

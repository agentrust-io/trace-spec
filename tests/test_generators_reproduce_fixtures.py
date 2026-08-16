"""Every fixture generator must reproduce its committed fixtures byte for byte.

A generated fixture and the script that generates it can disagree indefinitely,
because nothing runs the script. They did: `03-superseded-version-refused.json`
carried `superseded_profile_refused`, matching the dedicated branch `verify_record`
takes for the v0.1 identifier, while `gen_vectors.py` still emitted the generic
`profile_not_accepted` from before that branch existed. Every test passed, because
the tests read the committed file and both codes are registered. Running the
generator once would have silently replaced a specific rule with a general one.

This is the reverse of a generated artifact that only agrees with itself: here the
two disagreed and nothing was looking. Regenerating into a temporary directory and
comparing bytes is the only check that sees it, and it costs a subprocess.

Generators are discovered rather than listed. A list is correct until the first
person forgets it, and the failure is silent. A discovered generator is assumed to
write the fixtures beside it and no others; one that writes elsewhere reports its
committed fixtures as missing, which is loud and points at the right file.

Three ways a comparison can be silent, and what this module does about each:

  A file the generator writes but nobody committed is invisible to a comparison
  driven by the committed names, so the two name sets are compared before any
  bytes are.

  A file the generator no longer writes is invisible to a comparison run in a
  directory that was seeded with the committed fixtures: the leftover copy is
  compared against itself and agrees. The generator's own directory is therefore
  emptied of fixtures before it runs, so every byte compared was written by this
  run. A generator that reads a committed fixture as input would now fail loudly
  rather than pass quietly, which is the correct order of those two outcomes.

  A fixture no generator produces is a real thing, not an error: `01-09` under
  `action-receipts/conformance` pin a key whose private half is not published, so
  no script can reissue them. Those are named in `NOT_GENERATED` with the reason,
  and the name set is checked against the exemptions in both directions, so an
  exemption cannot outlive the fact behind it and a new unexplained gap cannot
  open quietly.
"""
from __future__ import annotations
import filecmp
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GENERATORS = sorted(p.relative_to(ROOT) for p in (ROOT / "examples").rglob("gen_*.py"))

# Committed fixtures that sit beside a generator which does not produce them,
# keyed by the generator's path from the repository root. Every entry states why
# the file cannot be regenerated; "nobody got round to it" is not a reason, it is
# the drift this module exists to catch.
#
# An exemption withdraws reproduction, not verification. `test_action_receipt_fixtures`
# globs the same directory and puts every fixture in it through the verifier,
# signature included, so a fixture named here is still read on every run. What it
# loses is the second opinion of a script that can rebuild it.
#
# This is a ledger rather than a carve-out. It cannot grow quietly: a committed
# fixture no generator produces fails the check, so the only way in is an edit here,
# with a reason, in front of a reviewer. And it is meant to empty. A vector nobody
# can reissue has to be hand-edited every time the spec moves under it, which is a
# cost that arrives with the first release that revises this corpus rather than adds
# to it; the names below are what a reissue under a published key would have to
# cover, in the order someone would work through them.
NOT_GENERATED: dict[str, frozenset[str]] = {
    # gen_rule_coverage_vectors.py, first paragraph: "The 01-09 fixtures pin a key
    # whose private half is not published, so everything here pins its own
    # deterministic test key." The generator covers 10-30.
    "examples/action-receipts/conformance/gen_rule_coverage_vectors.py": frozenset({
        "01-valid-controller-accepted.json",
        "02-valid-controller-rejected.json",
        "03-missing-required-receipt.json",
        "04-signature-key-mismatch.json",
        "05-action-ref-mismatch.json",
        "06-stale-receipt.json",
        "07-receipt-chain-gap.json",
        "08-same-party-self-report.json",
        "09-unsupported-physical-completion.json",
    }),
}


def _check_generator(
    root: pathlib.Path,
    generator: pathlib.Path,
    not_generated: frozenset[str] = frozenset(),
) -> None:
    """Run `generator` in a copy of `root` and hold it to its committed fixtures.

    `generator` is relative to `root`. Raises AssertionError describing the first
    disagreement found; returns None when the generator reproduces exactly the
    fixtures it owns.
    """
    committed_dir = root / generator.parent
    committed = {p.name for p in committed_dir.glob("*.json")}
    assert committed, f"{committed_dir} holds no fixtures to compare"

    unknown = not_generated - committed
    assert not unknown, (
        f"NOT_GENERATED names fixtures that are not committed beside {generator}: "
        f"{sorted(unknown)}. Remove the exemption or restore the file."
    )

    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp) / "repo"
        # The generators resolve their output relative to either the repository root
        # or their own file, so both need to move together.
        shutil.copytree(root / "examples", work / "examples")
        if (root / "src").is_dir():
            shutil.copytree(root / "src", work / "src")

        regenerated = work / generator.parent
        # Clear the fixtures this generator owns, so nothing is compared against a
        # copy of itself. Only this directory, and only the fixtures: a generator's
        # other inputs, and every other example directory, stay where they are.
        for stale in regenerated.glob("*.json"):
            stale.unlink()

        result = subprocess.run(
            [sys.executable, str(work / generator)],
            cwd=work, capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(work / "src")},
        )
        assert result.returncode == 0, (
            f"{generator} failed to run:\n{result.stderr[-1500:]}")

        produced = {p.name for p in regenerated.glob("*.json")}

        extra = produced - committed
        assert not extra, (
            f"{generator} writes fixtures that are not committed: {sorted(extra)}.\n"
            "A fixture nobody committed is a fixture no test reads. Commit them, or "
            "stop the generator from writing them."
        )

        absent = committed - produced - not_generated
        assert not absent, (
            f"{generator} no longer writes committed fixtures: {sorted(absent)}.\n"
            "Either the generator dropped a case that is still committed, or the "
            "fixtures were produced by something else. Restore the case, or name "
            "them in NOT_GENERATED with the reason they cannot be regenerated."
        )

        stale_exemption = not_generated & produced
        assert not stale_exemption, (
            f"NOT_GENERATED exempts fixtures that {generator} does produce: "
            f"{sorted(stale_exemption)}. The exemption outlived its reason; drop it "
            "so these are compared like every other generated fixture."
        )

        names = sorted(produced)
        match, mismatch, errors = filecmp.cmpfiles(
            committed_dir, regenerated, names, shallow=False)
        assert not mismatch and not errors, (
            f"{generator} does not reproduce its committed fixtures.\n"
            f"  differ : {mismatch}\n"
            f"  missing: {errors}\n"
            "Either the generator is behind the fixtures or the fixtures were edited "
            "by hand. Decide which is correct, then make the other match it."
        )


def test_generators_were_found() -> None:
    """A discovery walk that finds nothing passes every test below it."""
    assert GENERATORS, "no fixture generators discovered under examples/"


def test_no_directory_holds_two_generators() -> None:
    """Emptying a directory before regenerating it assumes one generator owns it.
    Two would each erase the other's output and each be told its fixtures went
    missing, which is a true report of a false problem. Fail here instead, where
    the message says what actually happened."""
    dirs = [g.parent for g in GENERATORS]
    doubled = sorted({d.as_posix() for d in dirs if dirs.count(d) > 1})
    assert not doubled, (
        f"more than one generator writes into {doubled}. Give each its own "
        "directory, or teach this module which fixtures belong to which."
    )


def test_every_exemption_names_a_discovered_generator() -> None:
    """An exemption keyed to a path no walk reaches is never applied, and never
    fails either: it would sit in the file reading like an enforced fact."""
    discovered = {g.as_posix() for g in GENERATORS}
    assert set(NOT_GENERATED) <= discovered, (
        f"NOT_GENERATED keys no generator discovers: "
        f"{sorted(set(NOT_GENERATED) - discovered)}"
    )


@pytest.mark.parametrize("generator", GENERATORS, ids=lambda p: p.parent.name)
def test_generator_reproduces_its_committed_fixtures(generator: pathlib.Path) -> None:
    _check_generator(
        ROOT, generator, NOT_GENERATED.get(generator.as_posix(), frozenset()))


# ---- the guard's own failure modes, on a repository built to trip them --------


def _fake_repo(
    tmp_path: pathlib.Path,
    *,
    emits: dict[str, str],
    committed: dict[str, str],
) -> tuple[pathlib.Path, pathlib.Path]:
    """A minimal repository whose one generator writes `emits` and whose fixture
    directory holds `committed`, both as name -> file contents."""
    root = tmp_path / "repo"
    fixtures = root / "examples" / "vectors"
    fixtures.mkdir(parents=True)
    (fixtures / "gen_fake.py").write_text(
        "import pathlib\n"
        "out = pathlib.Path(__file__).resolve().parent\n"
        f"for name, body in {emits!r}.items():\n"
        "    (out / name).write_text(body, encoding='utf-8')\n",
        encoding="utf-8",
    )
    for name, body in committed.items():
        (fixtures / name).write_text(body, encoding="utf-8")
    return root, pathlib.Path("examples/vectors/gen_fake.py")


def test_a_generator_that_reproduces_its_fixtures_passes(tmp_path) -> None:
    """The other tests here assert failures; without this one they would all pass
    against a check that raises unconditionally."""
    root, generator = _fake_repo(
        tmp_path, emits={"a.json": "{}\n"}, committed={"a.json": "{}\n"})
    _check_generator(root, generator)


def test_an_extra_generated_fixture_is_caught(tmp_path) -> None:
    """The case a comparison driven by the committed names cannot see: the
    generator writes a fixture nobody committed."""
    root, generator = _fake_repo(
        tmp_path,
        emits={"a.json": "{}\n", "b.json": "{}\n"},
        committed={"a.json": "{}\n"},
    )
    with pytest.raises(AssertionError, match=r"not committed.*b\.json"):
        _check_generator(root, generator)


def test_a_fixture_the_generator_stopped_writing_is_caught(tmp_path) -> None:
    """The case a directory seeded with the committed fixtures cannot see: the
    leftover copy would be compared against itself and agree."""
    root, generator = _fake_repo(
        tmp_path,
        emits={"a.json": "{}\n"},
        committed={"a.json": "{}\n", "b.json": "{}\n"},
    )
    with pytest.raises(AssertionError, match=r"no longer writes.*b\.json"):
        _check_generator(root, generator)


def test_a_fixture_the_generator_stopped_writing_can_be_exempted(tmp_path) -> None:
    root, generator = _fake_repo(
        tmp_path,
        emits={"a.json": "{}\n"},
        committed={"a.json": "{}\n", "b.json": "hand written\n"},
    )
    _check_generator(root, generator, frozenset({"b.json"}))


def test_an_exemption_the_generator_outgrew_is_caught(tmp_path) -> None:
    """An exemption for a fixture the generator does write would silently excuse
    that fixture from the byte comparison."""
    root, generator = _fake_repo(
        tmp_path,
        emits={"a.json": "{}\n", "b.json": "{}\n"},
        committed={"a.json": "{}\n", "b.json": "{}\n"},
    )
    with pytest.raises(AssertionError, match=r"does produce: \['b\.json'\]"):
        _check_generator(root, generator, frozenset({"b.json"}))


def test_an_exemption_for_an_absent_fixture_is_caught(tmp_path) -> None:
    root, generator = _fake_repo(
        tmp_path, emits={"a.json": "{}\n"}, committed={"a.json": "{}\n"})
    with pytest.raises(AssertionError, match=r"not committed beside.*gone\.json"):
        _check_generator(root, generator, frozenset({"gone.json"}))


def test_byte_drift_between_generator_and_fixture_is_caught(tmp_path) -> None:
    """The original point of the module, on a repository small enough to read."""
    root, generator = _fake_repo(
        tmp_path,
        emits={"a.json": '{"code": "specific"}\n'},
        committed={"a.json": '{"code": "generic"}\n'},
    )
    with pytest.raises(AssertionError, match=r"(?s)does not reproduce.*a\.json"):
        _check_generator(root, generator)


def test_a_generator_that_fails_to_run_is_caught(tmp_path) -> None:
    root, generator = _fake_repo(
        tmp_path, emits={"a.json": "{}\n"}, committed={"a.json": "{}\n"})
    (root / generator).write_text("raise SystemExit(1)\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="failed to run"):
        _check_generator(root, generator)


def test_a_directory_with_no_committed_fixtures_is_caught(tmp_path) -> None:
    """Nothing to compare passes a byte comparison. It should not pass this."""
    root, generator = _fake_repo(tmp_path, emits={"a.json": "{}\n"}, committed={})
    with pytest.raises(AssertionError, match="holds no fixtures"):
        _check_generator(root, generator)

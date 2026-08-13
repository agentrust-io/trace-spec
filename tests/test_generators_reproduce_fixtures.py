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
person forgets it, and the failure is silent.
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


def test_generators_were_found() -> None:
    """A discovery walk that finds nothing passes every test below it."""
    assert GENERATORS, "no fixture generators discovered under examples/"


@pytest.mark.parametrize("generator", GENERATORS, ids=lambda p: p.parent.name)
def test_generator_reproduces_its_committed_fixtures(generator: pathlib.Path) -> None:
    committed = ROOT / generator.parent
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp) / "repo"
        # The generators resolve their output relative to either the repository root
        # or their own file, so both need to move together.
        shutil.copytree(ROOT / "examples", work / "examples")
        shutil.copytree(ROOT / "src", work / "src")
        result = subprocess.run(
            [sys.executable, str(work / generator)],
            cwd=work, capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(work / "src")},
        )
        assert result.returncode == 0, (
            f"{generator} failed to run:\n{result.stderr[-1500:]}")

        regenerated = work / generator.parent
        names = sorted(p.name for p in committed.glob("*.json"))
        assert names, f"{committed} holds no fixtures to compare"
        match, mismatch, errors = filecmp.cmpfiles(committed, regenerated, names, shallow=False)
        assert not mismatch and not errors, (
            f"{generator} does not reproduce its committed fixtures.\n"
            f"  differ : {mismatch}\n"
            f"  missing: {errors}\n"
            "Either the generator is behind the fixtures or the fixtures were edited "
            "by hand. Decide which is correct, then make the other match it."
        )

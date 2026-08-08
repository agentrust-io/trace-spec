"""The package version must be one number, in one place.

``__version__`` was a literal that drifted from ``pyproject.toml`` at #36 and was never
corrected, so v0.3.0, v0.4.0, v0.5.0 and v0.5.1 each shipped a wheel reporting ``0.2.0``
at runtime. Anyone pinning or logging on ``agentrust_trace.__version__`` got the wrong
answer, and nothing failed.

It now derives from installed package metadata, so a built artifact cannot disagree with
itself. These tests guard the parts that are still possible to get wrong: reintroducing a
hardcoded literal, bumping ``pyproject.toml`` without cutting a changelog section, or
tagging a version that is not semver.
"""

from __future__ import annotations

import pathlib
import re
import tomllib
from importlib import metadata

import pytest

import agentrust_trace

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"
_INIT = _ROOT / "src" / "agentrust_trace" / "__init__.py"


def _declared_version() -> str:
    with _PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_version_is_not_hardcoded() -> None:
    """The regression that shipped four wrong releases: a literal in the source.

    Environment independent, unlike comparing the two numbers, so this is the test that
    actually holds the line.
    """
    source = _INIT.read_text(encoding="utf-8")
    literal = re.search(r'^__version__\s*=\s*["\']\d+\.\d+\.\d+', source, re.MULTILINE)
    assert literal is None, (
        "__version__ is assigned a hardcoded version literal. Derive it from package "
        "metadata instead; a literal here drifted from pyproject.toml for four releases "
        "and nothing caught it."
    )


def test_declared_version_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", _declared_version())


def test_changelog_documents_the_declared_version() -> None:
    """A release absent from the changelog is a release nobody can read.

    The tag is what publishes to PyPI, so this has to fail before the tag, not after.
    """
    declared = _declared_version()
    changelog = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{declared}]" in changelog, (
        f"CHANGELOG.md has no '## [{declared}]' section. Cut the release section before "
        "tagging."
    )


def test_module_version_matches_pyproject() -> None:
    """Meaningful only when the installed distribution is this source tree.

    CI installs with ``pip install -e .``, so it runs. A working copy with a stale wheel
    from PyPI alongside it would otherwise report a mismatch that says nothing about the
    code under test, so that case is skipped rather than failed.
    """
    try:
        dist = metadata.distribution("agentrust-trace")
    except metadata.PackageNotFoundError:
        pytest.skip("agentrust-trace is not installed in this environment")

    installed_root = pathlib.Path(str(dist.locate_file("agentrust_trace"))).resolve()
    if installed_root != (_ROOT / "src" / "agentrust_trace").resolve():
        pytest.skip(
            f"installed distribution resolves to {installed_root}, not this source "
            "tree; the comparison would test the environment, not the code"
        )

    assert agentrust_trace.__version__ == _declared_version()

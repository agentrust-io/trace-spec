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

import inspect
import pathlib
import re
import tomllib
from importlib import metadata

import pytest

import agentrust_trace

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"
_INIT = _ROOT / "src" / "agentrust_trace" / "__init__.py"


def test_test_suite_imports_checkout_source() -> None:
    """A stale installed wheel must never shadow the source being tested."""
    imported = pathlib.Path(inspect.getfile(agentrust_trace)).resolve()
    assert imported == _INIT.resolve(), (
        f"tests imported agentrust_trace from {imported}, not the checkout at {_INIT.resolve()}"
    )


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


# --- the record format's version, which is a different number in the same shape ------
#
# `__version__` above is the package's. This is the Trust Record's, and it drifted the
# same way: the docstring on `TrustRecord` said v0.1 from the commit that introduced the
# package through every release since, on a class whose `eat_profile` is
# `Literal[...trace-v0.2]` and which therefore cannot hold a v0.1 record. `docs/schema.md`
# said it twice more, four lines above a table requiring the v0.2 profile URI.
#
# Nothing failed, because nothing compared the label against the thing it labels. These
# read the version out of the packaged schema, which is the artifact that decides it.

_SCHEMA_DIR = _ROOT / "src" / "agentrust_trace" / "schema"
_DOCS = _ROOT / "docs"

# Surfaces that describe the *current* record and so must name the current version.
# Documents scoped to an earlier version on purpose are not listed and are not the
# subject: `docs/crosswalks/` is written against v0.1 deliberately.
_CURRENT_RECORD_SURFACES = (
    pathlib.Path("src") / "agentrust_trace" / "models.py",
    pathlib.Path("docs") / "schema.md",
    pathlib.Path("docs") / "integration" / "cmcp.md",
    pathlib.Path("src") / "agentrust_trace" / "adapters" / "agt.py",
    pathlib.Path("docs") / "tutorials" / "verifying-a-trust-record.md",
)


def _record_version() -> str:
    """`"v0.2"`, read from the profile URI the packaged schema pins."""
    import json

    schema = json.loads((_SCHEMA_DIR / "trace-v0.2.json").read_text(encoding="utf-8"))
    const = schema["properties"]["eat_profile"]["const"]
    match = re.search(r"trace-(v\d+\.\d+)$", const)
    assert match, f"the packaged schema's eat_profile const is not a profile URI: {const!r}"
    return match.group(1)


def test_the_packaged_schema_names_a_version() -> None:
    """Guards the guard. If this returns nothing the checks below pass vacuously."""
    assert _record_version() == "v0.2"


@pytest.mark.parametrize("relative", _CURRENT_RECORD_SURFACES, ids=str)
def test_no_current_surface_labels_the_record_with_a_superseded_version(
    relative: pathlib.Path,
) -> None:
    current = _record_version()
    text = (_ROOT / relative).read_text(encoding="utf-8")
    stale = sorted(
        {
            m.group(0)
            for m in re.finditer(r"TRACE (v\d+\.\d+)", text)
            if m.group(1) != current
        }
    )
    assert not stale, (
        f"{relative} calls the record {stale}, but the packaged schema pins {current}. "
        "Either the label is stale or the schema moved; they cannot both be right."
    )

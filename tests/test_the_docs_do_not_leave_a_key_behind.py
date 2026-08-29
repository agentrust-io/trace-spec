"""Anything the documentation writes into a reader's tree must be ignored by git.

`docs/quickstart.md` writes an unencrypted Ed25519 private key to `trace-key.pem`, under
a comment that reads *"keep secure, never commit or log"*. That comment was the whole of
the enforcement. `.gitignore` did not cover the path, so a reader following the quickstart
inside a clone, which is what a quickstart invites, was one `git add -A` away from
committing their signing key.

The finding came from running the documentation's code blocks and then noticing the three
files they left behind in the working tree, which is the sort of thing a check for
untracked files sees and a reader does not.

The paths are recovered from the documentation rather than listed here, so a doc that
starts writing somewhere new fails this rather than quietly widening the gap.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

_WRITES = (
    re.compile(r"""open\(\s*["']([^"']+)["']\s*,\s*["']w"""),
    re.compile(r"""Path\(\s*["']([^"']+)["']\s*\)\.write_(?:text|bytes)"""),
)


def _paths_the_docs_write() -> set[str]:
    found: set[str] = set()
    for doc in sorted(DOCS.rglob("*.md")):
        text = doc.read_text(encoding="utf-8")
        for pattern in _WRITES:
            found.update(pattern.findall(text))
    return {p for p in found if "/" not in p or not p.startswith("/")}


def test_the_documentation_writes_something() -> None:
    """A recovery that found nothing would make the check below vacuous, and the
    patterns above are the kind of thing that stops matching after an edit."""
    found = _paths_the_docs_write()
    assert found, "recovered no written paths from docs/; the patterns have stopped matching"
    assert "trace-key.pem" in found, f"the quickstart's key is not among {sorted(found)}"


@pytest.mark.parametrize("name", sorted(_paths_the_docs_write()))
def test_git_ignores_what_the_docs_write(name: str) -> None:
    result = subprocess.run(
        ["git", "check-ignore", "-q", name], cwd=ROOT, capture_output=True
    )
    assert result.returncode == 0, (
        f"docs/ tells a reader to write {name!r} and .gitignore does not cover it. "
        "A reader following along inside a clone can commit it by accident, and for a "
        "private key that is the one mistake this repository cannot help them undo."
    )


def test_no_key_material_is_tracked() -> None:
    """The other direction: not just ignored going forward, but absent today."""
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True
    ).stdout.split()
    keys = [f for f in tracked if f.lower().endswith((".pem", ".key", ".p8", ".pfx"))]
    assert not keys, f"key material is tracked in the repository: {keys}"


def test_the_ignore_rule_is_not_so_broad_it_hides_real_files() -> None:
    """Without this, `*` in .gitignore would pass every test above.

    `--no-index` is required and is the whole point. Plain `git check-ignore` reports a
    *tracked* file as not ignored whatever the rules say, because ignore rules do not
    apply to tracked files, so the first version of this test passed with `*` appended
    and guarded nothing. Asking about the rules rather than about the index is the
    difference.
    """
    for kept in ("README.md", "pyproject.toml", "src/agentrust_trace/sign.py"):
        result = subprocess.run(
            ["git", "check-ignore", "-q", "--no-index", kept], cwd=ROOT, capture_output=True
        )
        assert result.returncode != 0, (
            f".gitignore now matches {kept}, which is tracked. The rule is too broad: it "
            "would hide a new file beside an existing one and nothing would say so."
        )

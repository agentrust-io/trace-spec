"""RFC 2119 requirement keywords under `docs/` must name the document they come from.

`CONTRIBUTING.md` draws the line this guard enforces: normative text lives in the
specifications, and informative text "carries no RFC 2119 keywords and binds no
implementation". Guides, crosswalks and RFCs are informative. They still need to *state*
requirements, a crosswalk that cannot quote the requirement it is mapping is useless,
so the rule that holds mechanically is not "no keywords" but the weaker, checkable one:

    a requirement keyword in an informative document must be attributable to a document
    that binds.

An uppercase `MUST` next to a section reference is a quotation. An uppercase `MUST` on
its own is a requirement that no specification contains, published in a file that claims
to bind nothing, and reachable by implementers who will read it as normative anyway.

Both failure directions matter, and only one of them is loud:

- A doc invents a requirement. Nothing in the repository notices, because no test reads
  prose for keywords. It ships, and the first sign of trouble is an implementer citing a
  requirement that reviewers cannot find in the spec.
- A doc quotes a real requirement without saying where from. Same text, same silence, and
  the reader has no way to check it.

The corpus is recovered from the tree rather than listed here, so a new directory under
`docs/` is covered the day it appears rather than the day someone remembers to add it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1] / "docs"

# The requirement keywords. MAY and OPTIONAL are absent: they grant permission, and a
# permission invented by a guide is not the failure this guard is looking for.
KEYWORDS = re.compile(
    r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|RECOMMENDED)\b"
)

# What counts as naming the source. Deliberately shape-based rather than an allowlist of
# approved sentences: an allowlist has to be edited every time a doc is reworded, which
# turns the guard into something people route around instead of satisfying.
CITATION = re.compile(
    r"§\s*\d"                                     # §3.2.1 of the spec
    r"|\bspec/[A-Za-z0-9._-]+\.md"                # a link into spec/
    r"|\b[A-Z][A-Za-z0-9-]*\s+s\d+(?:\.\d+)*\b"   # an external standard: Acta s2.2
    r"|\bRFC\s*\d{3,5}\b"                         # RFC 8785, RFC 9334
)


def _uncited() -> list[tuple[Path, int, str]]:
    """Every keyword-bearing line under `docs/` that names no source. Fences excluded."""
    offences: list[tuple[Path, int, str]] = []
    for path in sorted(DOCS.rglob("*.md")):
        in_fence = False
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("```"):
                in_fence = not in_fence
                continue
            if not in_fence and KEYWORDS.search(line) and not CITATION.search(line):
                offences.append((path.relative_to(DOCS.parent), number, line.strip()))
    return offences


def _cited() -> list[tuple[Path, int, str]]:
    """The complement: keyword-bearing lines that do name a source."""
    cited: list[tuple[Path, int, str]] = []
    for path in sorted(DOCS.rglob("*.md")):
        in_fence = False
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("```"):
                in_fence = not in_fence
                continue
            if not in_fence and KEYWORDS.search(line) and CITATION.search(line):
                cited.append((path.relative_to(DOCS.parent), number, line.strip()))
    return cited


def test_every_requirement_keyword_under_docs_names_its_source() -> None:
    offences = _uncited()
    assert not offences, (
        "these lines state a requirement without naming the document that imposes it:\n\n"
        + "\n".join(f"  {path}:{number}\n    {text}" for path, number, text in offences)
        + "\n\nEither cite the section it comes from, or lowercase the keyword. A "
        "requirement that no specification contains does not become one by being written "
        "in a file that says it binds nothing."
    )


def test_the_corpus_is_not_empty() -> None:
    """A guard that scanned nothing would pass, and would keep passing after `docs/`
    moved. The count is not pinned, new documents are expected, but zero is a bug in
    this file rather than a clean repository."""
    assert list(DOCS.rglob("*.md")), f"no markdown found under {DOCS}"


def test_the_citation_rule_is_actually_exercised() -> None:
    """The other half of the same worry. If no document anywhere carried a cited keyword,
    `test_every_requirement_keyword_under_docs_names_its_source` would be green because
    the rule never ran, not because the rule holds."""
    cited = _cited()
    assert cited, (
        "no document under docs/ quotes a requirement with a citation, so the permissive "
        "half of this guard is untested and may be permitting nothing at all"
    )


@pytest.mark.parametrize(
    "line",
    [
        "A concrete assurance composition MUST define a canonical derivation rule.",
        "Verifiers SHALL reject a record whose profile is unknown.",
        "The `kid` field is REQUIRED.",
        "Deployments SHOULD NOT reuse a signing key across environments.",
    ],
)
def test_an_uncited_requirement_is_caught(line: str) -> None:
    assert KEYWORDS.search(line) and not CITATION.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "[§3.2.1 of the spec](../spec/trace-v0.2.md) requires that verifiers MUST consult it.",
        "`payload.issuer_id` MUST match `signature.kid` (Acta s2.2).",
        "Canonicalization MUST follow RFC 8785.",
        "See spec/trace-v0.2.md: records MUST carry a profile.",
    ],
)
def test_a_cited_requirement_is_allowed(line: str) -> None:
    assert KEYWORDS.search(line) and CITATION.search(line)


def test_a_keyword_inside_a_code_fence_is_not_a_requirement(tmp_path: Path) -> None:
    """Sample output, JSON with a `MUST` string, a shell transcript quoting the spec: all
    of it is illustration. Scanning fenced blocks would push authors to work around the
    guard by rewording their examples, which is worse than not having it."""
    doc = tmp_path / "docs" / "sample.md"
    doc.parent.mkdir()
    doc.write_text("```\nthis MUST not be scanned\n```\nordinary prose\n")
    in_fence, hits = False, []
    for line in doc.read_text().splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence and KEYWORDS.search(line):
            hits.append(line)
    assert not hits

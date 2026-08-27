"""Pins the schema facts that docs/build-provenance-depth.md asserts.

The note states what each build_provenance verification depth does not assure.
Two of its statements are about ``schema/trace-claim.json`` rather than about
verifier behaviour: that only ``slsa_level`` and ``digest`` are required, and
that a schema-valid record can therefore name no builder at all. Prose about a
machine-readable file rots silently when the file changes, so those claims are
checked here rather than trusted.

The same check is applied to the ``build_provenance`` table in docs/schema.md,
which listed ``builder`` as required while the schema and the reference model
both treat it as optional. That drift is what this test exists to catch the
next time.

``docs/trust-levels.md`` is also checked: the displayed slsa_level range must
agree with the schema minimum and maximum. The original drift (0 to 4 vs max 3)
was reported in #172 and would have caused a reader to emit slsa_level: 4,
which the schema and the pydantic model both reject.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CANONICAL_SCHEMA = json.loads((ROOT / "schema" / "trace-claim.json").read_text())
PACKAGED_SCHEMA = json.loads(
    (ROOT / "src" / "agentrust_trace" / "schema" / "trace-v0.2.json").read_text()
)
NOTE = (ROOT / "docs" / "build-provenance-depth.md").read_text()
SCHEMA_DOC = (ROOT / "docs" / "schema.md").read_text()
TRUST_LEVELS_DOC = (ROOT / "docs" / "trust-levels.md").read_text()

BUILD_PROVENANCE = CANONICAL_SCHEMA["properties"]["build_provenance"]

RFC_2119 = re.compile(
    r"\b(MUST|SHALL|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b",
)

_SLSA_RANGE_RE = re.compile(r"\((\d+)[-, ](\d+)\)")


def _schema_doc_required() -> dict[str, bool]:
    """Field -> required, parsed from the build_provenance table in docs/schema.md."""
    section = SCHEMA_DOC.split("## `build_provenance`", 1)[1].split("\n## ", 1)[0]
    fields = {}
    for line in section.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        fields[cells[0].strip("`")] = "yes" in cells[2].lower()
    assert fields, "no build_provenance field rows found in docs/schema.md"
    return fields


def test_only_slsa_level_and_digest_are_required():
    """The note's central claim: a record can carry a digest and a level, and nothing else."""
    assert set(BUILD_PROVENANCE["required"]) == {"slsa_level", "digest"}
    assert "builder" in BUILD_PROVENANCE["properties"]
    assert "provenance_uri" in BUILD_PROVENANCE["properties"]


def test_packaged_schema_matches_canonical_schema():
    """The shipped copy is what implementations validate against; drift makes the note wrong."""
    assert PACKAGED_SCHEMA["properties"]["build_provenance"] == BUILD_PROVENANCE


def test_schema_doc_table_matches_schema():
    documented = _schema_doc_required()
    assert set(documented) == set(BUILD_PROVENANCE["properties"])
    assert {name for name, required in documented.items() if required} == set(
        BUILD_PROVENANCE["required"]
    )


def test_note_is_non_normative():
    """It is informative text, so no uppercase RFC 2119 keyword may appear in it."""
    found = sorted(set(RFC_2119.findall(NOTE)))
    assert not found, f"informative note carries RFC 2119 keywords: {found}"


def _trust_levels_slsa_range() -> tuple[int, int]:
    """Extract the slsa_level numeric range from docs/trust-levels.md.

    Looks for the table row that documents build_provenance.slsa_level and
    parses the (low to high) range stated there. Raises AssertionError if the
    row is absent or carries no range in that format, so the test fails loudly
    if the prose is restructured rather than silently passing on a missing row.
    """
    for line in TRUST_LEVELS_DOC.splitlines():
        if "build_provenance.slsa_level" not in line:
            continue
        m = _SLSA_RANGE_RE.search(line)
        assert m, (
            f"slsa_level row found in trust-levels.md but no (low to high) range: {line!r}"
        )
        return int(m.group(1)), int(m.group(2))
    raise AssertionError(
        "build_provenance.slsa_level row not found in docs/trust-levels.md"
    )


def test_trust_levels_slsa_range_matches_schema():
    """docs/trust-levels.md must agree with the schema on the valid slsa_level range.

    SLSA Build Levels are 0 to 3; there is no Level 4. The schema encodes this as
    minimum/maximum. Any drift between the two surfaces causes readers to emit
    values that the schema rejects with a validation error rather than a message
    explaining that the level does not exist (issue #172).
    """
    slsa_schema = BUILD_PROVENANCE["properties"]["slsa_level"]
    lo, hi = _trust_levels_slsa_range()
    assert lo == slsa_schema["minimum"], (
        f"trust-levels.md lower bound {lo} != schema minimum {slsa_schema['minimum']}"
    )
    assert hi == slsa_schema["maximum"], (
        f"trust-levels.md upper bound {hi} != schema maximum {slsa_schema['maximum']}"
    )

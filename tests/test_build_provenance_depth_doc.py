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

BUILD_PROVENANCE = CANONICAL_SCHEMA["properties"]["build_provenance"]

RFC_2119 = re.compile(
    r"\b(MUST|SHALL|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b",
)


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

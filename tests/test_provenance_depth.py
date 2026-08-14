"""Pins the `provenance_depth` fields added for #50.

Two optional fields carry the depth decision: `build_provenance.provenance_depth` is what
the issuer claims, `appraisal.provenance_depth_verified` is what the verifier ran. They are
deliberately separate, because the interesting case is a verifier that could not reach the
depth the record claimed and has to say so rather than fail the record outright.

Both schemas forbid unknown properties and both models forbid extras, so a field added to
one and not the other is a rejection rather than a mismatch. These tests hold the four
copies (two schemas, two models) together, and pin the backward-compatibility promise that
a record without `provenance_depth` stays valid.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentrust_trace.models import Appraisal, BuildProvenance

ROOT = Path(__file__).resolve().parents[1]

CANONICAL = json.loads((ROOT / "schema" / "trace-claim.json").read_text())
PACKAGED = json.loads(
    (ROOT / "src" / "agentrust_trace" / "schema" / "trace-v0.2.json").read_text()
)

DEPTHS = ("surface", "builder", "transitive")

MINIMAL_PROVENANCE = {"slsa_level": 3, "digest": "sha256:" + "a" * 64}


def _property(schema: dict, parent: str, field: str) -> dict:
    return schema["properties"][parent]["properties"][field]


@pytest.mark.parametrize("schema", [CANONICAL, PACKAGED], ids=["canonical", "packaged"])
@pytest.mark.parametrize(
    "parent,field",
    [("build_provenance", "provenance_depth"), ("appraisal", "provenance_depth_verified")],
)
def test_depth_enum_is_the_decided_three(schema: dict, parent: str, field: str) -> None:
    assert _property(schema, parent, field)["enum"] == list(DEPTHS)


@pytest.mark.parametrize(
    "parent,field",
    [("build_provenance", "provenance_depth"), ("appraisal", "provenance_depth_verified")],
)
def test_packaged_schema_matches_canonical(parent: str, field: str) -> None:
    """The shipped copy is what implementations validate against; drift makes the docs wrong."""
    assert _property(PACKAGED, parent, field) == _property(CANONICAL, parent, field)


@pytest.mark.parametrize(
    "parent,field",
    [("build_provenance", "provenance_depth"), ("appraisal", "provenance_depth_verified")],
)
def test_depth_is_optional_in_both_schemas(parent: str, field: str) -> None:
    """Additive by construction: neither field may join a `required` list."""
    for schema in (CANONICAL, PACKAGED):
        assert field not in schema["properties"][parent].get("required", [])


def test_record_without_depth_still_validates() -> None:
    """The backward-compatibility promise. Absent is read as surface, not as invalid."""
    provenance = BuildProvenance(**MINIMAL_PROVENANCE)
    assert provenance.provenance_depth is None

    appraisal = Appraisal(status="affirming", verifier="https://verifier.example/v1")
    assert appraisal.provenance_depth_verified is None


@pytest.mark.parametrize("depth", DEPTHS)
def test_models_accept_every_declared_depth(depth: str) -> None:
    assert BuildProvenance(**MINIMAL_PROVENANCE, provenance_depth=depth).provenance_depth == depth
    appraisal = Appraisal(
        status="affirming",
        verifier="https://verifier.example/v1",
        provenance_depth_verified=depth,
    )
    assert appraisal.provenance_depth_verified == depth


@pytest.mark.parametrize("bogus", ["dependency_chain", "builder_chain", "Surface", "deep", ""])
def test_models_reject_undeclared_depths(bogus: str) -> None:
    """Including the descriptive doc names, which are not the wire values."""
    with pytest.raises(ValidationError):
        BuildProvenance(**MINIMAL_PROVENANCE, provenance_depth=bogus)
    with pytest.raises(ValidationError):
        Appraisal(
            status="affirming",
            verifier="https://verifier.example/v1",
            provenance_depth_verified=bogus,
        )


def test_claimed_and_verified_are_separate_fields() -> None:
    """A verifier that downgraded records a lower depth than the record claimed.

    If these ever collapse into one field that case becomes unrepresentable, which is the
    whole point of the pair.
    """
    assert "provenance_depth_verified" not in CANONICAL["properties"]["build_provenance"][
        "properties"
    ]
    assert "provenance_depth" not in CANONICAL["properties"]["appraisal"]["properties"]


def test_docs_table_lists_both_fields() -> None:
    """docs/schema.md is the human copy of the same two fields; drift is silent otherwise."""
    schema_doc = (ROOT / "docs" / "schema.md").read_text()
    assert "`provenance_depth`" in schema_doc
    assert "`provenance_depth_verified`" in schema_doc

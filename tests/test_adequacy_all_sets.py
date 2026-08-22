"""Run the adequacy criteria over every vector set in the repository, ours included.

The criteria come from defects found on real sets. A standard that only ever measures
other people's work is advocacy, so this module measures every set by the same loader
and records the shortfalls where they fall rather than where it would be comfortable.

Where they fall today: `canonicalization-boundary`, which is ours, expects acceptance
in every vector, so it cannot tell a conformant verifier from one that accepts
unconditionally. That is recorded in `KNOWN_ONE_DIRECTIONAL` with the record asserted
exactly, so it cannot widen unnoticed and the entry is deleted when the missing
direction is added. `build-provenance-depth` carries a margin at every boundary and
nothing is recorded against it.

A set is measured here or named in `MEASURED_ELSEWHERE` with the test that covers it.
Neither is possible to skip: `test_every_vector_set_on_disk_is_measured_somewhere`
compares both against what is actually in `examples/`, because a hand-maintained list
of what gets graded is the same defect these criteria exist to catch, in the one place
it would otherwise be invisible.
"""
from __future__ import annotations
import json
import pathlib

import pytest

from tests.adequacy import Vector, boundaries_without_margin, report, trivially_satisfied_by

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"


def _load(directory: str, outcome_of, codes_of, boundary_of=None) -> list[Vector]:
    out = []
    for path in sorted((EXAMPLES / directory).glob("*.json")):
        expected = json.loads(path.read_text())["expected"]
        v = Vector(path.stem, outcome_of(expected), codes_of(expected))
        v.boundary = boundary_of(expected) if boundary_of else None
        out.append(v)
    assert out, f"no vectors loaded from {directory}; the loader is measuring nothing"
    return out


def build_provenance_depth() -> list[Vector]:
    """Deepest depth only: a vector's rule is the one that rejects it furthest in."""
    def separates_at(e) -> str | None:
        """The shallowest depth at which this vector stops agreeing with a verifier
        that establishes everything.

        Not `outcome` alone. Upstream moved the signal: a vector that cannot be
        established at a depth now reports `accept` with `verified_depth` short of
        that depth and the reason under `unresolved`, which distinguishes "failed"
        from "could not be established" and is the better shape. Reading only the
        verdict scores those vectors as separating nothing, which is the same
        mistake as reading a verdict and missing a statement.
        """
        for d in _depths(e):
            at = e[d]
            if (at["outcome"] != "accept"
                    or at.get("unresolved")
                    or at.get("verified_depth", d) != d):
                return d
        return None

    def deepest(e) -> dict:
        return e[_depths(e)[-1]]

    def codes(e) -> list[str]:
        at = deepest(e)
        return list(at["failures"]) + list(at.get("unresolved", []))

    return _load("build-provenance-depth",
                 lambda e: deepest(e)["outcome"], codes, separates_at)


def canonicalization_boundary() -> list[Vector]:
    return _load("canonicalization-boundary",
                 lambda e: e["outcome"], lambda e: [e.get("failure")])


def _depths(expected: dict) -> list[str]:
    """The depth names this set uses, read from a fixture rather than restated here.

    Upstream renamed them from `builder_chain` / `dependency_chain` to `builder` /
    `transitive` and this module broke loudly, which is the design working and also
    the reason not to write the names down twice. A set that renames a depth again
    changes nothing here.
    """
    return [k for k, v in expected.items() if isinstance(v, dict) and "outcome" in v]


def _depth_boundary(v: Vector) -> tuple[str, ...]:
    """The shallowest depth that rejects this vector, read from its own verdicts.

    This set's boundaries are coarser than its failure codes: #124 asks for two
    vectors per boundary carrying *different* codes, so counting by code reports a
    correctly covered boundary as thin.

    Taken from `expected`, never from the filename. A name-derived boundary is
    silently wrong the moment a vector is renamed, and the verdicts that define the
    boundary are already in the fixture.
    """
    return (v.boundary,) if v.boundary else ()



def delegation_link() -> list[Vector]:
    """The delegation-link set, graded by the same criteria as every other set here.

    Its boundaries are its failure codes: `tests/delegation_margins.json` records the
    two-vector margin per code, and `tests/test_delegation_completeness.py` holds each
    rule to being load-bearing for both of them, so the default mapping is the set's
    own unit rather than an assumption made here.
    """
    return _load("delegation-link",
                 lambda e: e["classification"], lambda e: list(e.get("codes") or []))


SETS = {
    "build-provenance-depth": (build_provenance_depth, _depth_boundary),
    "canonicalization-boundary": (canonicalization_boundary, None),
    "delegation-link": (delegation_link, None),
}

# Every set must be able to fail both unconditional implementations. A set that
# only ever expects rejection is passed by one that rejects everything; a set that
# only ever expects acceptance is passed by one that accepts everything, and that
# half is the one that gets left out.
# One set is knowingly one-directional. `canonicalization-boundary` detects a
# non-conformant canonicalizer by the fact that it *rejects* records a conformant
# verifier accepts, so every vector in it expects acceptance and the set cannot tell
# a correct verifier from one that accepts unconditionally. That second implementation
# is a real failure, not a hypothetical, so this is a gap rather than a design: it
# closes when the set gains one record signed over a non-JCS form, which a conformant
# verifier must reject. Recorded rather than skipped, and asserted exactly, so it
# cannot widen and cannot be forgotten.
KNOWN_ONE_DIRECTIONAL = {"canonicalization-boundary": "accept"}


@pytest.mark.parametrize("name", sorted(SETS))
def test_no_set_is_satisfied_by_an_unconditional_answer(name: str) -> None:
    vectors = SETS[name][0]()
    trivial = trivially_satisfied_by(vectors)
    if name in KNOWN_ONE_DIRECTIONAL:
        assert trivial == KNOWN_ONE_DIRECTIONAL[name], (
            f"{name} is recorded as passable by {KNOWN_ONE_DIRECTIONAL[name]!r}-everything "
            f"and now measures {trivial!r}. Update the record, or delete the entry if the "
            f"missing direction was added.\n{report(name, vectors)}")
        return
    assert trivial is None, (
        f"{name} is satisfied by an implementation that answers {trivial!r} to "
        f"everything, so it pins nothing:\n{report(name, vectors)}")


# The shortfall this repository currently carries, stated exactly. Widening it fails
# here; closing it fails here too, and the entry is then deleted.
KNOWN_THIN: dict[str, dict[str, str]] = {}


@pytest.mark.parametrize("name", sorted(SETS))
def test_margin_shortfall_is_exactly_what_is_recorded(name: str) -> None:
    load, boundary_of = SETS[name]
    vectors = load()
    thin = {b: names[0] for b, names in boundaries_without_margin(vectors, boundary_of).items()}
    expected = KNOWN_THIN.get(name, {})
    assert thin == expected, (
        f"{name}: the set of rules carried by a single vector changed.\n"
        f"  now recorded: {sorted(expected)}\n"
        f"  measured    : {sorted(thin)}\n"
        f"Add the second vector and remove the entry, or record the new one.\n"
        f"{report(name, vectors, boundary_of)}")


def test_the_loader_reads_a_different_set_for_each_name() -> None:
    """A loader returning the same vectors under three names would pass everything
    above while measuring one set three times."""
    seen = {name: tuple(v.name for v in load()) for name, (load, _) in SETS.items()}
    assert len(set(seen.values())) == len(seen), f"two sets loaded identically: {seen}"


# A set named here is a claim that something else measures it, together with the thing
# that does. Without the assertion below, `SETS` is a hand-maintained list of what gets
# graded, and a set added later is simply not graded, with nothing failing to say so.
# That is the defect these criteria exist to catch, so leaving it in the instrument is
# the one place it could not be caught.
MEASURED_ELSEWHERE = {
    "action-receipts": "tests/test_vector_completeness.py, which recovers its rule "
                       "inventory from the verifier's source rather than restating it",
}


def test_every_vector_set_on_disk_is_measured_somewhere() -> None:
    on_disk = {
        path.name
        for path in EXAMPLES.iterdir()
        if path.is_dir() and any(path.rglob("*.json"))
    }
    accounted = set(SETS) | set(MEASURED_ELSEWHERE)
    unmeasured = on_disk - accounted
    assert not unmeasured, (
        f"vector sets with nothing grading them: {sorted(unmeasured)}. Add a loader to "
        "SETS, or name the test that covers the set in MEASURED_ELSEWHERE. A set in "
        "neither is not adequate or inadequate, it is unmeasured."
    )
    stale = accounted - on_disk
    assert not stale, (
        f"named here but not on disk: {sorted(stale)}. A stale entry hides a renamed "
        "set: the new name reads as unmeasured and the old one keeps this quiet."
    )


@pytest.mark.parametrize("name", sorted(MEASURED_ELSEWHERE))
def test_the_test_named_as_measuring_a_set_elsewhere_exists(name: str) -> None:
    named = MEASURED_ELSEWHERE[name].split(",")[0].strip()
    assert (EXAMPLES.parent / named).is_file(), (
        f"{name} is recorded as measured by {named!r}, which does not exist. The record "
        "is then an assertion that nothing checks."
    )

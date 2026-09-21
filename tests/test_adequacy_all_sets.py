"""Run the adequacy criteria over every vector set in the repository, ours included.

The criteria come from defects found on real sets. A standard that only ever measures
other people's work is advocacy, so this module measures every set by the same loader
and records the shortfalls where they fall rather than where it would be comfortable.

`canonicalization-boundary` previously expected acceptance in every vector, so it
could not tell a conformant verifier from one that accepts unconditionally. Its
non-JCS signing-preimage negatives supply the missing direction. No set currently
needs an exemption in `KNOWN_ONE_DIRECTIONAL`; any future shortfall is recorded
exactly rather than allowed to widen unnoticed.

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


def verifier_compatibility() -> list[Vector]:
    return _load("verifier-compatibility",
                 lambda e: e["outcome"], lambda e: [e.get("failure")])


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


def revocation_bundle() -> list[Vector]:
    """The revocation-bundle set. Boundaries are its codes, one code per rule.

    `rejected` is a fourth outcome beside 3.2.3's three: the key was named by a
    statement and the record refused. It counts as non-accepting here, which is
    what it is.
    """
    return _load("revocation-bundle",
                 lambda e: "rejected" if e["rejected"] else e["outcome"],
                 lambda e: list(e.get("codes") or []))


def reproducibility_claim() -> list[Vector]:
    """The reproducibility-claim set (spec section 3.1.4). One code per rule the schema
    holds, two vectors per code, and five accepting records: a claim with no result
    and one result per outcome."""
    return _load("reproducibility-claim",
                 lambda e: e["outcome"], lambda e: list(e.get("codes") or []))


SETS = {
    "build-provenance-depth": (build_provenance_depth, _depth_boundary),
    "reproducibility-claim": (reproducibility_claim, None),
    "revocation-bundle": (revocation_bundle, None),
    "canonicalization-boundary": (canonicalization_boundary, None),
    "delegation-link": (delegation_link, None),
    "verifier-compatibility": (verifier_compatibility, None),
}

# Every set must be able to fail both unconditional implementations. A set that
# only ever expects rejection is passed by one that rejects everything; a set that
# only ever expects acceptance is passed by one that accepts everything, and that
# half is the one that gets left out.
# No set currently needs an exemption. The former `canonicalization-boundary`
# entry was removed when schema-valid records signed over non-JCS preimages added
# the rejecting direction alongside the existing RFC 8785 positive controls.
# Keep any future shortfall explicit and exact; removing an exemption does not
# relax either unconditional-answer check below.
KNOWN_ONE_DIRECTIONAL: dict[str, str] = {}


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
KNOWN_THIN: dict[str, dict[str, str]] = {
    # This fork's own set, and the shape #124 established as insufficient. It was four
    # of the five refusal rules. Three have since closed, each by a different route.
    # `profile_absent` closed by writing the second vector, 11, which carries a profile
    # claim that is present and empty rather than absent. `superseded_profile_refused`
    # and `superseded_profile_in_accepted_set` closed by leaving: 03 and 08 followed 10
    # out of the set on 2026-09-15 under the #116 ruling that the v0.1 cutover is merged
    # normative text and not this issue's to pin, and both rules are now tested in
    # `test_sign.py` beside the cutover's own tests.
    #
    # The one below was measured and is not closable, which is different from not yet
    # done, so the reason is recorded here rather than left as an open task:
    #
    #   no_accepted_profiles       The rule fires on the verifier's own configuration
    #                              before any record is read, and the configuration has
    #                              one shape: the accepted set is empty. The one other
    #                              axis, pairing the empty set with a second defect the
    #                              verifier would catch later, needs `check_freshness`,
    #                              which every vector in the set asserts is False, for
    #                              a good reason: a fixed `iat` would make the set
    #                              expire. Varying the record instead pins nothing, as
    #                              no plausible implementation branches on record
    #                              content when deciding an empty set accepts nothing.
    #
    # A second vector written to close a count rather than to catch a defect an
    # implementation could plausibly have makes this record worse, not better: it
    # reports a margin that does not exist.
    "verifier-compatibility": {
        "no_accepted_profiles": "06-empty-accepted-set-refused",
    },
}


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
    # Not loadable here: every vector verifies, and the outcomes are per-surface
    # resolvability rather than accept/reject, so `trivially_satisfied_by` would
    # grade the set as passable by an implementation that accepts everything.
    "citation-resolution": "tests/test_citation_resolution.py, which compares the "
                           "citations mapping of every vector against its expected "
                           "block and holds the invariants I1 to I11",
    "action-receipts": "tests/test_vector_completeness.py, which recovers its rule "
                       "inventory from the verifier's source rather than restating it",
    # Not loadable here: the adequacy criteria grade a set on accept/reject outcomes,
    # and this set's outcomes are three assurance grades, so `trivially_satisfied_by`
    # would be comparing against the wrong two unconditional implementations.
    "runtime-evidence": "tests/test_runtime_evidence_vectors.py, which asserts the "
                        "half this repository can honestly measure (schema, signature, "
                        "evidence shape, and the pinned claim that the top grade is "
                        "unreachable) and names the half it cannot, quote verification, "
                        "which examples/runtime-evidence/test_appraisal.py runs in the "
                        "dedicated runtime-evidence job against agent-manifest's verifier "
                        "at a pinned commit",
    # Not loadable here: every record in this set is a valid Trust Record, and the
    # cases differ only in what the reference resolves to in a separate CHAP log,
    # so there is no per-file accept/reject outcome for the criteria to grade.
    "chap-approval-outcome": "tests/test_chap_approval_outcome_fixtures.py, which "
                             "recomputes every verdict from the committed record and "
                             "CHAP log instead of reading expected.json",
    # Not loadable here for the same reason: every record verifies, and the cases
    # differ only in what the reference resolves to in the appraisal store beside them.
    "condition-appraisal": "tests/test_condition_appraisal_fixtures.py, which recomputes "
                           "every verdict from the committed record and appraisal store "
                           "instead of reading expected.json, and re-runs the generator",
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

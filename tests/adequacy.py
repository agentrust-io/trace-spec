"""Criteria a conformance vector set has to meet to be worth running.

A vector set is a claim about what an implementation must do. The claim is only
as strong as the set's ability to fail an implementation that does not do it, and
a set can pass every one of its own assertions while failing that. These are the
ways it happens that we have actually seen, each with the vector set it was found
on:

1. **No control, in either direction.** If every vector expects rejection, an
   implementation that rejects unconditionally satisfies the whole set. If every
   vector expects acceptance, one that accepts unconditionally does. Both halves
   are needed and the second is the one that gets forgotten: a set written to show
   that certain inputs *do* verify reads as complete while pinning nothing, which
   is the shape `canonicalization-boundary` has here.

2. **No margin.** One vector per boundary has no margin: a single implementation
   shortcut that happens to reject that one vector passes the boundary. Two vectors
   introducing distinct failure codes force the boundary itself to be implemented.
   Established in agentrust-io/trace-spec#124.

   Margin is counted per *boundary*, never per failure code, and the two are not
   the same unit. A boundary covered the way #124 asks for produces two vectors
   carrying two different codes, so counting by code reports the correct design as
   a shortfall. This was written the wrong way round first and the set that caught
   it was the one that had done it right. A set therefore has to say what its
   boundaries are; where it does not, the code is used and that assumption is the
   set's to justify.

3. **A rule that nothing pins.** If deleting a rule from the verifier changes no
   expected verdict, the set does not cover it, whatever its name suggests. Only
   deletion establishes this; reading does not.

4. **A weakness shared across a boundary's vectors.** Distinct failure codes are
   not sufficient. Both dependency vectors of the build-provenance set placed
   their defect last in a list, so a verifier that read one entry of three passed
   both while still rejecting the absent-list vector, presenting as having
   implemented the rule. Every check was present; the shortcut was in how many
   entries each one ran over, so no code went missing and no code-level guard
   could see it. Found in #169, on a set that already satisfied 1 through 3.

Criteria 1 and 2 are decidable from the fixtures alone and are implemented here.
Criteria 3 and 4 need to run the set's own verifier under mutation, so each set
implements them in its own module; this file states them so that a set which omits
them omits something named rather than something nobody thought of.
"""
from __future__ import annotations
from collections import defaultdict
from collections.abc import Iterable

ACCEPTING = frozenset({"accept", "verified", "pass"})


class Vector:
    """One fixture, reduced to what adequacy is decided on."""

    __slots__ = ("name", "outcome", "codes", "boundary")

    def __init__(self, name: str, outcome: str, codes: Iterable[str] = ()):
        self.name, self.outcome = name, outcome
        self.codes = tuple(c for c in codes if c)
        self.boundary: str | None = None

    @property
    def accepts(self) -> bool:
        return self.outcome in ACCEPTING


def trivially_satisfied_by(vectors: list[Vector]) -> str | None:
    """The unconditional implementation this set cannot fail, if there is one.

    Returns ``"reject"`` when no vector expects acceptance, ``"accept"`` when none
    expects rejection, and ``None`` when the set pins both directions.
    """
    if not any(v.accepts for v in vectors):
        return "reject"
    if all(v.accepts for v in vectors):
        return "accept"
    return None


def boundaries_without_margin(
    vectors: list[Vector], boundary_of=None
) -> dict[str, list[str]]:
    """Boundaries covered by exactly one vector, each with that vector named.

    *boundary_of* maps a vector to the boundary it separates. It defaults to the
    vector's failure codes, which is right only where one code means one rule; a set
    whose boundaries are coarser than its codes must supply it, or every correctly
    covered boundary reads as a shortfall.

    The return is the shortfall itself rather than a boolean, because a set short in
    a named place is in a different position from one nobody has measured.
    """
    key = boundary_of or (lambda v: v.codes)
    by_boundary: dict[str, list[str]] = defaultdict(list)
    for v in vectors:
        for b in key(v):
            by_boundary[b].append(v.name)
    return {b: names for b, names in sorted(by_boundary.items()) if len(names) < 2}


def report(label: str, vectors: list[Vector], boundary_of=None) -> str:
    thin = boundaries_without_margin(vectors, boundary_of)
    lines = [f"{label}: {len(vectors)} vectors, "
             f"{sum(v.accepts for v in vectors)} accepting, "
             f"{len({c for v in vectors for c in v.codes})} distinct failure codes"]
    trivial = trivially_satisfied_by(vectors)
    if trivial:
        lines.append(f"  NO CONTROL: a verifier that answers {trivial!r} to everything "
                     f"passes this set")
    for boundary, names in thin.items():
        lines.append(f"  NO MARGIN: {boundary} is covered only by {names[0]}")
    return "\n".join(lines)

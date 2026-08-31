"""Depth-separating vectors for `build_provenance` verification (#50).

§3.3 step 7 requires that "SLSA provenance resolves to a trusted builder" without saying
how far a verifier walks. Three stopping points are all conformant today, and they are
the `build_provenance.provenance_depth` values:

1. **`surface`**: `build_provenance.digest` matches the artifact, `builder` is trusted.
2. **`builder`**: also resolve `provenance_uri` and check the attestation binds to
   that digest and names that builder.
3. **`transitive`**: also walk `resolvedDependencies` to a publisher attestation
   per build input.

Two outcomes are kept apart, because they are the same event only if you never fetched
the evidence. Evidence that **does not resolve**: no `provenance_uri`, a URI that 404s,
an input with no publisher attestation: leaves the check unrun, so the verifier records
the depth it did reach and says which evidence was missing. Evidence that **resolves and
contradicts** the record: an attestation naming another subject or another builder, an
input signed under an untrusted issuer: is a rejection, and no shallower reading of the
same record makes it go away. `verify` returns both: `unresolved` caps `verified_depth`,
`failures` sets the outcome.

A vector that all three depths reject separates nothing: it is satisfied by any verifier
strict enough to reject it, whatever depth it stopped at. The set here is the other kind
: each vector passes the depth below with nothing to report, and the depth named in its
filename is the first one that says something: a rejection, or a recorded depth lower
than the one it attempted. Either way a verifier's stopping point is observable from its
own output, which is the property the set exists for.

The one vector that rejects nowhere is `01-all-depths-accept`. Without it, the set is
satisfiable by a verifier that rejects unconditionally, and the separations mean nothing.

Scope. Every vector assumes signature verification already succeeded: a bad signature
rejects at every depth, so it cannot separate depths, and it is the case implementers
write first. What varies here is *binding*: subject, builder identity, and per-input
publisher, which is where a shallower verifier silently accepts. The cases an
implementer writes naturally (no `provenance_uri`, a URI that does not resolve) are
exercised by mutating the accepting control rather than by fixtures, so the fixture set
stays the non-obvious ones.

The vectors are informative. They are not TRACE Trust Records and are not validated
against `schema/trace-claim.json`; `build_provenance` appears as the record fragment
under verification, alongside the evidence a verifier would have fetched.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

FIXTURE_DIR = Path(__file__).parent.parent / "examples" / "build-provenance-depth"

# Ordered shallowest first, on the `build_provenance.provenance_depth` wire values.
# Depths stack: a verifier at depth N runs every check at depths 0..N, so a failure
# found shallow is still a failure deep.
DEPTHS: tuple[str, ...] = ("surface", "builder", "transitive")
DEPTH_INDEX = {depth: index for index, depth in enumerate(DEPTHS)}

# What a fired rule does to the appraisal. The two are disjoint, and what separates
# them is whether the evidence resolved, not how serious the finding is.
FAILS = "fails"  # evidence resolved and contradicts the record
DOWNGRADES = "downgrades"  # evidence did not resolve, so the check could not run


@dataclass(frozen=True)
class Rule:
    """One check, owned by the shallowest depth that can run it.

    ``check`` returns True when the defect is present: i.e. when the code is emitted.

    ``effect`` separates the two things a defect can mean. A rule that ``FAILS`` has
    evidence in hand that contradicts the record, and no shallower reading makes that
    go away. A rule that ``DOWNGRADES`` never got its evidence: the verifier caps
    `provenance_depth_verified` at the depth below and stands on what it did check.
    """

    code: str
    depth: str
    effect: str
    check: Callable[[dict[str, Any]], bool] = field(compare=False)


def _digest_parts(digest: str) -> tuple[str, str]:
    algorithm, hexadecimal = digest.split(":", 1)
    return algorithm, hexadecimal


def _attestation(vector: dict[str, Any]) -> dict[str, Any] | None:
    """The SLSA statement `provenance_uri` resolves to, or None if it does not resolve."""
    uri = vector["build_provenance"].get("provenance_uri")
    if uri is None:
        return None
    entry = vector["context"]["attestations"].get(uri)
    if entry is None:
        return None
    statement: dict[str, Any] = entry["statement"]
    return statement


def _resolved_dependencies(vector: dict[str, Any]) -> list[dict[str, Any]]:
    statement = _attestation(vector)
    if statement is None:
        return []
    build_definition = statement.get("predicate", {}).get("buildDefinition", {})
    dependencies: list[dict[str, Any]] = build_definition.get("resolvedDependencies", [])
    return dependencies


# -- surface -----------------------------------------------------------------------


def _artifact_digest_mismatch(vector: dict[str, Any]) -> bool:
    return bool(vector["build_provenance"].get("digest") != vector["context"]["artifact_digest"])


def _builder_untrusted(vector: dict[str, Any]) -> bool:
    builder = vector["build_provenance"].get("builder")
    return builder is None or builder not in vector["context"]["trusted_builders"]


# -- builder ----------------------------------------------------------------------


def _provenance_uri_missing(vector: dict[str, Any]) -> bool:
    return vector["build_provenance"].get("provenance_uri") is None


def _attestation_unresolvable(vector: dict[str, Any]) -> bool:
    uri = vector["build_provenance"].get("provenance_uri")
    return uri is not None and uri not in vector["context"]["attestations"]


def _attestation_subject_mismatch(vector: dict[str, Any]) -> bool:
    statement = _attestation(vector)
    if statement is None:
        return False  # absence is reported by the rule that owns it, once
    algorithm, wanted = _digest_parts(vector["build_provenance"]["digest"])
    subjects = statement.get("subject", [])
    return not any(entry.get("digest", {}).get(algorithm) == wanted for entry in subjects)


def _attestation_builder_mismatch(vector: dict[str, Any]) -> bool:
    statement = _attestation(vector)
    if statement is None:
        return False
    run_details = statement.get("predicate", {}).get("runDetails", {})
    attested_builder = run_details.get("builder", {}).get("id")
    return bool(attested_builder != vector["build_provenance"].get("builder"))


# -- transitive -------------------------------------------------------------------


def _resolved_dependencies_absent(vector: dict[str, Any]) -> bool:
    if _attestation(vector) is None:
        return False
    return not _resolved_dependencies(vector)


def _dependency_attestation_missing(vector: dict[str, Any]) -> bool:
    attested = vector["context"]["dependency_attestations"]
    return any(dependency["uri"] not in attested for dependency in _resolved_dependencies(vector))


def _dependency_publisher_untrusted(vector: dict[str, Any]) -> bool:
    attested = vector["context"]["dependency_attestations"]
    trusted = vector["context"]["trusted_publisher_issuers"]
    for dependency in _resolved_dependencies(vector):
        attestation = attested.get(dependency["uri"])
        if attestation is None:
            continue  # reported by _dependency_attestation_missing
        if attestation.get("verified_identity", {}).get("issuer") not in trusted:
            return True
    return False


RULES: tuple[Rule, ...] = (
    Rule("artifact_digest_mismatch", "surface", FAILS, _artifact_digest_mismatch),
    Rule("builder_untrusted", "surface", FAILS, _builder_untrusted),
    Rule("provenance_uri_missing", "builder", DOWNGRADES, _provenance_uri_missing),
    Rule("attestation_unresolvable", "builder", DOWNGRADES, _attestation_unresolvable),
    Rule("attestation_subject_mismatch", "builder", FAILS, _attestation_subject_mismatch),
    Rule("attestation_builder_mismatch", "builder", FAILS, _attestation_builder_mismatch),
    Rule("resolved_dependencies_absent", "transitive", DOWNGRADES, _resolved_dependencies_absent),
    Rule(
        "dependency_attestation_missing", "transitive", DOWNGRADES, _dependency_attestation_missing
    ),
    Rule("dependency_publisher_untrusted", "transitive", FAILS, _dependency_publisher_untrusted),
)

RULE_CODES = frozenset(rule.code for rule in RULES)

# Rules with no fixture of their own: they reject the record a verifier would write a
# test for unprompted, so they are exercised by mutating the accepting control instead.
# test_no_rule_is_exercised_only_by_declaration keeps this list from absorbing a rule
# whose fixture was later deleted or renamed away.
EXERCISED_BY_MUTATION = frozenset(
    {
        "artifact_digest_mismatch",
        "builder_untrusted",
        "provenance_uri_missing",
        "attestation_unresolvable",
    }
)


def verify(vector: dict[str, Any], depth: str, rules: Sequence[Rule] = RULES) -> dict[str, Any]:
    """Verify at `depth`, running every rule owned by that depth or a shallower one.

    `depth` is what the verifier attempts. `verified_depth` is what it reached, which is
    the value belonging in `appraisal.provenance_depth_verified`: never deeper than the
    attempt, and capped one level below any depth whose evidence did not resolve.
    """
    limit = DEPTH_INDEX[depth]
    fired = [rule for rule in rules if DEPTH_INDEX[rule.depth] <= limit and rule.check(vector)]
    failures = [rule.code for rule in fired if rule.effect == FAILS]
    unresolved = [rule.code for rule in fired if rule.effect == DOWNGRADES]
    reached = min(
        [limit] + [DEPTH_INDEX[rule.depth] - 1 for rule in fired if rule.effect == DOWNGRADES]
    )
    return {
        "outcome": "reject" if failures else "accept",
        "verified_depth": DEPTHS[reached],
        "failures": failures,
        "unresolved": unresolved,
    }


def _load(path: Path) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(path.read_text())
    return payload


FIXTURE_PATHS = sorted(FIXTURE_DIR.glob("*.json"))
FIXTURES = [(path.stem, _load(path)) for path in FIXTURE_PATHS]
CONTROL = _load(FIXTURE_DIR / "01-all-depths-accept.json")


def test_fixture_set_is_complete() -> None:
    assert [path.name for path in FIXTURE_PATHS] == [
        "01-all-depths-accept.json",
        "02-surface-accepts-attestation-subject-mismatch.json",
        "03-surface-accepts-attestation-builder-mismatch.json",
        "04-builder-accepts-dependency-unattested.json",
        "05-builder-accepts-dependency-publisher-untrusted.json",
        "06-builder-accepts-resolved-dependencies-absent.json",
    ]


@pytest.mark.parametrize("name,vector", FIXTURES, ids=[name for name, _ in FIXTURES])
def test_vector_matches_expected_verdict_at_every_depth(name: str, vector: dict[str, Any]) -> None:
    for depth in DEPTHS:
        assert verify(vector, depth) == vector["expected"][depth], f"{name} at {depth}"


def test_control_accepts_at_every_depth() -> None:
    """The floor. A set of rejections alone is passed by a verifier that rejects everything."""
    for depth in DEPTHS:
        assert verify(CONTROL, depth)["outcome"] == "accept"


def _sha384_control(*, subject_sha384: str) -> dict[str, Any]:
    vector = copy.deepcopy(CONTROL)
    hexadecimal = "a" * 96
    digest = "sha384:" + hexadecimal
    vector["build_provenance"]["digest"] = digest
    vector["context"]["artifact_digest"] = digest
    statement = _attestation(vector)
    assert statement is not None
    statement["subject"][0]["digest"] = {
        "sha256": "b" * 64,
        "sha384": subject_sha384,
    }
    return vector


def test_sha384_subject_binding_selects_the_declared_algorithm() -> None:
    assert verify(_sha384_control(subject_sha384="a" * 96), "builder") == {
        "outcome": "accept",
        "verified_depth": "builder",
        "failures": [],
        "unresolved": [],
    }


def test_sha384_subject_binding_rejects_the_wrong_digest() -> None:
    assert verify(_sha384_control(subject_sha384="c" * 96), "builder") == {
        "outcome": "reject",
        "verified_depth": "builder",
        "failures": ["attestation_subject_mismatch"],
        "unresolved": [],
    }


@pytest.mark.parametrize("name,vector", FIXTURES, ids=[name for name, _ in FIXTURES])
def test_verdicts_are_monotone_over_depth(name: str, vector: dict[str, Any]) -> None:
    """A deeper verifier never accepts what a shallower one rejected."""
    rejected = False
    seen: set[str] = set()
    for depth in DEPTHS:
        result = verify(vector, depth)
        if rejected:
            assert result["outcome"] == "reject", f"{name} accepts at {depth} after rejecting"
        assert seen <= set(result["failures"]), f"{name} drops a failure at {depth}"
        seen = set(result["failures"])
        rejected = rejected or result["outcome"] == "reject"


@pytest.mark.parametrize("name,vector", FIXTURES, ids=[name for name, _ in FIXTURES])
def test_verified_depth_never_exceeds_the_depth_attempted(
    name: str, vector: dict[str, Any]
) -> None:
    """The rule `docs/verification.md` states and no JSON Schema can: a verifier MUST NOT
    record `provenance_depth_verified` deeper than it executed.

    The record is byte-identical whether a verifier walked the chain or claimed it did, so
    the schema cannot hold this. A conformance runner can, on its own output.
    """
    for depth in DEPTHS:
        result = verify(vector, depth)
        assert DEPTH_INDEX[result["verified_depth"]] <= DEPTH_INDEX[depth], (
            f"{name} attempted {depth} and recorded {result['verified_depth']}"
        )


@pytest.mark.parametrize("name,vector", FIXTURES, ids=[name for name, _ in FIXTURES])
def test_a_downgrade_is_never_silent(name: str, vector: dict[str, Any]) -> None:
    """Recording a shallower depth than attempted is a claim about missing evidence, so
    the evidence has to be named. A verifier that downgrades without saying which check it
    could not run is indistinguishable from one that never attempted the depth at all:
    and that is the whole failure this vector set exists to make visible."""
    for depth in DEPTHS:
        result = verify(vector, depth)
        downgraded = DEPTH_INDEX[result["verified_depth"]] < DEPTH_INDEX[depth]
        assert downgraded == bool(result["unresolved"]), (
            f"{name} at {depth}: verified {result['verified_depth']}, unresolved "
            f"{result['unresolved']}"
        )


def test_the_floor_depth_has_no_downgrading_rule() -> None:
    """There is nothing below `surface` to downgrade to, so every rule owned by it must be
    a failure. A downgrading rule there would have to record a depth that does not exist."""
    floor = DEPTHS[0]
    assert not [rule for rule in RULES if rule.depth == floor and rule.effect == DOWNGRADES]


def test_every_rule_declares_one_of_the_two_effects() -> None:
    assert {rule.effect for rule in RULES} <= {FAILS, DOWNGRADES}


BOUNDARIES = list(zip(DEPTHS[:-1], DEPTHS[1:], strict=True))


@pytest.mark.parametrize(
    "shallower,deeper", BOUNDARIES, ids=[f"{a}->{b}" for a, b in BOUNDARIES]
)
def test_each_boundary_is_separated_by_two_independent_vectors(
    shallower: str, deeper: str
) -> None:
    """Two vectors, two distinct defects, for every place a verifier can stop.

    One vector per boundary has no margin: a single implementation shortcut that happens
    to catch that one defect passes the whole boundary. Requiring two distinct codes
    means a verifier has to have implemented the depth, not one check from it.

    Separation is over everything the verifier reports, not over rejection alone. A
    vector whose deeper evidence never resolves is still separating: the shallower
    verifier reports nothing, the deeper one records a lower depth and names what it
    could not fetch. Counting rejections only would have hidden that boundary the moment
    a defect moved from `FAILS` to `DOWNGRADES`.
    """

    def reported(vector: dict[str, Any], depth: str) -> frozenset[str]:
        result = verify(vector, depth)
        return frozenset(result["failures"]) | frozenset(result["unresolved"])

    introduced = [
        reported(vector, deeper) - reported(vector, shallower)
        for _, vector in FIXTURES
        if not reported(vector, shallower) and reported(vector, deeper)
    ]
    assert len(introduced) >= 2, f"{shallower} -> {deeper} has {len(introduced)} separating vectors"
    assert len(set(introduced)) >= 2, f"{shallower} -> {deeper} separates on one defect only"


def _expected_codes(vector: dict[str, Any], depth: str) -> set[str]:
    block = vector["expected"][depth]
    return set(block["failures"]) | set(block["unresolved"])


def test_expected_codes_are_all_registered() -> None:
    for name, vector in FIXTURES:
        for depth in DEPTHS:
            unknown = _expected_codes(vector, depth) - RULE_CODES
            assert not unknown, f"{name} expects codes no rule can emit: {sorted(unknown)}"


def test_expected_codes_are_filed_under_the_effect_their_rule_declares() -> None:
    """A code cannot be expected as a failure in one fixture and an unresolved in another.
    The two lists are the wire form of the distinction; letting a code cross between them
    is how the conflict this set had with `docs/verification.md` got in."""
    effect_of = {rule.code: rule.effect for rule in RULES}
    for name, vector in FIXTURES:
        for depth in DEPTHS:
            block = vector["expected"][depth]
            for code in block["failures"]:
                assert effect_of[code] == FAILS, f"{name}: {code} is not a failure"
            for code in block["unresolved"]:
                assert effect_of[code] == DOWNGRADES, f"{name}: {code} does not downgrade"


def test_every_rule_is_exercised() -> None:
    from_fixtures = {
        code
        for _, vector in FIXTURES
        for depth in DEPTHS
        for code in _expected_codes(vector, depth)
    }
    assert from_fixtures | EXERCISED_BY_MUTATION == RULE_CODES


def test_no_rule_is_exercised_only_by_declaration() -> None:
    """A rule cannot be moved into the mutation list while a fixture still covers it, and
    a fixture cannot quietly stop covering one: the two sets have to stay disjoint."""
    from_fixtures = {
        code
        for _, vector in FIXTURES
        for depth in DEPTHS
        for code in _expected_codes(vector, depth)
    }
    assert not (from_fixtures & EXERCISED_BY_MUTATION)


FIXTURE_COVERED_CODES = RULE_CODES - EXERCISED_BY_MUTATION


@pytest.mark.parametrize("code", sorted(FIXTURE_COVERED_CODES))
def test_deleting_a_rule_changes_a_fixture_verdict(code: str) -> None:
    """Every rule is load-bearing: remove it and some fixture stops matching its expected
    verdict. A vector that no rule deletion can disturb is documentation, not a test."""
    remaining = tuple(rule for rule in RULES if rule.code != code)
    flipped = [
        name
        for name, vector in FIXTURES
        for depth in DEPTHS
        if verify(vector, depth, remaining) != vector["expected"][depth]
    ]
    assert flipped, f"no fixture notices when {code} is gone"


def _mutate(**changes: Any) -> dict[str, Any]:
    vector = copy.deepcopy(CONTROL)
    for key, value in changes.items():
        if value is None:
            vector["build_provenance"].pop(key, None)
        else:
            vector["build_provenance"][key] = value
    return vector


@pytest.mark.parametrize(
    "mutation,code,depth",
    [
        (
            {"digest": "sha256:" + "0" * 64},
            "artifact_digest_mismatch",
            "surface",
        ),
        ({"builder": "https://ci.example.org/pipelines/agent"}, "builder_untrusted", "surface"),
    ],
)
def test_contradicting_control_mutation_is_rejected(
    mutation: dict[str, Any], code: str, depth: str
) -> None:
    """Evidence in hand that contradicts the record. The verifier fetched what it needed
    and what it got says the record is wrong, so there is no honest shallower reading.

    Each mutation also has to leave the unmutated control accepting at the same depth,
    so a rule that fires on everything cannot pass this as a detection.
    """
    assert verify(CONTROL, depth)["outcome"] == "accept"
    result = verify(_mutate(**mutation), depth)
    assert result["outcome"] == "reject"
    assert code in result["failures"]


@pytest.mark.parametrize(
    "mutation,code",
    [
        ({"provenance_uri": None}, "provenance_uri_missing"),
        (
            {"provenance_uri": "https://provenance.example.org/support-agent/2.4.2.intoto.jsonl"},
            "attestation_unresolvable",
        ),
    ],
)
def test_unresolvable_control_mutation_downgrades_rather_than_rejects(
    mutation: dict[str, Any], code: str
) -> None:
    """The other half of the same control, and the pair is the point.

    Nothing about the record changed except whether its evidence can be fetched. The
    contradicting mutations above reject; these two record `surface`: the depth actually
    reached, and name the evidence that never arrived. A verifier that rejects here is
    failing a record for the state of someone else's transparency log, which is what
    `provenance_depth_verified` exists to avoid.
    """
    assert verify(CONTROL, "builder") == {
        "outcome": "accept",
        "verified_depth": "builder",
        "failures": [],
        "unresolved": [],
    }
    result = verify(_mutate(**mutation), "builder")
    assert result["outcome"] == "accept"
    assert result["verified_depth"] == "surface"
    assert result["unresolved"] == [code]
    assert result["failures"] == []


def test_surface_mutation_rejects_at_every_depth() -> None:
    """Monotonicity, from the other side: a surface defect is not outgrown by depth."""
    mutated = _mutate(digest="sha256:" + "0" * 64)
    for depth in DEPTHS:
        assert verify(mutated, depth)["outcome"] == "reject"


def _checking_only_first(count: int) -> tuple[Rule, ...]:
    """The rule set of a verifier that walks `resolvedDependencies` and stops early."""

    def truncated(check: Callable[[dict[str, Any]], bool]) -> Callable[[dict[str, Any]], bool]:
        def run(vector: dict[str, Any]) -> bool:
            dependencies = _resolved_dependencies(vector)
            if not dependencies:
                return check(vector)
            trimmed = copy.deepcopy(vector)
            statement = _attestation(trimmed)
            assert statement is not None
            build_definition = statement["predicate"]["buildDefinition"]
            build_definition["resolvedDependencies"] = dependencies[:count]
            return check(trimmed)

        return run

    walks_the_list = ("dependency_attestation_missing", "dependency_publisher_untrusted")
    return tuple(
        Rule(rule.code, rule.depth, rule.effect, truncated(rule.check))
        if rule.code in walks_the_list
        else rule
        for rule in RULES
    )


@pytest.mark.parametrize("count", [1, 2])
def test_a_verifier_that_stops_early_in_the_dependency_list_is_caught(count: int) -> None:
    """Distinct failure codes are not enough on their own.

    `test_each_boundary_is_separated_by_two_independent_vectors` asks that the two
    vectors introduce different codes. A verifier can run every dependency check and
    still be wrong by running them over too few dependencies, and that defeats distinct
    codes without emitting one: every check is implemented, so no code is missing.

    Both dependency vectors once placed their defect last, so a verifier reading any
    proper prefix of the list accepted both while still rejecting the absent-list vector
: presenting as a `dependency_chain` verifier having read one dependency of three.
    At least one vector must therefore fail for a verifier that stops early.
    """
    weakened = _checking_only_first(count)
    walks_the_list = {"dependency_attestation_missing", "dependency_publisher_untrusted"}
    # Only the vectors whose rejection depends on reading the list. 06 rejects because
    # the list is absent, which an early-stopping verifier still catches, so counting it
    # would satisfy this assertion without testing anything.
    separating = [
        (name, vector)
        for name, vector in FIXTURES
        if verify(vector, "builder")["outcome"] == "accept"
        and walks_the_list & set(verify(vector, "transitive")["failures"])
    ]
    assert separating, "no vector rejects on a rule that walks resolvedDependencies"
    caught = [
        name
        for name, vector in separating
        if verify(vector, "transitive", weakened)["outcome"] == "reject"
    ]
    assert caught, (
        f"a verifier checking only the first {count} of resolvedDependencies is accepted "
        f"by every vector that separates this boundary: {[n for n, _ in separating]}"
    )

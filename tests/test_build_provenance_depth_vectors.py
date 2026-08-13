"""Depth-separating vectors for `build_provenance` verification (#50).

§3.3 step 7 requires that "SLSA provenance resolves to a trusted builder" without saying
how far a verifier walks. Three stopping points are all conformant today:

1. **Surface** — `build_provenance.digest` matches the artifact, `builder` is trusted.
2. **Builder-chain** — also resolve `provenance_uri` and check the attestation binds to
   that digest and names that builder.
3. **Dependency-chain** — also walk `resolvedDependencies` to a publisher attestation
   per build input.

A vector that all three depths reject separates nothing: it is satisfied by any verifier
strict enough to reject it, whatever depth it stopped at. The set here is the other kind
— each vector is **accepted by the depth below and rejected by the depth named in its
filename**, so a verifier's stopping point is observable from its verdicts alone.

The one vector that rejects nowhere is `01-all-depths-accept`. Without it, the set is
satisfiable by a verifier that rejects unconditionally, and the separations mean nothing.

Scope. Every vector assumes signature verification already succeeded: a bad signature
rejects at every depth, so it cannot separate depths, and it is the case implementers
write first. What varies here is *binding* — subject, builder identity, and per-input
publisher — which is where a shallower verifier silently accepts. The cases an
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

# Ordered shallowest first. Depths stack: a verifier at depth N runs every check at
# depths 0..N, so a failure found shallow is still a failure deep.
DEPTHS: tuple[str, ...] = ("surface", "builder_chain", "dependency_chain")
DEPTH_INDEX = {depth: index for index, depth in enumerate(DEPTHS)}


@dataclass(frozen=True)
class Rule:
    """One check, owned by the shallowest depth that can run it.

    ``check`` returns True when the defect is present — i.e. when the code is emitted.
    """

    code: str
    depth: str
    check: Callable[[dict[str, Any]], bool] = field(compare=False)


def _hex(digest: str) -> str:
    return digest.split(":", 1)[1]


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


# -- builder chain -----------------------------------------------------------------


def _provenance_uri_missing(vector: dict[str, Any]) -> bool:
    return vector["build_provenance"].get("provenance_uri") is None


def _attestation_unresolvable(vector: dict[str, Any]) -> bool:
    uri = vector["build_provenance"].get("provenance_uri")
    return uri is not None and uri not in vector["context"]["attestations"]


def _attestation_subject_mismatch(vector: dict[str, Any]) -> bool:
    statement = _attestation(vector)
    if statement is None:
        return False  # absence is reported by the rule that owns it, once
    wanted = _hex(vector["build_provenance"]["digest"])
    subjects = statement.get("subject", [])
    return not any(entry.get("digest", {}).get("sha256") == wanted for entry in subjects)


def _attestation_builder_mismatch(vector: dict[str, Any]) -> bool:
    statement = _attestation(vector)
    if statement is None:
        return False
    run_details = statement.get("predicate", {}).get("runDetails", {})
    attested_builder = run_details.get("builder", {}).get("id")
    return bool(attested_builder != vector["build_provenance"].get("builder"))


# -- dependency chain --------------------------------------------------------------


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
    Rule("artifact_digest_mismatch", "surface", _artifact_digest_mismatch),
    Rule("builder_untrusted", "surface", _builder_untrusted),
    Rule("provenance_uri_missing", "builder_chain", _provenance_uri_missing),
    Rule("attestation_unresolvable", "builder_chain", _attestation_unresolvable),
    Rule("attestation_subject_mismatch", "builder_chain", _attestation_subject_mismatch),
    Rule("attestation_builder_mismatch", "builder_chain", _attestation_builder_mismatch),
    Rule("resolved_dependencies_absent", "dependency_chain", _resolved_dependencies_absent),
    Rule("dependency_attestation_missing", "dependency_chain", _dependency_attestation_missing),
    Rule("dependency_publisher_untrusted", "dependency_chain", _dependency_publisher_untrusted),
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
    """Verify at `depth`, running every rule owned by that depth or a shallower one."""
    limit = DEPTH_INDEX[depth]
    failures = [
        rule.code for rule in rules if DEPTH_INDEX[rule.depth] <= limit and rule.check(vector)
    ]
    return {"outcome": "reject" if failures else "accept", "failures": failures}


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
        "04-builder-chain-accepts-dependency-unattested.json",
        "05-builder-chain-accepts-dependency-publisher-untrusted.json",
        "06-builder-chain-accepts-resolved-dependencies-absent.json",
    ]


@pytest.mark.parametrize("name,vector", FIXTURES, ids=[name for name, _ in FIXTURES])
def test_vector_matches_expected_verdict_at_every_depth(name: str, vector: dict[str, Any]) -> None:
    for depth in DEPTHS:
        assert verify(vector, depth) == vector["expected"][depth], f"{name} at {depth}"


def test_control_accepts_at_every_depth() -> None:
    """The floor. A set of rejections alone is passed by a verifier that rejects everything."""
    for depth in DEPTHS:
        assert verify(CONTROL, depth)["outcome"] == "accept"


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
    """
    introduced = [
        frozenset(verify(vector, deeper)["failures"])
        - frozenset(verify(vector, shallower)["failures"])
        for _, vector in FIXTURES
        if verify(vector, shallower)["outcome"] == "accept"
        and verify(vector, deeper)["outcome"] == "reject"
    ]
    assert len(introduced) >= 2, f"{shallower} -> {deeper} has {len(introduced)} separating vectors"
    assert len(set(introduced)) >= 2, f"{shallower} -> {deeper} separates on one defect only"


def test_expected_failure_codes_are_all_registered() -> None:
    for name, vector in FIXTURES:
        for depth in DEPTHS:
            unknown = set(vector["expected"][depth]["failures"]) - RULE_CODES
            assert not unknown, f"{name} expects codes no rule can emit: {sorted(unknown)}"


def test_every_rule_is_exercised() -> None:
    from_fixtures = {
        code
        for _, vector in FIXTURES
        for depth in DEPTHS
        for code in vector["expected"][depth]["failures"]
    }
    assert from_fixtures | EXERCISED_BY_MUTATION == RULE_CODES


def test_no_rule_is_exercised_only_by_declaration() -> None:
    """A rule cannot be moved into the mutation list while a fixture still covers it, and
    a fixture cannot quietly stop covering one: the two sets have to stay disjoint."""
    from_fixtures = {
        code
        for _, vector in FIXTURES
        for depth in DEPTHS
        for code in vector["expected"][depth]["failures"]
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
        ({"provenance_uri": None}, "provenance_uri_missing", "builder_chain"),
        (
            {"provenance_uri": "https://provenance.example.org/support-agent/2.4.2.intoto.jsonl"},
            "attestation_unresolvable",
            "builder_chain",
        ),
    ],
)
def test_control_mutation_is_rejected(mutation: dict[str, Any], code: str, depth: str) -> None:
    """The rules with no fixture, checked against the vector they would reject.

    Each mutation also has to leave the unmutated control accepting at the same depth,
    so a rule that fires on everything cannot pass this as a detection.
    """
    assert verify(CONTROL, depth)["outcome"] == "accept"
    result = verify(_mutate(**mutation), depth)
    assert result["outcome"] == "reject"
    assert code in result["failures"]


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
        Rule(rule.code, rule.depth, truncated(rule.check))
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
    — presenting as a `dependency_chain` verifier having read one dependency of three.
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
        if verify(vector, "builder_chain")["outcome"] == "accept"
        and walks_the_list & set(verify(vector, "dependency_chain")["failures"])
    ]
    assert separating, "no vector rejects on a rule that walks resolvedDependencies"
    caught = [
        name
        for name, vector in separating
        if verify(vector, "dependency_chain", weakened)["outcome"] == "reject"
    ]
    assert caught, (
        f"a verifier checking only the first {count} of resolvedDependencies is accepted "
        f"by every vector that separates this boundary: {[n for n, _ in separating]}"
    )

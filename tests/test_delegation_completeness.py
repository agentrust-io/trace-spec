"""Completeness checks over the delegation-link vectors.

`test_delegation_vectors.py` asks whether the vectors are *correct*. This module
asks whether they are *complete*, by the same five questions
`test_vector_completeness.py` asks of the action-receipt corpus, against the same
floor: two load-bearing vectors per rule, and at least one declared implementation
defect that tells the two apart.

The method is unchanged and the reason is unchanged. Mutation targets named rule
hooks: a rule is deleted by rebuilding the registry without its entry, or weakened
by substituting its check: never by pattern-matching source text, so the mutation
cannot drift away from the code under test. `DEFECTS` is fail-closed: registering a
rule without declaring what its second vector adds fails this suite, so the
question "what bug would your second vector catch that your first would not?" is
answered when the rule is written rather than after a regression demonstrates it.

Two of the defects declared below found real faults in the walk while this file was
being written, which is the argument for declaring them at all rather than
asserting margin and stopping:

  `anchor_on_any_trusted_key` is why vector 09 exists in its present form. The
  first version put an untrusted root three hops down and no declared defect could
  separate it from vector 08: both were simply "the root is not trusted", twice.
  The vector that separates them had to place a *trusted* key partway up the
  chain, which is the shortcut an implementation actually takes.

  `off_by_one` on the depth bound could not deviate anything while the walk
  repeated the depth comparison in its own break condition. A weakened bound never
  got to walk further than a correct one, so both depth vectors moved together
  under every mutation. The walk now breaks for one reason: an unresolvable
  parent, and terminates on a visited set instead.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
import rfc8785

from tests.test_delegation_vectors import (
    CLASSIFICATIONS,
    VECTOR_PATHS,
    Hop,
    Rule,
    RULES,
    _jwk_key,
    _signature_invalid,
    verify_chain,
)

TESTS_DIR = Path(__file__).parent
WALK_MODULE = TESTS_DIR / "test_delegation_vectors.py"
MARGINS_FILE = TESTS_DIR / "delegation_margins.json"

RULE_CODES = tuple(rule.code for rule in RULES)
VECTORS = [json.loads(path.read_text(encoding="utf-8")) for path in VECTOR_PATHS]
NAMES = [path.stem for path in VECTOR_PATHS]


# ---------------------------------------------------------------------------
# Declared defects: one weakened check per rule, minimum
# ---------------------------------------------------------------------------

Check = Callable[[Hop], bool]


def _leaf_only_signature(hop: Hop) -> bool:
    """Verify the leaf and take the rest of the chain on the strength of the hashes.

    Tempting because it is nearly right: a parent's bytes really are committed to
    by its child, so nothing upstream can be altered in place. What the hashes do
    not establish is that an ancestor was ever validly signed at all.
    """
    return hop.depth == 0 and _signature_invalid(hop.record)


def _anchor_on_any_trusted_key(hop: Hop) -> bool:
    """Accept the chain if any record on it carries a trusted key.

    The shape of "we found our own key in there somewhere, so this is ours".
    """
    trusted = {_jwk_key(jwk) for jwk in hop.context["trusted_root_keys"]}
    present = {_jwk_key(r.get("cnf", {}).get("jwk", {})) for r in hop.index.values()}
    return not (trusted & present)


def _off_by_one_depth(hop: Hop) -> bool:
    """`>` where the bound wanted `>=`, or a counter started at one."""
    return hop.depth > hop.context["max_depth"] + 1


def _first_link_algorithm_only(hop: Hop) -> bool:
    """Read the algorithm off the leaf's link and assume the chain is uniform."""
    return hop.depth == 1 and hop.link_algorithm not in hop.context[
        "supported_digest_algorithms"
    ]


def _resolves_over_signed_body(hop: Hop) -> bool:
    """Index parents by the digest of their signed body as well as the record.

    The other reading of "digest of the parent hop's Trust Record", and an
    implementation being liberal about which one it accepts ends up accepting both.
    """
    if hop.link_algorithm not in hop.context["supported_digest_algorithms"]:
        return False
    wanted = hop.delegation["parent_record_hash"]
    if wanted in hop.index:
        return False
    algorithm = hop.link_algorithm
    for record in hop.index.values():
        body = {k: v for k, v in record.items() if k != "signature"}
        if f"{algorithm}:" + hashlib.new(algorithm, rfc8785.dumps(body)).hexdigest() == wanted:
            return False
    return True


def _case_insensitive_credential_lookup(hop: Hop) -> bool:
    """The classic 'be liberal in what you accept', applied to an opaque identifier."""
    wanted = hop.delegation["credential_id"].lower()
    return not any(cid.lower() == wanted for cid in hop.context["credentials"])


def _issuer_compared_to_the_record_itself(hop: Hop) -> bool:
    """The right comparison against the wrong end of the hop."""
    credential = hop.credential
    if credential is None:
        return False
    return credential["issuer"] != hop.record["subject"]


def _holder_compared_to_the_parent(hop: Hop) -> bool:
    """Issuer and holder read in the wrong order."""
    credential = hop.credential
    if credential is None:
        return False
    assert hop.parent is not None
    return credential["holder"] != hop.parent["subject"]


def _expiry_only(hop: Hop) -> bool:
    """Half a validity window. The half everyone remembers."""
    credential = hop.credential
    if credential is None:
        return False
    return hop.record["iat"] > credential["not_after"]


def _narrowing_checked_at_the_first_hop_only(hop: Hop) -> bool:
    """Compare the leaf against its parent and call the chain narrowed."""
    if hop.depth != 1:
        return False
    assert hop.parent is not None
    lattice: list[str] = hop.context["data_class_lattice"]
    if hop.record["data_class"] not in lattice or hop.parent["data_class"] not in lattice:
        return False
    return lattice.index(hop.record["data_class"]) > lattice.index(hop.parent["data_class"])


DEFECTS: dict[str, dict[str, Check]] = {
    "record_signature_invalid": {"verifies_the_leaf_only": _leaf_only_signature},
    "root_key_untrusted": {"anchor_on_any_trusted_key": _anchor_on_any_trusted_key},
    "depth_exceeded": {"off_by_one": _off_by_one_depth},
    "digest_algorithm_unsupported": {"first_link_only": _first_link_algorithm_only},
    "parent_not_found": {"resolves_over_signed_body": _resolves_over_signed_body},
    "credential_unknown": {"case_insensitive_lookup": _case_insensitive_credential_lookup},
    "credential_issuer_mismatch": {
        "issuer_compared_to_the_record_itself": _issuer_compared_to_the_record_itself
    },
    "credential_holder_mismatch": {
        "holder_compared_to_the_parent": _holder_compared_to_the_parent
    },
    "credential_window": {"expiry_only": _expiry_only},
    "data_class_widened": {"first_hop_only": _narrowing_checked_at_the_first_hop_only},
}


# ---------------------------------------------------------------------------
# Mutation machinery
# ---------------------------------------------------------------------------


def _outcomes(rules: tuple[Rule, ...]) -> list[tuple[str, str, tuple[str, ...]]]:
    out = []
    for name, vector in zip(NAMES, VECTORS, strict=True):
        result = verify_chain(vector, rules)
        out.append((name, result.classification, tuple(result.codes)))
    return out


DECLARED = [
    (name, vector["expected"]["classification"], tuple(sorted(vector["expected"]["codes"])))
    for name, vector in zip(NAMES, VECTORS, strict=True)
]


def _without(code: str) -> tuple[Rule, ...]:
    return tuple(rule for rule in RULES if rule.code != code)


def _weakened(code: str, check: Check) -> tuple[Rule, ...]:
    return tuple(
        replace(rule, check=check) if rule.code == code else rule for rule in RULES
    )


def _deviating(rules: tuple[Rule, ...]) -> set[str]:
    """Vector names whose outcome under `rules` departs from their declared block."""
    return {
        was[0] for was, now in zip(DECLARED, _outcomes(rules), strict=True) if was != now
    }


def _margin(code: str) -> set[str]:
    return _deviating(_without(code))


# ---------------------------------------------------------------------------
# 0. Guards on the instrument itself
# ---------------------------------------------------------------------------


def test_the_unmutated_registry_agrees_with_every_declaration() -> None:
    """Without this, every mutation test below measures deviation from a baseline
    that already deviates, and a registry that agrees with nothing passes them all."""
    assert _deviating(RULES) == set()


def test_registry_is_well_formed() -> None:
    assert VECTORS, "no vectors found"
    assert len(RULES) >= 10, "the registry lost entries"
    assert len(set(RULE_CODES)) == len(RULE_CODES), "duplicate rule codes"
    assert all(rule.severity in {"failure", "warning"} for rule in RULES)
    assert all(rule.klass in {"provenance", "authorization", "unverifiable"} for rule in RULES)
    assert all(rule.path in {"record", "root", "resolve", "link"} for rule in RULES)


def test_no_emission_outside_the_registry() -> None:
    """Nothing in the walk may emit a code around the registry.

    The registry is the inventory *because* `_evaluate` is the only place a code is
    emitted. This walks the module's source and fails on an append to a failure or
    warning collection anywhere outside that function, or a literal code passed
    into a result's `failures=` / `warnings=` argument.
    """
    tree = ast.parse(WALK_MODULE.read_text(encoding="utf-8"))

    enclosing: dict[ast.AST, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                enclosing.setdefault(child, node.name)

    offenders: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"failures", "warnings"}
            and enclosing.get(node) != "_evaluate"
        ):
            offenders.append(f"{enclosing.get(node, '<module>')}:{node.lineno} append")
        if isinstance(node, ast.keyword) and node.arg in {"failures", "warnings"}:
            if isinstance(node.value, ast.List):
                for element in node.value.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        offenders.append(
                            f"{enclosing.get(node, '<module>')}: literal "
                            f"{element.value!r} in {node.arg}="
                        )

    assert not offenders, (
        "codes emitted outside the registry, which would make the rule inventory "
        f"incomplete without failing anything: {offenders}"
    )


def test_registry_codes_are_literals() -> None:
    """A code built from a variable or an f-string is invisible to every reader and
    to the cross-reference table in the RFC."""
    tree = ast.parse(WALK_MODULE.read_text(encoding="utf-8"))
    constructions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Rule"
    ]
    assert len(constructions) == len(RULES), (
        "the registry is not built from literal Rule(...) constructions in this module"
    )
    assert all(
        node.args and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        for node in constructions
    ), "a rule code is not a string literal"


# ---------------------------------------------------------------------------
# 1-2. Dead expectations, unexercised rules, unreached outcomes
# ---------------------------------------------------------------------------


def test_no_vector_expects_a_code_the_registry_cannot_emit() -> None:
    declared = {code for vector in VECTORS for code in vector["expected"]["codes"]}
    unknown = sorted(declared - set(RULE_CODES))
    assert not unknown, f"vectors expect codes no rule emits: {unknown}"


def test_every_registered_rule_is_exercised_by_some_vector() -> None:
    declared = {code for vector in VECTORS for code in vector["expected"]["codes"]}
    idle = sorted(set(RULE_CODES) - declared)
    assert not idle, f"registered rules no vector exercises: {idle}"


def test_every_declared_outcome_is_reached_by_some_vector() -> None:
    reached = {vector["expected"]["classification"] for vector in VECTORS}
    assert reached == CLASSIFICATIONS, (
        f"classifications the walk can return that no vector produces: "
        f"{sorted(CLASSIFICATIONS - reached)}"
    )


# ---------------------------------------------------------------------------
# 3-4. Margin and independence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", RULE_CODES)
def test_each_rule_is_load_bearing_for_two_vectors(code: str) -> None:
    """Deleting an obligation must change at least two vectors' outcomes.

    One is existence; two is margin. With a single load-bearing vector, any change
    that weakens or retires that vector silently removes the rule's coverage.
    """
    margin = _margin(code)
    assert len(margin) >= 2, (
        f"removing rule {code!r} changed {len(margin)} vector outcome(s) "
        f"({sorted(margin)}). Two independent vectors are required per rule."
    )


def test_every_rule_declares_a_defect() -> None:
    missing = sorted(set(RULE_CODES) - set(DEFECTS))
    assert not missing, f"registered rules with no declared defect variant: {missing}"
    stale = sorted(set(DEFECTS) - set(RULE_CODES))
    assert not stale, f"defects declared for rules that no longer exist: {stale}"


@pytest.mark.parametrize("code", RULE_CODES)
def test_vectors_for_each_rule_are_independent(code: str) -> None:
    """#124's criterion, executed: some single defect separates the rule's vectors."""
    bearing = _margin(code)
    if len(bearing) < 2:
        pytest.fail(f"rule {code!r} lacks two load-bearing vectors; the margin test covers this")

    separations = {}
    for name, weakened_check in DEFECTS[code].items():
        caught = _deviating(_weakened(code, weakened_check)) & bearing
        if 0 < len(caught) < len(bearing):
            separations[name] = sorted(caught)

    assert separations, (
        f"no declared defect separates the vectors for {code!r}: every weakening "
        f"either fools all of {sorted(bearing)} or none of them. The vectors are "
        "mutually redundant: author one that catches a defect the others miss, or "
        "declare a defect that tells them apart."
    )


# ---------------------------------------------------------------------------
# 5. The ratchet
# ---------------------------------------------------------------------------


def test_margins_have_not_thinned() -> None:
    """A ratchet above the floor. The floor is two."""
    current = {code: len(_margin(code)) for code in RULE_CODES}

    if not MARGINS_FILE.exists():
        MARGINS_FILE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip(f"recorded initial margins to {MARGINS_FILE.name}; re-run to enforce")

    recorded: dict[str, int] = json.loads(MARGINS_FILE.read_text(encoding="utf-8"))
    thinned = {
        key: (recorded[key], current[key])
        for key in recorded
        if key in current and current[key] < recorded[key]
    }
    assert not thinned, (
        "coverage thinned for: "
        + ", ".join(f"{k} {was}->{now}" for k, (was, now) in sorted(thinned.items()))
        + ". Lowering a recorded margin is a decision to make on purpose, in this "
        "commit, with a reason."
    )

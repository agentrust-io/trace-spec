"""Completeness checks over the action-receipt conformance vectors.

`test_action_receipt_fixtures.py` asks whether the vectors are *correct*. This module
asks whether they are *complete*: does every obligation the verifier implements have
vectors that notice when the obligation is gone, and notice it from more than one
direction?

The rule inventory is ``RULES``, the registry the verifier itself consumes. A
hand-maintained rule list drifts when someone forgets to extend it; an inventory
recovered from the verifier's source by AST search has the mirror failure: a rule
written as ``extend([...])``, ``+=``, an f-string or a named constant is invisible to
the walk, and the suite reports complete coverage over an inventory that is quietly
missing entries (#124). The registry inverts that: a check that is not registered
never runs, so it cannot silently exist outside the inventory, and
``test_no_emission_outside_the_registry`` is the residual guard for code that would
try to emit around it.

Mutation therefore targets **named rule hooks**: a rule is deleted by rebuilding the
registry without its entry, or weakened by substituting its check: never by
pattern-matching source text, so the mutation cannot drift away from the code under
test.

The questions, in increasing strength:

1. Does any fixture expect a code the registry cannot produce? (dead expectations)
2. Is every registered rule exercised by some fixture? (unexercised rules)
3. Does deleting each rule change at least **two** fixtures' outcomes? (#124:
   single-vector coverage has no margin: one fixture weakened or renamed away
   silently removes a rule's coverage)
4. Are two of those fixtures **independent**: is there a single plausible
   implementation defect that one catches and the other misses? Two copies of the
   same vector satisfy question 3 and fail this one.
5. Has any rule's margin dropped below what it was? (silent thinning)

Independence is #124's definition made executable. For every rule, ``DEFECTS``
declares at least one *weakened* variant of its check, each modelling a real
implementation shortcut: comparing digest prefixes, case-insensitive identifier
matching, structural signature validation without cryptography, clock-skew
tolerances. A rule's vectors are independent when some declared defect deviates at
least one of them from its expected outcome while leaving another undisturbed. The
declaration is fail-closed: a registered rule with no defect entry fails the suite,
so the question "what bug would your second vector catch that your first would not?"
has to be answered when the rule is added, not after a regression demonstrates it.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from tests.test_action_receipt_fixtures import (
    ACTION_REF_FIELDS,
    RULES,
    STATUSES,
    Rule,
    _decode_base64url,
    _receipt_age_seconds,
    _sha256_jcs,
    _trusted_jwk,
    _verify_fixture,
    discover_fixtures,
)

TESTS_DIR = Path(__file__).parent
VERIFIER_MODULE = TESTS_DIR / "test_action_receipt_fixtures.py"
FIXTURE_DIR = TESTS_DIR.parent / "examples" / "action-receipts" / "conformance"
MARGINS_FILE = TESTS_DIR / "vector_margins.json"
FIXTURES = discover_fixtures(FIXTURE_DIR)

RULE_CODES = tuple(rule.code for rule in RULES)


# ---------------------------------------------------------------------------
# Declared defects: one weakened check per rule, minimum
# ---------------------------------------------------------------------------

Check = Callable[[dict[str, Any]], bool]


def _hash_prefix(value: str) -> str:
    return value[:23]  # "sha256:" + 16 hex characters


def _ci_lookup(fixture: dict[str, Any], signed: dict[str, Any]) -> dict[str, str] | None:
    """A key lookup that normalises case: the classic 'be liberal' shortcut."""
    wanted = signed["issuer_key_id"].lower()
    for key_id, jwk in fixture["trusted_issuer_keys"].items():
        if key_id.lower() == wanted:
            return jwk
    return None


def _sig_malformed(signed: dict[str, Any]) -> bool:
    """Structural validation only: decodes and length-checks, never verifies."""
    try:
        return len(_decode_base64url(signed["signature"])) != 64
    except ValueError:
        return True


def _recomputed_action_ref(fixture: dict[str, Any]) -> str:
    return _sha256_jcs({name: fixture["action"][name] for name in ACTION_REF_FIELDS})


DEFECTS: dict[str, dict[str, Check]] = {
    # An implementation that tests key presence rather than null-ness treats an
    # explicit `"receipt": null` as a receipt.
    "receipt_missing": {
        "treats_explicit_null_as_present": lambda f: "receipt" not in f,
    },
    # Digest comparisons shortened to a prefix: log-friendly truncation that leaks
    # into the comparison.
    "action_ref_invalid": {
        "compares_truncated_digest": lambda f: _hash_prefix(_recomputed_action_ref(f))
        != _hash_prefix(f["action"]["action_ref"]),
    },
    "action_ref_mismatch": {
        "compares_truncated_digest": lambda f: _hash_prefix(f["receipt"]["action_ref"])
        != _hash_prefix(f["action"]["action_ref"]),
    },
    "evidence_hash_mismatch": {
        "compares_truncated_digest": lambda f: _hash_prefix(f["receipt"]["evidence_hash"])
        != _hash_prefix(_sha256_jcs(f["evidence"])),
    },
    "receipt_chain_gap": {
        "compares_truncated_digest": lambda f: _hash_prefix(
            f["receipt"]["previous_receipt_hash"]
        )
        != _hash_prefix(f["context"]["expected_previous_receipt_hash"]),
    },
    # Identifier comparisons that normalise case, as URL- and DID-handling code
    # habitually does.
    "call_id_mismatch": {
        "compares_case_insensitively": lambda f: f["receipt"]["linked_call_id"].lower()
        != f["context"]["call_id"].lower(),
    },
    "session_id_mismatch": {
        "compares_case_insensitively": lambda f: f["receipt"]["session_id"].lower()
        != f["context"]["session_id"].lower(),
    },
    "issuer_key_unknown": {
        "looks_up_keys_case_insensitively": lambda f: _ci_lookup(f, f["receipt"]) is None,
    },
    "decision_invalid": {
        "matches_enum_case_insensitively": lambda f: f["receipt"]["decision"].lower()
        not in {"accepted", "rejected"},
    },
    "unsupported_physical_completion_claim": {
        "compares_case_insensitively": lambda f: f["evidence"][
            "physical_completion_claim"
        ].lower()
        != "none",
    },
    # A signature check that stops at well-formedness.
    "signature_or_key_mismatch": {
        "checks_structure_only": lambda f: _trusted_jwk(f, f["receipt"]) is not None
        and _sig_malformed(f["receipt"]),
    },
    # Freshness windows padded with tolerance an operator once asked for.
    "receipt_stale": {
        "grants_sixty_seconds_grace": lambda f: _receipt_age_seconds(f)
        > f["context"]["max_receipt_age_seconds"] + 60,
    },
    "receipt_from_future": {
        "tolerates_sixty_seconds_skew": lambda f: _receipt_age_seconds(f) < -60,
    },
    # A warning wired to the happy path only.
    "issuer_not_independent": {
        "warns_only_on_accepted": lambda f: f["receipt"]["issuer_independence"]
        == "gateway_self_report"
        and f["receipt"]["decision"] == "accepted",
    },
}


# ---------------------------------------------------------------------------
# Running the verifier under mutation
# ---------------------------------------------------------------------------

Outcome = tuple[str, str, tuple[str, ...], tuple[str, ...]]


def _expected(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))["expected"]


def _outcomes(rules: tuple[Rule, ...]) -> list[Outcome]:
    """Full outcome per fixture: status, failures and warnings.

    Status alone is too coarse. Under a status-only comparison a warning can never be
    load-bearing by construction, which reads as "warnings are untestable" when it is
    only an artifact of what is being compared.
    """
    results: list[Outcome] = []
    for path in FIXTURES:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        try:
            r = _verify_fixture(fixture, rules)
            results.append((path.name, r.status, tuple(r.failures), tuple(r.warnings)))
        except Exception as exc:  # a mutation that breaks the verifier still counts
            results.append((path.name, f"raised:{type(exc).__name__}", (), ()))
    return results


def _baseline() -> list[Outcome]:
    return [
        (path.name, e["status"], tuple(e.get("failures", [])), tuple(e.get("warnings", [])))
        for path, e in ((p, _expected(p)) for p in FIXTURES)
    ]


BASELINE = _baseline()


def _without(code: str) -> tuple[Rule, ...]:
    return tuple(rule for rule in RULES if rule.code != code)


def _weakened(code: str, check: Check) -> tuple[Rule, ...]:
    return tuple(
        replace(rule, check=check) if rule.code == code else rule for rule in RULES
    )


def _deviating(rules: tuple[Rule, ...]) -> set[str]:
    """Fixture names whose outcome under `rules` departs from their expected block."""
    return {
        was[0]
        for was, now in zip(BASELINE, _outcomes(rules), strict=True)
        if was != now
    }


def _margin(code: str) -> set[str]:
    """The fixtures that notice this rule's deletion."""
    return _deviating(_without(code))


# ---------------------------------------------------------------------------
# 0. Guards on the instrument itself
# ---------------------------------------------------------------------------


def test_registry_is_well_formed() -> None:
    """Vacuity and hygiene: the inventory below is only as good as the registry."""
    assert FIXTURES, "no fixtures found"
    assert len(RULES) >= 13, "the registry lost most of its entries"
    assert len(set(RULE_CODES)) == len(RULE_CODES), "duplicate rule codes in the registry"
    assert all(rule.severity in {"failure", "warning"} for rule in RULES)
    assert all(rule.path in {"receipt", "missing"} for rule in RULES)


def test_no_emission_outside_the_registry() -> None:
    """Nothing in the verifier may emit a code around the registry.

    The registry is the inventory *because* `_evaluate` is the only place a code is
    emitted. This walks the verifier's source and fails on: an append to a failure or
    warning collection anywhere else, or a literal code smuggled into a result's
    `failures=`/`warnings=` argument.
    """
    tree = ast.parse(VERIFIER_MODULE.read_text(encoding="utf-8"))

    enclosing: dict[ast.AST, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                enclosing.setdefault(child, node.name)

    findings: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"append", "extend", "insert"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"failures", "warnings"}
            and enclosing.get(node) != "_evaluate"
        ):
            findings.append(
                f"line {node.lineno}: {node.func.value.id}.{node.func.attr}(...) outside "
                "_evaluate"
            )
        if isinstance(node, ast.keyword) and node.arg in {"failures", "warnings"}:
            if isinstance(node.value, ast.List):
                for element in node.value.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        findings.append(
                            f"line {element.lineno}: literal {element.value!r} in a "
                            f"{node.arg}= argument bypasses the registry"
                        )

    assert not findings, (
        "the verifier emits outside the registry, so the inventory is incomplete:\n  "
        + "\n  ".join(findings)
    )


def test_registry_codes_are_literals() -> None:
    """Every `Rule(...)` names its code as a string literal.

    Not needed at runtime, the imported registry is the ground truth either way,
    but a computed code would make the registry unreadable in review, and reviewability
    is half of what the registry is for.
    """
    tree = ast.parse(VERIFIER_MODULE.read_text(encoding="utf-8"))
    computed = [
        f"line {node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Rule"
        and node.args
        and not (
            isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
        )
    ]
    assert not computed, f"Rule() calls with computed codes: {computed}"


# ---------------------------------------------------------------------------
# 1-2. Cheap diagnostics
# ---------------------------------------------------------------------------


def _codes_expected_by_fixtures() -> set[str]:
    codes: set[str] = set()
    for path in FIXTURES:
        expected = _expected(path)
        codes.update(expected.get("failures", []))
        codes.update(expected.get("warnings", []))
    return codes


def test_no_fixture_expects_a_code_the_registry_cannot_emit() -> None:
    """A fixture naming a code nothing produces holds an assertion that cannot fail."""
    orphans = _codes_expected_by_fixtures() - set(RULE_CODES)
    assert not orphans, (
        f"fixtures expect codes no registered rule produces: {sorted(orphans)}. "
        "Either the rule was removed and the fixture kept, or the code is misspelled: "
        "in both cases the fixture is no longer testing anything."
    )


def test_every_registered_rule_is_exercised_by_some_fixture() -> None:
    unexercised = sorted(set(RULE_CODES) - _codes_expected_by_fixtures())
    assert not unexercised, (
        f"{len(unexercised)} obligation(s) have no conformance vector: {unexercised}. "
        "Each is a check a conforming implementation could omit entirely and still pass."
    )


def test_every_declared_outcome_is_reached_by_some_fixture() -> None:
    reached = {_expected(path)["status"] for path in FIXTURES}
    assert not sorted(STATUSES - reached), (
        f"outcomes the verifier can return that no fixture produces: "
        f"{sorted(STATUSES - reached)}"
    )
    assert not sorted(reached - STATUSES), (
        f"fixtures expect outcomes the verifier cannot return: {sorted(reached - STATUSES)}"
    )


# ---------------------------------------------------------------------------
# 3-4. Margin and independence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", RULE_CODES)
def test_each_rule_is_load_bearing_for_two_fixtures(code: str) -> None:
    """Deleting an obligation must change at least two fixtures' outcomes.

    One is existence; two is margin. With a single load-bearing vector, any change
    that weakens or retires that vector silently removes the rule's coverage: the
    failure mode #124 exists to close. A rule here has margin two only if both
    vectors independently notice its deletion, so a vector that merely *names* the
    rule while another rule fires on its input does not count.
    """
    margin = _margin(code)
    assert len(margin) >= 2, (
        f"removing rule {code!r} changed {len(margin)} fixture outcome(s) "
        f"({sorted(margin)}). Two independent vectors are required per rule; with "
        "fewer, coverage rests on a single fixture and disappears with it."
    )


def test_every_rule_declares_a_defect() -> None:
    """Fail closed: registering a rule requires declaring what its second vector adds.

    A rule with no weakened variant cannot demonstrate that its vectors are
    independent rather than copies, so the declaration is part of adding the rule:
    the mirror of the registry requirement on the verifier side.
    """
    missing = sorted(set(RULE_CODES) - set(DEFECTS))
    assert not missing, f"registered rules with no declared defect variant: {missing}"
    stale = sorted(set(DEFECTS) - set(RULE_CODES))
    assert not stale, f"defects declared for rules that no longer exist: {stale}"


@pytest.mark.parametrize("code", RULE_CODES)
def test_vectors_for_each_rule_are_independent(code: str) -> None:
    """#124's criterion, executed: some single defect separates the rule's vectors.

    For at least one declared weakening of the rule, one load-bearing vector must
    catch the defective implementation (its outcome deviates from expected) while
    another passes it. If every declared defect moves all of a rule's vectors
    together, the vectors are redundant copies: every implementation shortcut they
    can detect, they detect identically, and the second vector adds count without
    margin.
    """
    bearing = _margin(code)
    if len(bearing) < 2:
        pytest.fail(f"rule {code!r} lacks two load-bearing vectors; margin test covers this")

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
    """A ratchet above the floor: coverage may not silently get thinner.

    The floor is two. Anything above it that exists today: a rule three or four
    fixtures notice: may not quietly decay back toward the floor: lowering a
    recorded margin is a decision someone has to make on purpose, in the same commit,
    with a reason. Raising one is an ordinary PR.
    """
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
        + f". If the reduction is intended, update {MARGINS_FILE.name} in the same commit "
        "and say why."
    )

    vanished = sorted(set(recorded) - set(current))
    assert not vanished, (
        f"rules that had recorded margins no longer exist: {vanished}. If they were "
        f"removed on purpose, drop them from {MARGINS_FILE.name} in the same commit."
    )

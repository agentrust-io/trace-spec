"""Conformance checks for the informative action-receipt fixture set.

The verifier consumes an explicit registry of named rules (``RULES``) rather than
emitting failure codes inline. The registry is the inventory: every obligation this
verifier enforces is one ``Rule`` entry, and the completeness suite in
`test_vector_completeness.py` mutates registry entries by name: removing or weakening
one hook at a time: to prove each rule is load-bearing for at least two independent
fixtures.

That shape is the review outcome of #124: recovering the rule inventory from this
module's source (by AST-walking for string literals appended to failure lists) stays
blind to ``append`` vs ``extend``, constants, f-strings and refactors: a source-derived
inventory can silently under-count. A registry the verifier itself consumes turns "add
a rule without adding it to the inventory" from heuristically detectable into
structurally difficult: a check that is not registered is a check that never runs, and
an unregistered emission path is a guard failure, not a silent hole.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import ast
import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURE_DIR = Path(__file__).parent.parent / "examples" / "action-receipts" / "conformance"
ACTION_REF_FIELDS = ("agent_id", "action_type", "action_scope", "action_timestamp")

STATUSES = frozenset(
    {
        "receipt_valid_accepted",
        "receipt_valid_rejected",
        "receipt_invalid",
        "receipt_unverified",
        "receipt_missing_required",
    }
)
"""Every outcome the verifier can return. Enforced at construction: a status outside
this set is a bug in the verifier, not a new outcome."""


@dataclass(frozen=True)
class ReceiptResult:
    status: str
    controller_outcome: str
    failures: list[str]
    warnings: list[str]

    def __post_init__(self) -> None:
        assert self.status in STATUSES, f"undeclared verifier outcome {self.status!r}"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_jcs(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _decode_base64url(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise ValueError("fixture value is not valid base64url") from exc


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _receipt_age_seconds(fixture: dict[str, Any]) -> float:
    delta = _parse_timestamp(fixture["context"]["verification_time"]) - _parse_timestamp(
        fixture["receipt"]["issued_at"]
    )
    return delta.total_seconds()


def _trusted_jwk(fixture: dict[str, Any], signed: dict[str, Any]) -> dict[str, str] | None:
    return fixture["trusted_issuer_keys"].get(signed["issuer_key_id"])


def _signature_invalid(signed: dict[str, Any], trusted_jwk: dict[str, str]) -> bool:
    if trusted_jwk.get("kty") != "OKP" or trusted_jwk.get("crv") != "Ed25519":
        return True
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode_base64url(trusted_jwk["x"]))
        signing_input = {key: value for key, value in signed.items() if key != "signature"}
        public_key.verify(_decode_base64url(signed["signature"]), rfc8785.dumps(signing_input))
    except (InvalidSignature, ValueError):
        return True
    return False


# ---------------------------------------------------------------------------
# The rule registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """One named obligation. ``check`` returns True when the defect it guards against
    is observed in the fixture: i.e. True means the code is emitted."""

    code: str
    severity: str  # "failure" | "warning"
    path: str  # "receipt" | "missing"
    check: Callable[[dict[str, Any]], bool] = field(compare=False)


def _action_ref_invalid(f: dict[str, Any]) -> bool:
    preimage = {name: f["action"][name] for name in ACTION_REF_FIELDS}
    return bool(f["action"]["action_ref"] != _sha256_jcs(preimage))


def _action_ref_mismatch(f: dict[str, Any]) -> bool:
    return bool(f["receipt"]["action_ref"] != f["action"]["action_ref"])


def _call_id_mismatch(f: dict[str, Any]) -> bool:
    return bool(f["receipt"]["linked_call_id"] != f["context"]["call_id"])


def _session_id_mismatch(f: dict[str, Any]) -> bool:
    return bool(f["receipt"]["session_id"] != f["context"]["session_id"])


def _evidence_hash_mismatch(f: dict[str, Any]) -> bool:
    return bool(f["receipt"]["evidence_hash"] != _sha256_jcs(f["evidence"]))


def _issuer_key_unknown(f: dict[str, Any]) -> bool:
    # Spec section 3.3.2: a receipt whose issuer key is unknown to the verifier is
    # unverified, not invalid. An unpinned key is an inability to check, not
    # evidence of forgery, so this is an advisory rather than a failure; the
    # structural checks still run, and any of them failing is positive evidence
    # that does make the receipt invalid.
    return _trusted_jwk(f, f["receipt"]) is None


def _receipt_signature_invalid(f: dict[str, Any]) -> bool:
    jwk = _trusted_jwk(f, f["receipt"])
    return jwk is not None and _signature_invalid(f["receipt"], jwk)


def _receipt_stale(f: dict[str, Any]) -> bool:
    return _receipt_age_seconds(f) > f["context"]["max_receipt_age_seconds"]


def _receipt_from_future(f: dict[str, Any]) -> bool:
    return _receipt_age_seconds(f) < 0


def _receipt_chain_gap(f: dict[str, Any]) -> bool:
    return bool(
        f["receipt"]["previous_receipt_hash"] != f["context"]["expected_previous_receipt_hash"]
    )


def _unsupported_physical_completion(f: dict[str, Any]) -> bool:
    return bool(f["evidence"]["physical_completion_claim"] != "none")


def _issuer_not_independent(f: dict[str, Any]) -> bool:
    return bool(f["receipt"]["issuer_independence"] == "gateway_self_report")


def _decision_invalid(f: dict[str, Any]) -> bool:
    return f["receipt"]["decision"] not in {"accepted", "rejected"}


def _receipt_missing(f: dict[str, Any]) -> bool:
    return f.get("receipt") is None


RULES: tuple[Rule, ...] = (
    # -- a required receipt that was never produced ------------------------------
    Rule("receipt_missing", "failure", "missing", _receipt_missing),
    # -- receipts ----------------------------------------------------------------
    Rule("action_ref_invalid", "failure", "receipt", _action_ref_invalid),
    Rule("action_ref_mismatch", "failure", "receipt", _action_ref_mismatch),
    Rule("call_id_mismatch", "failure", "receipt", _call_id_mismatch),
    Rule("session_id_mismatch", "failure", "receipt", _session_id_mismatch),
    Rule("evidence_hash_mismatch", "failure", "receipt", _evidence_hash_mismatch),
    Rule("issuer_key_unknown", "warning", "receipt", _issuer_key_unknown),
    Rule("signature_or_key_mismatch", "failure", "receipt", _receipt_signature_invalid),
    Rule("receipt_stale", "failure", "receipt", _receipt_stale),
    Rule("receipt_from_future", "failure", "receipt", _receipt_from_future),
    Rule("receipt_chain_gap", "failure", "receipt", _receipt_chain_gap),
    Rule(
        "unsupported_physical_completion_claim",
        "failure",
        "receipt",
        _unsupported_physical_completion,
    ),
    Rule("issuer_not_independent", "warning", "receipt", _issuer_not_independent),
    Rule("decision_invalid", "failure", "receipt", _decision_invalid),
)


def _evaluate(
    fixture: dict[str, Any], rules: Sequence[Rule], path: str
) -> tuple[list[str], list[str]]:
    """The single point where rule codes are emitted.

    Everything the verifier reports flows through this loop, which is what makes the
    registry authoritative: the completeness suite asserts by AST that no other code
    in this module appends to a failure or warning list.
    """
    failures: list[str] = []
    warnings: list[str] = []
    for rule in rules:
        if rule.path == path and rule.check(fixture):
            (failures if rule.severity == "failure" else warnings).append(rule.code)
    return failures, warnings


# ---------------------------------------------------------------------------
# Orchestration: paths and outcomes
# ---------------------------------------------------------------------------


def _verify_fixture(fixture: dict[str, Any], rules: Sequence[Rule] = RULES) -> ReceiptResult:
    receipt = fixture.get("receipt")

    if receipt is None:
        if not fixture["context"]["require_receipt"]:
            raise AssertionError("the conformance set has no optional missing-receipt case")
        failures, warnings = _evaluate(fixture, rules, "missing")
        return ReceiptResult(
            status="receipt_missing_required",
            controller_outcome="unknown",
            failures=failures,
            warnings=warnings,
        )

    failures, warnings = _evaluate(fixture, rules, "receipt")

    if failures:
        return ReceiptResult(
            status="receipt_invalid",
            controller_outcome="unknown",
            failures=failures,
            warnings=warnings,
        )

    if "issuer_key_unknown" in warnings:
        # Nothing failed, but nothing was signed by a key the verifier could check
        # either. The receipt confers no trust and proves no wrongdoing, and the
        # controller outcome stays unknown because the evidence is only as good as
        # the unverified receipt that binds it.
        return ReceiptResult(
            status="receipt_unverified",
            controller_outcome="unknown",
            failures=[],
            warnings=warnings,
        )

    status = (
        "receipt_valid_accepted"
        if receipt["decision"] == "accepted"
        else "receipt_valid_rejected"
    )
    return ReceiptResult(
        status=status,
        controller_outcome=fixture["evidence"]["terminal_state"],
        failures=[],
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# The conformance run
# ---------------------------------------------------------------------------

def discover_fixtures(root: Path) -> list[Path]:
    """Every fixture under *root*, at any depth.

    Recursive, because a fixture one directory down was previously discovered by
    nothing: this module did not run it, and `test_vector_completeness` did not
    grade it. A vector expecting a code no registered rule can emit passed the
    whole suite from there, which is the one thing a conformance corpus cannot
    afford to be quiet about.

    Shared with `test_vector_completeness` so the two cannot disagree about what
    the corpus contains. `test_fixture_set_is_complete` still names every file, so
    a nested fixture is an explicit decision rather than an accident.

    Machine-written directories are skipped. Widening the walk without bounding it
    sweeps in `__pycache__` and anything under a dot-directory, neither of which a
    person ever put there as a vector, and a corpus that grades build output is
    worse than one that misses a directory.

    The skip is judged on the path *below* `root`, not on the absolute path: judging
    the whole path discards every fixture whenever the checkout itself sits under a
    dot-directory, which is a plausible place to keep one.
    """
    return sorted(
        path
        for path in root.rglob("*.json")
        if not any(
            part == "__pycache__" or part.startswith(".")
            for part in path.relative_to(root).parts
        )
    )


FIXTURE_PATHS = discover_fixtures(FIXTURE_DIR)


def test_fixture_set_is_complete() -> None:
    assert [path.name for path in FIXTURE_PATHS] == [
        "01-valid-controller-accepted.json",
        "02-valid-controller-rejected.json",
        "03-missing-required-receipt.json",
        "04-signature-key-mismatch.json",
        "05-action-ref-mismatch.json",
        "06-stale-receipt.json",
        "07-receipt-chain-gap.json",
        "08-same-party-self-report.json",
        "09-unsupported-physical-completion.json",
        # 10-16 cover the receipt rules that had no fixture at all. Each was a check a
        # conforming implementation could have omitted entirely while passing this set.
        "10-action-ref-not-recomputable.json",
        "11-call-id-mismatch.json",
        "12-session-id-mismatch.json",
        "13-evidence-hash-mismatch.json",
        "14-receipt-issuer-key-unknown.json",
        "15-receipt-from-future.json",
        "16-decision-not-in-enum.json",
        # 17-30 are the second vector for every rule (#124: two independent vectors
        # each), placed against implementation shortcuts the first set cannot detect:
        # prefix-true digests, case-variant identifiers, one-second boundaries,
        # structural-but-wrong signatures, an explicit-null receipt.
        "17-missing-receipt-explicit-null.json",
        "18-action-ref-tail-forged.json",
        "19-action-ref-mismatch-in-tail.json",
        "20-call-id-case-mismatch.json",
        "21-session-id-case-mismatch.json",
        "22-evidence-hash-mismatch-in-tail.json",
        "23-receipt-issuer-key-case-variant.json",
        "24-receipt-signature-malformed.json",
        "25-stale-receipt-boundary.json",
        "26-receipt-from-future-boundary.json",
        "27-receipt-chain-gap-in-tail.json",
        "28-physical-completion-claim-case.json",
        "29-same-party-self-report-rejected.json",
        "30-decision-case-variant.json",
    ]


@pytest.mark.parametrize("fixture_path", FIXTURE_PATHS, ids=lambda path: path.stem)
def test_action_receipt_conformance_fixture(fixture_path: Path) -> None:
    fixture = _load_fixture(fixture_path)
    assert fixture["profile"] == "trace.action_receipt.conformance.v0"
    result = _verify_fixture(fixture)

    assert result.status == fixture["expected"]["status"]
    assert result.controller_outcome == fixture["expected"]["controller_outcome"]
    assert result.failures == fixture["expected"]["failures"]
    assert result.warnings == fixture["expected"]["warnings"]


def test_discovery_reaches_a_nested_fixture(tmp_path: Path) -> None:
    """The scope of `discover_fixtures`, asserted without depending on the corpus.

    A guard that only checked the committed tree would pass today whatever the glob
    said, since nothing is nested right now. Built here instead, so it fails under a
    flat glob no matter what the corpus happens to contain.
    """
    (tmp_path / "01-top.json").write_text("{}", encoding="utf-8")
    nested = tmp_path / "candidate-set"
    nested.mkdir()
    (nested / "01-nested.json").write_text("{}", encoding="utf-8")

    found = {path.name for path in discover_fixtures(tmp_path)}
    assert found == {"01-top.json", "01-nested.json"}, (
        f"discover_fixtures found {sorted(found)}. A fixture one directory down must "
        "be discovered, or it is graded by nothing and says so to no one."
    )


def test_discovery_skips_machine_written_directories(tmp_path: Path) -> None:
    """The bound on the walk, and the reason it is measured below `root`.

    Recursion without a bound grades `__pycache__`. Bounding it on the absolute path
    instead discards everything whenever the checkout sits under a dot-directory,
    which is where both of these went wrong in turn while this was written.
    """
    root = tmp_path / ".checkout" / "repo"
    for relative in ("01-real.json", "nested/02-real.json",
                     "__pycache__/03-generated.json", ".git/04-internal.json"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")

    found = {path.relative_to(root).as_posix() for path in discover_fixtures(root)}
    assert found == {"01-real.json", "nested/02-real.json"}, (
        f"discover_fixtures found {sorted(found)} under a checkout inside a "
        "dot-directory. Real fixtures at any depth are in; machine-written "
        "directories are out; the path above `root` is not the walk's business."
    )


@pytest.mark.parametrize(
    ("module", "binding"),
    [
        ("test_action_receipt_fixtures.py", "FIXTURE_PATHS"),
        ("test_vector_completeness.py", "FIXTURES"),
    ],
)
def test_both_corpus_readers_go_through_the_shared_discovery(
    module: str, binding: str
) -> None:
    """Neither module may narrow its own view of the corpus.

    Read out of the source, because comparing the two file lists is vacuous while
    nothing is nested: a flat glob and a recursive one then return identical files, so
    the check would pass in exactly the state it exists to detect. That was the first
    version, and a mutation caught it.

    Parsed rather than matched line by line, because the second version read the
    assignment as a line and failed on `BINDING = (` with the call underneath, and on
    an annotated assignment. Both are legal, both are what a formatter or this
    repository's own style produce, and neither is the defect.
    """

    def bound_value(node: ast.stmt) -> ast.expr | None:
        """The value assigned to *binding* by this statement, in either spelling."""
        if isinstance(node, ast.Assign):
            names = [t for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            names = [node.target] if isinstance(node.target, ast.Name) else []
        else:
            return None
        return node.value if any(name.id == binding for name in names) else None

    tree = ast.parse((Path(__file__).parent / module).read_text(encoding="utf-8"))
    bound = [value for node in tree.body if (value := bound_value(node)) is not None]

    assert len(bound) == 1, (
        f"{module} assigns {binding} at module level {len(bound)} times. Renaming or "
        "duplicating it would leave this check with nothing to read, so the count is "
        "asserted rather than assumed."
    )
    value = bound[0]
    assert (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "discover_fixtures"
    ), (
        f"{module} binds {binding} to {type(value).__name__} rather than to a "
        "discover_fixtures call. The two readers then disagree about what the corpus "
        "contains, which is how a nested fixture came to be graded by neither."
    )

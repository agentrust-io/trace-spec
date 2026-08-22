"""Run the delegation-link corpus through a reference walk of the proposed A2A profile.

The `delegation` block is normative in v0.2; what a verifier does with a chain of
them is not, and `docs/rfcs/a2a-delegation-profile.md` is the proposal that would
make it so. This module is that proposal executed: every rule below corresponds to
one numbered requirement in the RFC, and every vector under
`examples/delegation-link/` declares the outcome it expects before this code runs.

The registry is the same shape as `test_action_receipt_fixtures.RULES`, for the
same reason: a check that is not registered never runs, so it cannot exist quietly
outside the inventory that `test_delegation_completeness.py` mutates. Nothing here
is exported from `agentrust_trace` — the package gains no public API for rules
that are not yet normative.

Two orderings in the walk carry weight and are not incidental:

  `parent_not_found` cannot fire while the link's digest algorithm is one this
  verifier does not implement. Reporting a chain invalid because of a link nobody
  looked at is the downgrade-to-escape that `docs/verification.md` forbids in the
  other direction: evidence that does not resolve is unverifiable, and only
  evidence that resolves and contradicts is a failure.

  Provenance outranks authorization in the classification. A chain whose structure
  is broken has no established parent to judge a credential against, so reporting
  an authorization failure over it would be describing a relationship that was
  never demonstrated.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace.validate import iter_errors

VECTOR_DIR = Path(__file__).resolve().parents[1] / "examples" / "delegation-link"

CLASSIFICATIONS = frozenset(
    {"verified", "provenance-invalid", "authorization-invalid", "unverifiable"}
)
"""Every outcome the walk can return. ca2a's Group 7 three-way classification with
`unverifiable` kept distinct from both invalid kinds; collapsing any two of these
is the nonconformance the classification exists to name."""


@dataclass(frozen=True)
class ChainResult:
    classification: str
    failures: list[str]
    warnings: list[str]
    depth: int

    def __post_init__(self) -> None:
        assert self.classification in CLASSIFICATIONS, (
            f"undeclared outcome {self.classification!r}"
        )

    @property
    def codes(self) -> list[str]:
        return sorted(set(self.failures) | set(self.warnings))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _canonical(value: dict[str, Any]) -> bytes:
    return rfc8785.dumps(value)


def _digest(record: dict[str, Any], alg: str) -> str:
    """The profile's preimage: the complete record, signature included.

    The alternative reading — the signed body alone — is what vector 05 is built
    on, and the RFC states why it is rejected: a body digest does not bind the
    parent's signer, so anyone may re-sign identical bytes and satisfy the child's
    commitment.
    """
    return f"{alg}:" + hashlib.new(alg, _canonical(record)).hexdigest()


def _decode_b64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _signature_invalid(record: dict[str, Any]) -> bool:
    """Does `record` fail verification under the key it advertises in `cnf.jwk`?

    The claimed key, not a trusted one: whether the key is trusted is a separate
    question with its own rule, and merging them produces a verifier that cannot
    tell "forged" from "signed by someone you have not heard of"."""
    jwk = record.get("cnf", {}).get("jwk", {})
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        return True
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(_decode_b64u(jwk["x"])).verify(
            _decode_b64u(record["signature"]), _canonical(body)
        )
    except (InvalidSignature, ValueError, KeyError):
        return True
    return False


def _jwk_key(jwk: dict[str, Any]) -> tuple[Any, ...]:
    """A hashable identity for a JWK, over key material only.

    `kid` and other members are advisory; two records naming the same curve point
    hold the same key whatever else they say about it."""
    return (jwk.get("kty"), jwk.get("crv"), jwk.get("x"), jwk.get("y"))


# ---------------------------------------------------------------------------
# The rule registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hop:
    """One position in the walk, with everything a rule may read.

    `parent` is populated only on the `link` path, after the parent record has
    actually been resolved. A rule that needs the parent and runs before it exists
    would be reasoning about a hop that was never demonstrated."""

    record: dict[str, Any]
    context: dict[str, Any]
    index: dict[str, dict[str, Any]]
    depth: int
    parent: dict[str, Any] | None = None

    @property
    def delegation(self) -> dict[str, Any]:
        return self.record["delegation"]

    @property
    def link_algorithm(self) -> str:
        return self.delegation["parent_record_hash"].split(":", 1)[0]

    @property
    def credential(self) -> dict[str, Any] | None:
        return self.context["credentials"].get(self.delegation["credential_id"])


@dataclass(frozen=True)
class Rule:
    """One named obligation. ``check`` returns True when the defect it guards
    against is observed at this hop — True means the code is emitted."""

    code: str
    severity: str  # "failure" | "warning"
    klass: str  # "provenance" | "authorization" | "unverifiable"
    path: str  # "record" | "root" | "resolve" | "link"
    check: Callable[[Hop], bool] = field(compare=False)


def _record_signature_invalid(hop: Hop) -> bool:
    return _signature_invalid(hop.record)


def _root_key_untrusted(hop: Hop) -> bool:
    trusted = {_jwk_key(j) for j in hop.context["trusted_root_keys"]}
    return _jwk_key(hop.record.get("cnf", {}).get("jwk", {})) not in trusted


def _depth_exceeded(hop: Hop) -> bool:
    return hop.depth > hop.context["max_depth"]


def _digest_algorithm_unsupported(hop: Hop) -> bool:
    return hop.link_algorithm not in hop.context["supported_digest_algorithms"]


def _parent_not_found(hop: Hop) -> bool:
    # Guarded on support: a link this verifier cannot compute is unread, not
    # broken, and saying "not found" about it would be a finding nobody made.
    if _digest_algorithm_unsupported(hop):
        return False
    return hop.delegation["parent_record_hash"] not in hop.index


def _credential_unknown(hop: Hop) -> bool:
    return hop.credential is None


def _credential_issuer_mismatch(hop: Hop) -> bool:
    cred = hop.credential
    if cred is None:
        return False
    assert hop.parent is not None
    return cred["issuer"] != hop.parent["subject"]


def _credential_holder_mismatch(hop: Hop) -> bool:
    cred = hop.credential
    if cred is None:
        return False
    return cred["holder"] != hop.record["subject"]


def _credential_window(hop: Hop) -> bool:
    cred = hop.credential
    if cred is None:
        return False
    # Judged at the hop's own `iat`. A chain does not expire because it is being
    # read late, and a verifier using its own clock reports a different answer
    # every day for the same evidence.
    return not (cred["not_before"] <= hop.record["iat"] <= cred["not_after"])


def _data_class_widened(hop: Hop) -> bool:
    assert hop.parent is not None
    lattice: list[str] = hop.context["data_class_lattice"]
    if hop.record["data_class"] not in lattice or hop.parent["data_class"] not in lattice:
        # A class outside the supplied ordering is not comparable. It is not this
        # rule's business to invent a position for it.
        return False
    return lattice.index(hop.record["data_class"]) > lattice.index(hop.parent["data_class"])


RULES: tuple[Rule, ...] = (
    # -- every record on the chain ----------------------------------------------
    Rule("record_signature_invalid", "failure", "provenance", "record",
         _record_signature_invalid),
    # -- the record with no delegation block -------------------------------------
    Rule("root_key_untrusted", "failure", "provenance", "root", _root_key_untrusted),
    # -- following a link, before the parent is known ----------------------------
    Rule("depth_exceeded", "failure", "authorization", "resolve", _depth_exceeded),
    Rule("digest_algorithm_unsupported", "warning", "unverifiable", "resolve",
         _digest_algorithm_unsupported),
    Rule("parent_not_found", "failure", "provenance", "resolve", _parent_not_found),
    # -- the hop, once its parent has been resolved ------------------------------
    Rule("credential_unknown", "failure", "authorization", "link", _credential_unknown),
    Rule("credential_issuer_mismatch", "failure", "authorization", "link",
         _credential_issuer_mismatch),
    Rule("credential_holder_mismatch", "failure", "authorization", "link",
         _credential_holder_mismatch),
    Rule("credential_window", "failure", "authorization", "link", _credential_window),
    Rule("data_class_widened", "failure", "authorization", "link", _data_class_widened),
)


def _evaluate(
    hop: Hop, rules: Sequence[Rule], path: str
) -> tuple[list[str], list[str]]:
    """The single point where rule codes are emitted.

    Everything the walk reports flows through this loop, which is what makes the
    registry authoritative. `test_delegation_completeness` asserts by AST that no
    other function in this module appends to a failure or warning list.
    """
    failures: list[str] = []
    warnings: list[str] = []
    for rule in rules:
        if rule.path == path and rule.check(hop):
            (failures if rule.severity == "failure" else warnings).append(rule.code)
    return failures, warnings


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------


def verify_chain(vector: dict[str, Any], rules: Sequence[Rule] = RULES) -> ChainResult:
    """Walk `vector` from its designated leaf towards the root.

    The record set is a set: it arrives in no useful order, the leaf is named by
    digest rather than by position, and a parent is found by looking its digest up
    rather than by taking the next element. An implementation that reads
    `records[0]` as the root agrees with this one on nothing.

    No cycle check, deliberately. A cycle needs each record's delegation block to
    carry a digest covering the block that names it back, which is a hash
    collision; the reachable analogue is an unbounded chain, and that is what
    `depth_exceeded` is for. The RFC states this rather than leaving a reader to
    wonder which of the two was forgotten.
    """
    context = vector["context"]
    records = vector["records"]

    index: dict[str, dict[str, Any]] = {}
    for algorithm in context["supported_digest_algorithms"]:
        for record in records:
            index[_digest(record, algorithm)] = record

    current = index.get(context["leaf"])
    assert current is not None, (
        f"{vector['id']}: the record under appraisal is not in the vector's own "
        "record set, or is not addressable under a supported digest algorithm"
    )

    failures: list[str] = []
    warnings: list[str] = []
    depth = 0
    visited: set[int] = set()

    while True:
        hop = Hop(record=current, context=context, index=index, depth=depth)

        found, warned = _evaluate(hop, rules, "record")
        failures += found
        warnings += warned

        if "delegation" not in current:
            found, warned = _evaluate(hop, rules, "root")
            failures += found
            warnings += warned
            break

        depth += 1
        hop = replace(hop, depth=depth)
        found, warned = _evaluate(hop, rules, "resolve")
        failures += found
        warnings += warned

        # Whether the walk can continue is a structural fact about the records,
        # asked here directly. The registry says *why* a link could not be
        # followed; it does not decide whether one was. Deriving the control flow
        # from "did any rule fire" instead couples the walk to the registry's
        # contents, and the completeness suite's whole method is to run this
        # function with rules removed — under which that walk stepped off the end
        # of the index and raised, rather than reporting a changed outcome.
        # One reason only: the parent could not be resolved. The depth bound is
        # deliberately *not* repeated here. Repeating it stops the walk at the same
        # record whether or not `depth_exceeded` is registered, so a weakened bound
        # never gets to walk further than a correct one, and the two depth vectors
        # move together under every mutation — margin without independence, which
        # is exactly what #124 says a second vector must not be.
        parent = None
        if hop.link_algorithm in context["supported_digest_algorithms"]:
            parent = index.get(current["delegation"]["parent_record_hash"])
        if parent is None:
            break

        hop = replace(hop, parent=parent)
        found, warned = _evaluate(hop, rules, "link")
        failures += found
        warnings += warned

        # Not a conformance rule, and it cannot fire on a chain anyone can build:
        # a cycle would need a record's delegation block to hold a digest of the
        # block that names it back. It is here so that this function terminates on
        # any input at all, including one hand-edited into a shape the hashes
        # forbid, rather than terminating because the corpus happens to be honest.
        if id(parent) in visited:
            break
        visited.add(id(parent))

        current = parent

    if any(rule.klass == "provenance" for rule in rules if rule.code in failures):
        classification = "provenance-invalid"
    elif failures:
        classification = "authorization-invalid"
    elif warnings:
        classification = "unverifiable"
    else:
        classification = "verified"

    return ChainResult(
        classification=classification,
        failures=failures,
        warnings=warnings,
        depth=depth,
    )


# ---------------------------------------------------------------------------
# The conformance run
# ---------------------------------------------------------------------------

VECTOR_PATHS = sorted(VECTOR_DIR.glob("*.json"))


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vector_set_is_complete() -> None:
    """A glob that silently loses a file passes every test parametrised on it."""
    assert [path.name for path in VECTOR_PATHS] == [
        "01-valid-single-hop.json",
        "02-valid-full-depth-out-of-order.json",
        "03-valid-root-only.json",
        "04-parent-record-absent.json",
        "05-link-over-signed-body.json",
        "06-leaf-signed-by-other-key.json",
        "07-intermediate-signed-by-other-key.json",
        "08-root-key-untrusted.json",
        "09-trusted-key-below-the-root.json",
        "10-credential-not-registered.json",
        "11-credential-id-case-differs.json",
        "12-credential-issued-by-third-party.json",
        "13-credential-self-issued.json",
        "14-credential-held-by-third-party.json",
        "15-credential-holder-is-the-parent.json",
        "16-credential-expired-at-hop.json",
        "17-credential-not-yet-valid-at-hop.json",
        "18-data-class-widened-at-leaf.json",
        "19-data-class-widened-mid-chain.json",
        "20-depth-far-past-the-bound.json",
        "21-depth-one-past-the-bound.json",
        "22-leaf-link-uses-sha384.json",
        "23-deep-link-uses-sha384.json",
    ]


def test_vector_ids_match_their_filenames() -> None:
    """The id is the cross-reference surface and the filename is how anyone finds
    the file; a vector renumbered in one and not the other is citable under a name
    that leads somewhere else."""
    for path in VECTOR_PATHS:
        number = int(path.stem.split("-", 1)[0])
        assert _load(path)["id"] == f"TRACE-DELEG-{number:03d}", path.name


def test_every_vector_is_emitted_leaf_first() -> None:
    """Not decoration. The set is emitted in the order least likely to be right for
    an implementation that reads position, so that such an implementation fails on
    the first vector rather than on the first shuffled input in production."""
    for path in VECTOR_PATHS:
        vector = _load(path)
        assert _digest(vector["records"][0], "sha256") == vector["context"]["leaf"], (
            f"{path.name}: the first emitted record is not the leaf"
        )


def test_each_vector_holds_exactly_one_root() -> None:
    """Two roots is two chains, and a walk that reaches either would be judging a
    record set nobody meant to present. Vector 04 drops a record from the middle,
    which leaves the root intact and the chain broken — the defect it is for."""
    for path in VECTOR_PATHS:
        vector = _load(path)
        roots = [r for r in vector["records"] if "delegation" not in r]
        assert len(roots) == 1, f"{path.name}: {len(roots)} records without a delegation block"


def test_the_trusted_key_placement_that_separates_08_from_09() -> None:
    """Both vectors are 'the root is not trusted', and only one of them catches an
    implementation that anchors on any trusted key it can find. That difference is
    a property of where the keys sit, not of the walk, so it is pinned here: 09 has
    a trusted key below its root and 08 has none anywhere. Lose either half and the
    pair collapses into two copies of one test."""
    for name, trusted_key_present in (
        ("08-root-key-untrusted.json", False),
        ("09-trusted-key-below-the-root.json", True),
    ):
        vector = _load(VECTOR_DIR / name)
        trusted = {_jwk_key(jwk) for jwk in vector["context"]["trusted_root_keys"]}
        held = {_jwk_key(r.get("cnf", {}).get("jwk", {})) for r in vector["records"]}
        root = next(r for r in vector["records"] if "delegation" not in r)
        assert _jwk_key(root["cnf"]["jwk"]) not in trusted, f"{name}: the root is trusted"
        assert bool(trusted & held) is trusted_key_present, (
            f"{name}: expected trusted key present={trusted_key_present} on the chain"
        )


def test_vector_ids_are_unique_and_ordered() -> None:
    """IDs are the cross-reference surface with ca2a's ACTION-* set and are never
    reused. A duplicate would silently retire whichever case is read second."""
    ids = [_load(path)["id"] for path in VECTOR_PATHS]
    assert len(set(ids)) == len(ids), "duplicate vector id"
    assert ids == sorted(ids), "vector ids do not follow file order"


@pytest.mark.parametrize("path", VECTOR_PATHS, ids=lambda p: p.stem)
def test_every_record_is_schema_valid(path: Path) -> None:
    """A defect the schema already rejects is not a profile defect.

    Every record in every vector — including the ones built to fail — validates
    against `trace-claim.json`. Otherwise a rule here could be "passing" only
    because its vector is malformed in some louder, unrelated way.
    """
    vector = _load(path)
    for position, record in enumerate(vector["records"]):
        errors = list(iter_errors(record))
        assert not errors, (
            f"{vector['id']} record {position} is not schema-valid: "
            f"{[e.message for e in errors][:3]}"
        )


@pytest.mark.parametrize("path", VECTOR_PATHS, ids=lambda p: p.stem)
def test_vector_reaches_its_declared_outcome(path: Path) -> None:
    vector = _load(path)
    result = verify_chain(vector)
    expected = vector["expected"]
    assert result.classification == expected["classification"], (
        f"{vector['id']} ({vector['name']}): expected "
        f"{expected['classification']}, got {result.classification} "
        f"with {result.codes}"
    )
    assert result.codes == sorted(expected["codes"]), (
        f"{vector['id']} ({vector['name']}): expected codes "
        f"{sorted(expected['codes'])}, got {result.codes}"
    )


@pytest.mark.parametrize("path", VECTOR_PATHS, ids=lambda p: p.stem)
def test_outcome_is_independent_of_record_order(path: Path) -> None:
    """The record set is a set.

    Every vector is emitted leaf-first already, so this reverses it back to
    root-first and rotates it, and asserts the walk is unmoved. A verifier that
    reads position — `records[0]` as the root, or the next element as the parent —
    passes the corpus in one ordering and fails in another, and which one it met
    first is not a property of the implementation.
    """
    vector = _load(path)
    baseline = verify_chain(vector)
    records = vector["records"]
    for permutation in (list(reversed(records)), records[1:] + records[:1]):
        shuffled = {**vector, "records": permutation}
        assert verify_chain(shuffled).codes == baseline.codes
        assert verify_chain(shuffled).classification == baseline.classification


def test_the_corpus_exercises_every_classification() -> None:
    """Three-way classification is the contract; a corpus that never produces one
    of the outcomes cannot tell a verifier that collapses it from one that does."""
    produced = {verify_chain(_load(path)).classification for path in VECTOR_PATHS}
    assert produced == CLASSIFICATIONS, f"never produced: {sorted(CLASSIFICATIONS - produced)}"


def test_the_rejected_digest_reading_is_what_vector_05_isolates() -> None:
    """Vector 05's whole value is that it separates two readings of one sentence.

    If the leaf's link happened to resolve under the profile's reading too, the
    vector would be testing nothing and no one would notice, because it would
    still report `parent_not_found` for some other reason. This pins the
    counterfactual: recomputing the link over the parent's signed body finds the
    parent exactly, which is what makes the vector a boundary rather than a
    coincidence.
    """
    vector = _load(VECTOR_DIR / "05-link-over-signed-body.json")
    leaf = next(r for r in vector["records"] if "delegation" in r)
    parent = next(r for r in vector["records"] if "delegation" not in r)
    claimed = leaf["delegation"]["parent_record_hash"]

    body = {k: v for k, v in parent.items() if k != "signature"}
    body_digest = "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()

    assert claimed == body_digest, "vector 05 no longer links over the signed body"
    assert claimed != _digest(parent, "sha256"), (
        "the two readings agree on this vector, which makes it a boundary that "
        "does not separate anything"
    )

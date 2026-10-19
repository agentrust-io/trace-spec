"""Run the delegation-link corpus through a reference walk of the proposed A2A profile.

The `delegation` block is normative in v0.2; what a verifier does with a chain of
them is not, and `docs/rfcs/a2a-delegation-profile.md` is the proposal that would
make it so. This module is that proposal executed: every rule below corresponds to
one numbered requirement in the RFC, and every vector under
`examples/delegation-link/` declares the outcome it expects before this code runs.

The registry is the same shape as `test_action_receipt_fixtures.RULES`, for the
same reason: a check that is not registered never runs, so it cannot exist quietly
outside the inventory that `test_delegation_completeness.py` mutates. Nothing here
is exported from `agentrust_trace`: the package gains no public API for rules
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

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

try:
    from agentrust_trace.delegation import (
        CLASSIFICATIONS,
        RULES,
        ChainResult,
        Rule,
        _jwk_key,
        parent_record_hash as _digest,
        verify_delegation_chain,
    )
except ImportError:
    pytest.fail("unimplemented")

from agentrust_trace.sign import _canonical_bytes as _canonical
from agentrust_trace.validate import iter_errors

VECTOR_DIR = Path(__file__).resolve().parents[1] / "examples" / "delegation-link"


def verify_chain(vector: dict[str, Any], rules: Sequence[Rule] = RULES) -> ChainResult:
    """Walk `vector` from its designated leaf towards the root via `agentrust_trace.delegation`."""
    return verify_delegation_chain(
        vector["records"],
        vector["context"]["leaf"],
        vector["context"],
        rules=rules,
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
        "24-parent-key-supplementary-plane.json",
        "25-data-class-unknown-at-leaf.json",
        "26-data-class-unknown-at-parent.json",
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
    which leaves the root intact and the chain broken: the defect it is for."""
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

    Every record in every vector, including the ones built to fail, validates
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
    reads position, `records[0]` as the root, or the next element as the parent,
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

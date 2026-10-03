"""Adequacy of the policy-resolution set, per the criteria on trace-spec#186.

agentrust-io/trace-spec#186 (merged 2026-08-20) states what a conformance
vector set is claiming: *a verifier that does not implement these rules will
fail this set*. Three of its four criteria are checkable here and are checked;
the fourth is about repository-wide bookkeeping and is noted below.

It merged into trace-spec, where it grades that repository's ``examples/``.
This repository has no adequacy harness, so nothing here is subject to it.
These criteria are a standard this set was built to by choice, and the tests
below are this set holding itself to them.

    1. A set must fail BOTH unconditional implementations.
       A set of all-rejections is passed by a verifier that rejects everything,
       exactly as a set of all-acceptances is passed by one that accepts
       everything. Vectors 01, 02 and 06 close the second half.
    2. Every boundary needs more than one vector.
       One vector cannot separate a check that reads a prefix from one that
       reads the whole object.
    3. Every set on disk is measured, or named with the test that measures it.
       Repository-wide; trace-tests has no registry to add to, so it cannot be
       asserted from inside one set. Recorded in the set's README instead.
    4. Shortfalls are recorded exactly.
       See KNOWN_SHORTFALLS below.

THE UNIT OF MEASUREMENT
    Each vector's expected value is the status of the TR-POL-003 finding, not
    a verdict on the whole record. That is narrower than a record-level pass
    or fail on purpose: these records are unsigned, so they carry findings
    from other modules that have nothing to do with the check under test.
    Every claim about margin below is a claim about that one finding.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

VECTOR_DIR = Path(__file__).parent / "vectors" / "policy-resolution"

ACCEPTING = {"pass", "skip"}
REJECTING = {"fail"}
ALL_STATUSES = ACCEPTING | REJECTING | {"unverified"}
BOUNDARIES = {"accept", "contradicted", "unresolvable", "malformed"}

# Criterion 4: shortfalls asserted to their exact extent, so they cannot widen
# quietly. Delete an entry when the shortfall is closed, not when it is excused.
KNOWN_SHORTFALLS = {
    "unresolvable_outcome_unnamed": (
        "Vectors 05 and 11 assert that the check did not run, which is a fact "
        "about the run. The level at which that stops being tolerable is suite "
        "policy in src/trace_tests/modules/unverified.py, not a reading of any "
        "merged text: policy_uri appears nowhere in the specification. Tracked "
        "on agentrust-io/trace-spec#190."
    ),
    "no_network_resolution": (
        "The resolver in every test here reads bytes from disk. Nothing in this "
        "set exercises an HTTP fetch, a redirect, a timeout, or a TLS failure, "
        "so the mapping from real-world retrieval failures onto the unverified "
        "status is asserted rather than measured."
    ),
}


def _vectors() -> list[dict]:
    out = []
    for path in sorted(VECTOR_DIR.glob("[0-9][0-9]-*.json")):
        out.append(json.loads(path.read_text(encoding="utf-8")))
    return out


def _status(vector: dict) -> str:
    return vector["expected"]["tr_pol_003"]


@pytest.mark.level0
def test_the_set_is_not_empty() -> None:
    assert len(_vectors()) == 11, "the set is eleven vectors, 01 through 11"


@pytest.mark.level0
def test_criterion_1_the_set_fails_an_accept_everything_verifier() -> None:
    """At least one vector a conformant verifier must reject."""
    rejects = [v for v in _vectors() if _status(v) in REJECTING]
    assert rejects, (
        "every vector expects acceptance, so a verifier that accepts "
        "unconditionally passes the set"
    )


@pytest.mark.level0
def test_criterion_1_the_set_fails_a_reject_everything_verifier() -> None:
    """At least one vector a conformant verifier must accept.

    This is the criterion the set would otherwise fail. Its subject is a family
    of resolution failures, so every vector written from the motivating problem
    alone is a reject.
    """
    accepts = [v for v in _vectors() if _status(v) in ACCEPTING]
    assert accepts, (
        "no vector expects acceptance, so a verifier that rejects "
        "unconditionally passes the set"
    )
    assert len(accepts) >= 2, (
        "one must-accept vector cannot separate a verifier that accepts only "
        "records declaring no policy_uri from one that also checks a matching "
        "digest; 01 and 02 are that pair"
    )


@pytest.mark.level0
def test_criterion_1_a_verifier_that_never_resolves_does_not_pass() -> None:
    """A verifier that answers "skip" to everything must fail the set too.

    Without this, a module that returned SKIP unconditionally would satisfy
    both halves of criterion 1, because SKIP reads as acceptance.
    """
    non_skip = [v for v in _vectors() if _status(v) != "skip"]
    assert len(non_skip) >= 2, (
        "a verifier that skips every record would pass this set unnoticed"
    )


@pytest.mark.level0
def test_criterion_2_every_boundary_carries_at_least_two_vectors() -> None:
    counts = Counter(v["boundary"] for v in _vectors())
    thin = {b: n for b, n in counts.items() if n < 2}
    assert not thin, f"boundaries carried by a single vector: {thin}"
    assert set(counts) == BOUNDARIES, f"unexpected boundary set: {sorted(counts)}"


@pytest.mark.level0
def test_no_two_vectors_share_a_defect() -> None:
    defects = [v["defect"] for v in _vectors()]
    dupes = [d for d, n in Counter(defects).items() if n > 1 and d != "none"]
    assert not dupes, f"defect exercised by more than one vector: {dupes}"


@pytest.mark.level0
def test_every_expected_block_is_well_formed() -> None:
    for v in _vectors():
        exp = v["expected"]
        assert set(exp) == {"tr_pol_003", "reason"}, (
            f"{v['name']}: an expected block is a status and the reason for it, "
            f"nothing else; got {sorted(exp)}"
        )
        assert exp["tr_pol_003"] in ALL_STATUSES, (
            f"{v['name']}: {exp['tr_pol_003']!r} is not a finding status"
        )
        assert exp["reason"].strip(), f"{v['name']}: an expected status needs a reason"


@pytest.mark.level0
def test_every_vector_carries_an_anchor_naming_its_tier() -> None:
    """An expected outcome that names no source is an assertion, not a derivation.

    Tier 1 is merged specification prose. Tier 2 is the packaged schema, which
    this suite tests conformance against but which is not the specification.
    Tier 0 means no text governs the case, and a vector claiming it must say
    what it asserts instead.
    """
    for v in _vectors():
        anchor = v["context"]["anchor"]
        assert set(anchor) == {"tier", "source", "text", "applies"}, (
            f"{v['name']}: malformed anchor {sorted(anchor)}"
        )
        assert anchor["tier"] in (0, 1, 2), f"{v['name']}: unknown tier"
        assert anchor["applies"].strip(), f"{v['name']}: an anchor must say how it applies"
        if anchor["tier"] == 0:
            assert anchor["text"] == "", (
                f"{v['name']}: tier 0 means no governing text, so quoting one is a "
                "contradiction"
            )
            assert "no merged sentence" in anchor["source"], (
                f"{v['name']}: tier 0 must say plainly that nothing governs the case"
            )
        else:
            assert anchor["text"].strip(), f"{v['name']}: tier {anchor['tier']} must quote text"


@pytest.mark.level0
def test_the_unresolvable_vectors_do_not_claim_a_specification_requirement() -> None:
    """The one thing this set must never do: invent authority it does not have."""
    for v in _vectors():
        if v["boundary"] != "unresolvable":
            continue
        assert v["context"]["anchor"]["tier"] == 0, (
            f"{v['name']}: no merged text governs an unresolvable policy_uri"
        )
        assert "suite policy" in v["context"]["anchor"]["applies"], (
            f"{v['name']}: the level must be named as suite policy, not as a "
            "specification requirement"
        )


@pytest.mark.level0
def test_no_vector_proposes_an_appraisal_status_value() -> None:
    """The set answers a policy-binding question and must not reach for another.

    ``appraisal.status`` values are decided one layer up, on
    agentrust-io/trace-spec#190. A vector that named one would be proposing a
    schema change under cover of a fixture.
    """
    for v in _vectors():
        blob = json.dumps(v)
        for value in ("contraindicated", "no_verifier_exercised"):
            assert value not in blob, (
                f"{v['name']} names {value!r}; this set does not propose "
                "appraisal.status values"
            )
        assert v["record"]["appraisal"]["status"] == "affirming", (
            f"{v['name']}: appraisal.status is fixed across the set"
        )


@pytest.mark.level0
def test_appraisal_policy_ref_is_identical_across_the_set() -> None:
    """The retarget's whole point: the varying field is policy.*, not appraisal.*."""
    refs = {v["record"]["appraisal"]["policy_ref"] for v in _vectors()}
    assert len(refs) == 1, f"appraisal.policy_ref varies across the set: {sorted(refs)}"


@pytest.mark.level0
def test_every_record_is_identical_outside_the_policy_block() -> None:
    seen = []
    for v in _vectors():
        rec = {k: val for k, val in v["record"].items() if k != "policy"}
        seen.append(json.dumps(rec, sort_keys=True))
    assert len(set(seen)) == 1, (
        "records differ outside policy.*, so a finding could be answering "
        "something other than the check under test"
    )


@pytest.mark.level0
def test_known_shortfalls_are_recorded_not_silent() -> None:
    assert KNOWN_SHORTFALLS, "a set with no recorded shortfalls is claiming to have none"
    for key, text in KNOWN_SHORTFALLS.items():
        assert text.strip(), f"{key} is recorded with no explanation"

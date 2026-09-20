"""What the verifier-compatibility set can still tell apart, measured rather than assumed.

A vector set is a claim that an implementation which does not do the thing will fail
it. Nothing in the set's own tests checks that claim: they run *this* verifier and
compare verdicts, so they pass whether or not any other implementation could pass too.

Measured against a verifier implementing none of the four obligations in
agentrust-io/trace-spec#116, the set separates 4 of its 8 vectors. The figure lives
in one place, next to `SEPARATING` below, and this paragraph names it only because a
reader arrives here first: it read `3 of 8` for as long as it took someone to notice,
which is the drift this module exists to prevent, happening to the module's own
headline number. Four refusal vectors separate nothing, and the reason is structural
rather than a flaw in how they were written:

`schema/trace-claim.json` pins `eat_profile` with a `const`, so a record carrying any
other profile is schema-invalid. Since upstream #156 made `verify_record` validate
against that schema, every such record is refused by the schema whether or not the
verifier implements a single profile rule. Vectors 02, 05, 07 and 11 all carry
exactly those records, and their `expected.statement` is null, so there is no second
signal to separate on either. The rule underneath is exact in both directions and is
asserted below: **a vector separates the null verifier if and only if its record is
schema-valid.**

The set was separating when it was written. #156 introduced a second gate covering the
same inputs, and no vector was edited. **Verdict stability is not coverage stability:**
a vector set has to be re-measured when the implementation changes, not only when the
vectors do. This module is that measurement, recorded exactly so the number cannot
drift in either direction unnoticed.

## One mutation is not a measurement

Everything above measures against a single wrong implementation: one that reverts the
whole proposal. Killing it shows the vectors are not vacuous and nothing more. The
question a reader actually has is which rows they may delete, and that is answered only
by the fix a competent implementer would have written and that looks right.

`PANEL` below is eight such near misses, each a plausible reading of #116 rather than an
absence of one, and `SEPARATION` records what each one is caught by. Read down a column
rather than across: a vector that is the only entry in some column is one nobody may
delete, and a column that is empty is a wrong implementation this set cannot see.

It was nine for three days. The tenth was a verifier that applies every rule the
reference applies and reports one generic label for every refusal, added on 2026-09-12
by widening `_panel_separates` to compare the refusal's stated cause. The review on the
pull request settled that this verifier is conformant, so the widening is reverted and
that entry is now a control that nothing here may separate, beside `_v_reference`. The
panel is eight. The one figure the revert moved is the membership reading, which no
longer fails vector 06: it refused that vector for the right verdict under a different
rule, and a different rule is not a wrong answer any more.

One column is empty. It is recorded in `SHORTFALLS` with the reason and the condition
under which the reason expires, and `test_recorded_shortfalls_have_not_closed` fails
when it does, which is the only way a shortfall gets revisited rather than inherited.

Every live vector is the only entry in some column, so on this measurement none of them
is deletable: 06 for an empty set read as a wildcard, 04 for a verifier checking only the
first declared member, 09 for one checking only the last, and 01 for obligation 3 being
absent. `test_no_live_vector_is_redundant` pins that, and it is written to fail in both
directions, because "nothing here is redundant" is the kind of claim that stops being
true quietly. It read "09 is the one live vector with nothing unique to it" until
2026-09-15, which was wrong in the file that exists to keep this honest: 09 has had that
column to itself throughout. 09 also carries the second vector for
`unschemaed_profile_in_accepted_set`, which is the margin property recorded in
`tests/test_adequacy_all_sets.py`, so it would be kept even if some other vector took its
column: a row can be redundant under one measurement and load-bearing under another.
"""
from __future__ import annotations
import itertools
import json
import pathlib
import sys
from unittest import mock

import pytest

from agentrust_trace import sign as _sign
from agentrust_trace.validate import profiles_with_schema, validate_json

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "examples/verifier-compatibility"

V2 = "tag:agentrust-io.com,2026:trace-v0.2"
V01 = "tag:agentrust.io,2026:trace-v0.1"
SCHEMAED = profiles_with_schema()
"""The profiles this build carries a schema for, read out of the packaged schema files
rather than restated here.

Restating it is how this module first got the relationship between the two declared-set
rules backwards. `trace-v0.1.json` ships, so the v0.1 identifier *is* a profile this
build can check, and the rule forbidding it in a declared set is therefore independent
of the rule requiring every member to be checkable. A hardcoded `{V2}` made the second
rule appear to subsume the first, and the panel below agreed with itself because both
sides came from the same wrong constant.
"""


class Refused(Exception):
    """A verifier declining to verify. The panel raises it; the real one raises
    ValueError and InvalidSignature."""


GATE = "gate"
"""The label `_base_checks` refuses under, distinguished from every obligation label.

A pre-116 build refuses a non-v0.2 record through the profile const and the schema, and
neither knows which of #116's rules would have applied. So a gate refusal is not a claim
about a rule, and `_panel_separates` does not compare it against a vector's stated
failure. Without the exemption the reference implementation is separated by six vectors
and the panel's control collapses; that is asserted below rather than left as a remark.
"""


def _base_checks(record: dict, trusted_jwk: dict) -> str:
    """Everything every build on this codebase already does, before #116.

    Two independent refusals of a non-v0.2 record, and the assertion below is the
    positive control on the claim that they cover the same inputs: `verify_record`'s
    own `eat_profile` check, and `validate_json` against a schema whose `eat_profile`
    is a `const`. A vector carrying a non-v0.2 record measures these, not an obligation.
    """
    profile = record.get("eat_profile")
    refused_by_profile_check = not (isinstance(profile, str) and profile == V2)
    try:
        validate_json(record)
        refused_by_schema = False
    except Exception:
        refused_by_schema = True
    assert refused_by_profile_check == refused_by_schema, (
        f"the two gates disagree on {profile!r}: the module's account of why six "
        "vectors separate nothing rests on them covering the same inputs"
    )
    if refused_by_profile_check:
        raise Refused("gate")
    # Delegate to `verify_record` rather than replicate it. Until 2026-09-12 this
    # function hand-copied the signature and key checks, and a hand-written copy of
    # `verify_record`'s gates cannot see a gate that lands inside `verify_record`,
    # which is the single event this module exists to catch. Measured: a gate at the
    # top of `verify_record` refusing every record left the replica at 25 passed and
    # takes the delegating version to 20 failed.
    #
    # The default accepted set is used deliberately. A verifier that has not read #116
    # declares nothing, and the degenerate hardcoded set of one is exactly the state
    # this proposal exists to replace.
    try:
        _sign.verify_record(record, trusted_jwk, max_age_seconds=None)
    except Exception as exc:
        raise Refused(str(exc)) from exc
    return profile


def null_verifier(record: dict, trusted_jwk: dict) -> None:
    """Everything `verify_record` does except the four obligations under test.

    Signature, key material and schema, and no return value: it signals success by
    returning rather than by describing what it established. A real implementation
    that simply had not read #116 looks like this.
    """
    _base_checks(record, trusted_jwk)


def _fixtures() -> dict[str, dict]:
    out = {p.stem: json.loads(p.read_text()) for p in sorted(VECTORS.glob("*.json"))}
    assert out, "no fixtures loaded; this module would pass while measuring nothing"
    return out


def _separates(vector: dict) -> bool:
    """True when the null verifier's behaviour differs from what the vector expects."""
    expected = vector["expected"]
    try:
        null_verifier(vector["record"], vector["trusted_key"])
        outcome, statement = "verified", None
    except Exception:
        outcome, statement = "refused", None
    if outcome != expected["outcome"]:
        return True
    # Same verdict: the vector can still separate if it requires a statement, which a
    # verifier that returns nothing cannot produce.
    return expected.get("statement") is not None and statement is None


# Recorded, not asserted as a threshold. The honest figure is 4 of 8 and a test that
# demanded more would be failing on a truth rather than on a regression. Adding a
# separating vector fails this and the entry is updated; losing one fails it too.
#
# It was 3 of 8, then 4 of 9. What moved is instructive and is the reason this file
# exists: the refusal vectors that separate nothing do so because the schema pins
# `eat_profile` with a `const`, so their records are refused by the schema whether or
# not a verifier implements any profile rule at all. The ones that were added separate
# precisely because their records are innocent v0.2 records and the only defect is in
# the verifier's declared configuration, which no schema can catch. A vector aimed at
# a configuration rule has to carry a record with nothing wrong with it.
#
# That rule is what 10 was written to, and it is why 10 separated where 08 did not
# although both pinned the same boundary: 08 presented a v0.1 record, which the schema
# refuses on its own. Both have since left, 08 on 2026-09-15 for the same reason 10 left
# before it. Vector 10, which put the v0.1 identifier first in the accepted set
# against an innocent record, left this set on 2026-09-13: the Project Lead ruled on #116
# that the v0.1 cutover is merged normative text, so a vector for it tests an existing
# rule rather than pinning an obligation this issue proposes, and it belongs with the
# cutover's own coverage in `test_sign.py`. The configuration-side rule it exercised,
# that the accepted set may not name v0.1, is still implemented in `sign.py` and is now
# tested there.
SEPARATING = frozenset({
    "01-known-version-verified",              # requires a statement naming the profile
    "04-unschemaed-profile-refused",          # a declared profile with no schema, last
    "06-empty-accepted-set-refused",          # the record is valid; only the config is wrong
    "09-unschemaed-profile-first-in-set-refused",  # the same defect, first in the set
})


def test_separation_is_exactly_what_is_recorded() -> None:
    measured = {name for name, v in _fixtures().items() if _separates(v)}
    assert measured == SEPARATING, (
        "the set's separating power changed.\n"
        f"  recorded: {sorted(SEPARATING)}\n"
        f"  measured: {sorted(measured)}\n"
        "A vector that stopped separating did so because the implementation gained "
        "a gate covering the same input, not because anyone edited it."
    )


@pytest.mark.parametrize("name", sorted(SEPARATING))
def test_each_recorded_vector_really_separates(name: str) -> None:
    """Guards the record against being satisfied by an empty measurement."""
    assert _separates(_fixtures()[name])


def test_the_null_verifier_still_accepts_a_conformant_record() -> None:
    """A null verifier that rejected everything would separate every vector and make
    the measurement meaningless. It has to be a plausible implementation, not a broken
    one."""
    null_verifier(*(lambda v: (v["record"], v["trusted_key"]))(
        _fixtures()["01-known-version-verified"]))


def test_a_vector_separates_exactly_when_its_record_is_schema_valid() -> None:
    """The structural rule, stated in the docstring, asserted in both directions.

    It is the whole account of why six vectors are inert, and it is the rule that
    decides what a rebuilt set may contain: a vector aimed at an obligation has to
    carry a record the schema has no quarrel with, or it measures the schema.
    """
    fixtures = _fixtures()

    def schema_valid(record: dict) -> bool:
        try:
            validate_json(record)
            return True
        except Exception:
            return False

    valid = {name for name, v in fixtures.items() if schema_valid(v["record"])}
    separating = {name for name, v in fixtures.items() if _separates(v)}
    assert valid == separating, (
        "separation and schema-validity came apart.\n"
        f"  schema-valid: {sorted(valid)}\n"
        f"  separating  : {sorted(separating)}\n"
        "Either a gate moved or a vector was rewritten; both invalidate the recorded "
        "figure and the account of it in this module's docstring."
    )
    assert valid, "positive control: no record is schema-valid, so this proves nothing"


# --------------------------------------------------------------------------------
# The panel: wrong implementations, each a reading of #116 rather than an absence of
# one. The rule they are built to is to mutate toward the near miss: reverting the
# change tests only that the vectors are not vacuous, and the question a reader of the
# set has is which rows carry their own weight. #124 gives the checkable form, that two
# vectors are independent when one implementation defect makes one pass and the other
# fail, and that injecting the defect is how you find out.
# --------------------------------------------------------------------------------

def _set_integrity(accepted: list[str]) -> None:
    """Obligation 2 read as a constraint on the declared set rather than on the record."""
    if not accepted:
        raise Refused("no_accepted_profiles")
    if V01 in accepted:
        raise Refused("superseded_profile_in_accepted_set")
    for entry in accepted:
        if entry not in SCHEMAED:
            raise Refused("unschemaed_profile_in_accepted_set")


def _statement(profile: str, accepted: list[str]) -> dict:
    return {"profile": profile, "accepted_profiles": list(accepted)}


def _v_null(record, jwk, accepted):
    """Has not read #116 at all."""
    _base_checks(record, jwk)
    return "verified", None


def _v_membership(record, jwk, accepted):
    """Obligation 2 exactly as the issue words it: "declares the set of versions it
    supports and MUST refuse versions outside that set". A membership test, and
    nothing about the declared set itself. Obligation 3 done properly."""
    profile = _base_checks(record, jwk)
    if profile not in accepted:
        raise Refused("profile_not_accepted")
    return "verified", _statement(profile, accepted)


def _v_empty_is_wildcard(record, jwk, accepted):
    """A membership test in which an empty declared set means "no restriction".
    The allowlist bug, which is a configuration default rather than a typo."""
    profile = _base_checks(record, jwk)
    if accepted:
        _set_integrity(accepted)
        if profile not in accepted:
            raise Refused("profile_not_accepted")
    return "verified", _statement(profile, accepted)


def _integrity_at(accepted: list[str], index: int) -> None:
    if not accepted:
        raise Refused("no_accepted_profiles")
    entry = accepted[index]
    if entry == V01:
        raise Refused("superseded_profile_in_accepted_set")
    if entry not in SCHEMAED:
        raise Refused("unschemaed_profile_in_accepted_set")


def _v_first_member_only(record, jwk, accepted):
    """Checks the declared set, but only its first member."""
    profile = _base_checks(record, jwk)
    _integrity_at(accepted, 0)
    if profile not in accepted:
        raise Refused("profile_not_accepted")
    return "verified", _statement(profile, accepted)


def _v_last_member_only(record, jwk, accepted):
    """Checks the declared set, but only its last member."""
    profile = _base_checks(record, jwk)
    _integrity_at(accepted, -1)
    if profile not in accepted:
        raise Refused("profile_not_accepted")
    return "verified", _statement(profile, accepted)


def _v_v01_rule_only(record, jwk, accepted):
    """Never the v0.1 identifier, and no check that the rest are checkable."""
    profile = _base_checks(record, jwk)
    if not accepted:
        raise Refused("no_accepted_profiles")
    if V01 in accepted:
        raise Refused("superseded_profile_in_accepted_set")
    if profile not in accepted:
        raise Refused("profile_not_accepted")
    return "verified", _statement(profile, accepted)


def _v_no_statement(record, jwk, accepted):
    """Obligation 2 in full, obligation 3 absent: returns what upstream's
    `VerificationResult` carries today, which is a revocation check and a thumbprint
    and no profile."""
    profile = _base_checks(record, jwk)
    _set_integrity(accepted)
    if profile not in accepted:
        raise Refused("profile_not_accepted")
    return "verified", None


def _v_hardcoded_profile(record, jwk, accepted):
    """Obligations 2 and 3, with the statement's fields written as literals rather
    than reported. Satisfies obligation 3's letter and observes nothing."""
    profile = _base_checks(record, jwk)
    _set_integrity(accepted)
    if profile not in accepted:
        raise Refused("profile_not_accepted")
    return "verified", _statement(V2, [V2])


def _v_wrong_reason(record, jwk, accepted):
    """Every rule of the reference, every refusal reported under one generic label.

    The near miss nothing in this module could see until 2026-09-12. It reaches the
    right verdict on all eight vectors and reaches it by applying the right rules; what
    it does not do is say which rule fired, so an operator handed `profile_not_accepted`
    for an empty declared set goes looking at the record instead of at their own
    configuration.

    Whether #116 obliges this was the open question on the pull request, and the review
    settled it: it does not. `expected.failure` is informative, the portable adapter
    asserts the verdict and the statement and nothing about which rule refused, and this
    verifier is conformant rather than a near miss. It is kept here as the control that
    nothing in the set may separate, which is why it sits outside `PANEL`.

    The draft normative text for #116, held for a maintainer to carry and not part of
    this change, says a verifier SHOULD report refusal-for-an-unimplemented-profile
    distinguishably from a verification failure, which is a coarser distinction and a
    SHOULD, and its "what is deliberately not required" paragraph declines to mandate any
    field name. Asserting a rule name was the set asking more of a foreign implementation
    than the text it encodes.
    """
    profile = _base_checks(record, jwk)
    try:
        _set_integrity(accepted)
    except Refused:
        raise Refused("profile_not_accepted") from None
    if profile not in accepted:
        raise Refused("profile_not_accepted")
    return "verified", _statement(profile, accepted)


def _v_reference(record, jwk, accepted):
    """Both obligations, honestly. The control: it must be separated by nothing."""
    profile = _base_checks(record, jwk)
    _set_integrity(accepted)
    if profile not in accepted:
        raise Refused("profile_not_accepted")
    return "verified", _statement(profile, accepted)


PANEL = {
    "null: has not read #116": _v_null,
    "obligation 2 as worded: a membership test": _v_membership,
    "an empty declared set read as a wildcard": _v_empty_is_wildcard,
    "declared set checked, first member only": _v_first_member_only,
    "declared set checked, last member only": _v_last_member_only,
    "no rule that a declared member be checkable": _v_v01_rule_only,
    "obligation 2 in full, obligation 3 absent": _v_no_statement,
    "obligations 2 and 3, statement hardcoded": _v_hardcoded_profile,
}


def _panel_separates(verifier, vector: dict) -> bool:
    """Outcome, then every key the statement names. Wider than `_separates`, which
    compares presence only.

    The refusal's stated cause is deliberately not compared, and was, between
    2026-09-12 and 2026-09-15. Comparing it made `_v_wrong_reason` look like a wrong
    implementation, and the review settled that it is not one: `expected.failure` is
    informative, a verifier that applies every agreed rule and reports one generic
    refusal conforms, and a panel that separates it is measuring this library's
    diagnostics rather than #116's obligations. `_v_wrong_reason` is now a control that
    must be separated by nothing, beside `_v_reference`, and
    `tests/test_verifier_compatibility_fixtures.py` carries the portable half of the
    same control.
    """
    expected = vector["expected"]
    try:
        outcome, statement = verifier(
            vector["record"], vector["trusted_key"],
            vector["verifier"]["accepted_profiles"])
    except Exception:
        outcome, statement = "refused", None
    if outcome != expected["outcome"]:
        return True
    if outcome == "refused":
        # The refusal's stated cause is not compared; see this function's docstring.
        return False
    want = expected.get("statement")
    if want is None:
        return False
    if statement is None:
        return True
    return any(statement.get(key) != value for key, value in want.items())


SEPARATION = {
    "null: has not read #116": frozenset({
        "01-known-version-verified",
        "04-unschemaed-profile-refused",
        "06-empty-accepted-set-refused",
        "09-unschemaed-profile-first-in-set-refused"}),
    "obligation 2 as worded: a membership test": frozenset({
        "04-unschemaed-profile-refused",
        "09-unschemaed-profile-first-in-set-refused"}),
    "an empty declared set read as a wildcard": frozenset({
        "06-empty-accepted-set-refused"}),
    "declared set checked, first member only": frozenset({
        "04-unschemaed-profile-refused"}),
    "declared set checked, last member only": frozenset({
        "09-unschemaed-profile-first-in-set-refused"}),
    "no rule that a declared member be checkable": frozenset({
        "04-unschemaed-profile-refused",
        "09-unschemaed-profile-first-in-set-refused"}),
    "obligation 2 in full, obligation 3 absent": frozenset({
        "01-known-version-verified"}),
    "obligations 2 and 3, statement hardcoded": frozenset(),
}
"""What each near miss is caught by. Read down a column rather than across: the rows
that appear once are the ones whose deletion would cost coverage, and the entry whose
value is empty is a wrong implementation this set cannot see at all."""


SHORTFALLS = {
    "obligations 2 and 3, statement hardcoded":
        "This build carries a schema for two profiles and every conformant declared "
        "set must exclude one of them, the v0.1 identifier, so exactly one declared "
        "set is conformant and exactly one profile can appear in a conformant "
        "statement. A literal and an observation print the same string. Expires when "
        "a second profile schema ships, which is the decision recorded in #114.",
}
"""Wrong implementations no vector separates, with the reason and its expiry.

Recorded rather than fixed, because no vector written against this build can fix
them. The test below fails when one expires, so the set is revisited at that point
instead of inheriting a figure that has quietly stopped being true.
"""


def test_no_live_vector_is_redundant() -> None:
    """Each of the four is the sole entry in some column, measured rather than asserted.

    The docstring at the top of this module made a claim of this shape and had it wrong
    for as long as nobody recomputed it. Written to fail in both directions: a vector
    that stops being anyone's only catch, and a vector that becomes one.
    """
    fixtures = _fixtures()
    live = {n for n, v in fixtures.items() if _separates(v)}
    sole = {sorted(caught)[0] for caught in SEPARATION.values() if len(caught) == 1}
    assert sole == live, (
        f"the vectors that are some column's only catch are {sorted(sole)} and the live "
        f"vectors are {sorted(live)}; the module's account of which rows are deletable is "
        "stale in whichever direction they differ")


def test_a_generic_refusal_is_separated_by_nothing() -> None:
    """The control the review asked for, at the panel's level.

    `_v_wrong_reason` applies every rule the reference applies and reports one generic
    label for all of them. It is conformant, so nothing in this set may separate it.
    This fails the day `_panel_separates` starts comparing the refusal's stated cause
    again, which is the one change that would make the set stricter than the text it
    encodes.
    """
    fixtures = _fixtures()
    separated = sorted(n for n, v in fixtures.items() if _panel_separates(_v_wrong_reason, v))
    assert not separated, (
        f"a verifier that names no rule is separated by {separated}; this set is asking "
        "for a diagnostic #116's draft text does not require")


@pytest.mark.parametrize("label", sorted(PANEL))
def test_the_panel_separation_is_exactly_what_is_recorded(label: str) -> None:
    fixtures = _fixtures()
    measured = frozenset(
        name for name, v in fixtures.items() if _panel_separates(PANEL[label], v))
    assert measured == SEPARATION[label], (
        f"what {label!r} is caught by changed.\n"
        f"  recorded: {sorted(SEPARATION[label])}\n"
        f"  measured: {sorted(measured)}"
    )


def test_the_reference_verifier_is_separated_by_nothing() -> None:
    """The control on the whole panel. A vector that separates an implementation
    doing everything the proposal asks is testing something the proposal does not
    ask for, and every count above would be inflated by it."""
    caught = [name for name, v in _fixtures().items()
              if _panel_separates(_v_reference, v)]
    assert not caught, (
        f"the reference implementation is separated by {caught}, so those vectors "
        "encode something other than obligations 2 and 3")


def test_recorded_shortfalls_have_not_closed() -> None:
    """The ratchet. Fails when a shortfall stops being one.

    A recorded shortfall is a promise to revisit, and a promise nothing checks is how
    `3 of 8` survived #156. When this fails, the entry comes out of `SHORTFALLS` and
    the vector that now separates goes in.
    """
    fixtures = _fixtures()
    for label in SHORTFALLS:
        caught = [name for name, v in fixtures.items()
                  if _panel_separates(PANEL[label], v)]
        assert not caught, (
            f"recorded shortfall closed: {label!r} is now separated by {caught}.\n"
            f"  recorded reason: {SHORTFALLS[label]}\n"
            "Remove the entry and record what closed it."
        )
    assert SHORTFALLS, "positive control: an empty shortfall list asserts nothing"
    # The loop above fires only once some vector separates the entry, and no vector
    # here exercises a second profile, so shipping one would not move it. The entry's
    # stated expiry has to be asserted directly or the ratchet names a condition it
    # does not watch.
    assert len(_conformant_declared_sets()) == 1, (
        "the recorded shortfall's stated expiry has arrived: more than one declared "
        f"set is now conformant ({_conformant_declared_sets()}), so a conformant run "
        "has more than one profile to report and a literal is no longer "
        "indistinguishable from an observation. Write the vector that separates "
        "'obligations 2 and 3, statement hardcoded' and remove the entry.")


def test_the_comparison_does_not_look_at_the_refusal_cause_and_that_is_deliberate() -> None:
    """The revert of 2026-09-12's widening, pinned with the control that shows it is one.

    Between 2026-09-12 and 2026-09-15 `_panel_separates` compared the refusal's stated
    cause, which made `_v_wrong_reason` look like a wrong implementation. The review on
    the pull request settled that it is not: `expected.failure` is informative and a
    verifier that applies every agreed rule and names none of them conforms.

    Two halves, and the second is what makes the first mean something. The live
    comparison separates that verifier by nothing. A comparison that does look at the
    cause separates it by three, so the difference between the two is real and the
    choice between them is a decision rather than an accident of how the code is
    written. If the second assertion ever measures nothing, this test has stopped
    being able to tell the two comparisons apart and the first one is worthless.
    """
    fixtures = _fixtures()

    live = sorted(n for n, v in fixtures.items() if _panel_separates(_v_wrong_reason, v))
    assert not live, f"the live comparison separates the generic refuser by {live}"

    def compares_the_cause(verifier, vector) -> bool:
        """`_panel_separates` as it stood while the cause was compared."""
        expected = vector["expected"]
        reason = None
        try:
            outcome, statement = verifier(
                vector["record"], vector["trusted_key"],
                vector["verifier"]["accepted_profiles"])
        except Refused as exc:
            outcome, statement, reason = "refused", None, str(exc)
        except Exception:
            outcome, statement = "refused", None
        if outcome != expected["outcome"]:
            return True
        if outcome == "refused":
            want_failure = expected.get("failure")
            return bool(want_failure and reason is not None
                        and reason != GATE and reason != want_failure)
        want = expected.get("statement")
        if want is None:
            return False
        if statement is None:
            return True
        return any(statement.get(key) != value for key, value in want.items())

    would_separate = sorted(
        n for n, v in fixtures.items() if compares_the_cause(_v_wrong_reason, v))
    assert would_separate, (
        "positive control: a comparison that looks at the cause separates the generic "
        "refuser by nothing either, so this test cannot tell the two apart")

    assert not [n for n, v in fixtures.items() if compares_the_cause(_v_reference, v)], (
        "positive control: the reference must be separated by neither comparison")


def test_every_panel_entry_is_either_caught_or_a_recorded_shortfall() -> None:
    """No silent third category. A near miss that nothing catches is either written
    down with its reason or it is an unrecorded hole."""
    silent = {label for label, caught in SEPARATION.items()
              if not caught and label not in SHORTFALLS}
    assert not silent, (
        f"these wrong implementations are separated by nothing and are not recorded "
        f"as shortfalls: {sorted(silent)}")


UNCHECKABLE_PROBES = (
    "tag:example.com,2025:trace-v0.0", "tag:agentrust-io.com,2031:trace-v9.9")
"""Two profiles this build carries no schema for: a third party's and a future one.
Fixed, because "a profile the build cannot check" is not something the build can
enumerate for itself."""


def _declared_set_universe() -> tuple[str, ...]:
    """Every profile a declared set could name, read from the build where it can be.

    Hardcoding this list is what let the ratchet below sleep through its own expiry.
    `SHORTFALLS` says its entry expires when a second usable profile schema ships, and
    a hardcoded universe cannot contain a profile that does not exist yet, so shipping
    one left every count unchanged and every test green. Checked by mutation: adding a
    `trace-v0.3` schema to the package now widens this and fails three tests.

    The probes are subtracted from rather than appended to the packaged set, because
    the two lists can overlap exactly when the ratchet fires. A probe that ships a
    schema appears in both and `itertools.combinations` then enumerates every subset
    twice: measured, five members, thirty-two combinations, sixteen distinct sets. The
    duplication is loud but misdiagnoses itself, since what fails is the readings split
    and the conformant-set count, both of which report a number that moved while the
    thing that moved is the universe underneath them.
    """
    return tuple(sorted(SCHEMAED)) + tuple(
        probe for probe in UNCHECKABLE_PROBES if probe not in SCHEMAED)


DECLARED_SET_UNIVERSE = _declared_set_universe()
"""Four members today, so sixteen subsets: v0.1 and v0.2 from the packaged schemas, plus
the two probes. Both halves move -- a shipped schema widens the first, and the probe list
is a choice made here -- so nothing downstream restates either number as a literal."""


def test_the_declared_set_universe_is_a_set_and_still_has_an_uncheckable_member() -> None:
    """Positive control on the enumeration every count below is taken over.

    Two ways the universe stops being what the counts assume, neither of which any
    other test here can see. It gains a duplicate, and the subsets are enumerated twice
    each. Or every probe ships a schema, and "a profile this build cannot check" leaves
    the domain entirely, taking the `unschemaed_profile_in_accepted_set` half of the
    analysis with it while the arithmetic stays consistent.
    """
    universe = _declared_set_universe()
    assert len(universe) == len(set(universe)), (
        f"the universe repeats a member: {universe}. Every subset below is enumerated "
        "twice and the counts double.")
    assert [p for p in universe if p not in SCHEMAED], (
        f"every member of {universe} is now a profile this build carries a schema for, "
        "so no declared set here can name an uncheckable profile and the rule vectors "
        "04 and 09 pin has no domain left. Add a probe that is still uncheckable.")
    assert set(SCHEMAED) <= set(universe), (
        f"positive control: {sorted(set(SCHEMAED) - set(universe))} is a packaged "
        "profile missing from the universe")


def _declared_sets() -> list[tuple[str, ...]]:
    universe = _declared_set_universe()
    return [c for r in range(len(universe) + 1)
            for c in itertools.combinations(universe, r)]


def _conformant_declared_sets() -> list[list[str]]:
    out = []
    for combo in _declared_sets():
        try:
            _set_integrity(list(combo))
        except Refused:
            continue
        out.append(list(combo))
    return out




def _membership_only(accepted: list[str], record: dict, jwk: dict) -> tuple[str, str | None]:
    """Obligation 2 exactly as issue 116 words it, and nothing more.

    "declares the set of versions it supports and MUST refuse versions outside that
    set". A membership test over the record's profile, with no rule about the set.
    """
    try:
        profile = _base_checks(record, jwk)
    except Exception:
        return "refused", "gate"
    if profile not in accepted:
        return "refused", "profile_not_accepted"
    return "verified", None


def _stronger_reading(accepted: list[str], record: dict, jwk: dict) -> tuple[str, str | None]:
    """Obligation 2 as this set actually pins it: constraints on the declared set,
    checked before membership, which is the order `verify_record` uses."""
    try:
        profile = _base_checks(record, jwk)
    except Exception:
        return "refused", "gate"
    try:
        _set_integrity(list(accepted))
    except Refused as exc:
        return "refused", str(exc)
    if profile not in accepted:
        return "refused", "profile_not_accepted"
    return "verified", None


def _admissible() -> tuple[str, ...]:
    """The profiles `_set_integrity` lets a declared set contain: schemaed, not v0.1."""
    return tuple(sorted(p for p in SCHEMAED if p != V01))


def _readings_split(universe: int, admissible: int) -> dict[str, int]:
    """How the two readings of obligation 2 divide the declared sets, in closed form.

    These were three literals, 7 and 8 and 1 over sixteen sets, and they read as a
    measurement. They are not one. Membership verifies exactly the sets containing v0.2,
    of which there are `2**(u-1)`; the stronger reading verifies those that are also
    subsets of the admissible profiles, of which there are `2**(a-1)`. So the two give
    opposite verdicts on the difference, agree with different reasons on one more than
    that, and agree identically on `2**a - 1`.

    Neither `u` nor `a` says anything about #116, the vector set, or which reading is
    right. `u` is how many entries `UNCHECKABLE_PROBES` happens to carry, a choice made
    in this file: one probe gives 3 of 8, five give 63 of 128. `a` is how many usable
    profile schemas the build packages, which is the `SHORTFALLS` entry's own expiry
    condition. Verified against the enumeration at eight combinations of the two by
    `test_the_readings_split_is_arithmetic_not_a_measurement`.

    This took one argument until an hour after it was written, and read `2**(u-1) - 1`
    with "always" attached. That form is right only while exactly one declared set is
    conformant, which is today and is the condition `SHORTFALLS` is waiting to see end.
    Packaging upstream's `schema/trace-claim-v0.3-draft.json`, which exists on main
    today from #277 and is not packaged, takes `a` to 2 and the figure to 14 of 32. The
    defect was the scope of the word rather than the arithmetic, and it was caught by
    running the mutation rather than by re-checking the sum.

    What the enumeration does establish is the direction, which holds at every `u` and
    `a` and is the claim the ruling turns on: wherever they disagree, membership
    verifies and the stronger reading refuses. A vector saying `refused` takes the
    stronger reading's side, so the choice between the two cannot be deferred past the
    fixtures.

    An earlier version of this module instead asserted that membership is never the sole
    cause of a refusal, and proved it by filtering the sets through `_set_integrity`
    first. That is the stronger reading, so the claim was its own premise: the filter
    left an empty domain and the assertion could not fail. Against a verifier that
    implements membership and nothing else, membership is the sole cause in half of
    them.
    """
    return {
        "opposite verdicts": 2 ** (universe - 1) - 2 ** (admissible - 1),
        "same verdict, different reason": 2 ** (universe - 1) - 2 ** (admissible - 1) + 1,
        "identical": 2 ** admissible - 1,
    }


READINGS = _readings_split(len(DECLARED_SET_UNIVERSE), len(_admissible()))


def test_the_two_readings_of_obligation_2_are_mutually_exclusive() -> None:
    """The two readings are not "one testable and one not". They are mutually
    exclusive about the same configurations, and a vector states one outcome.

    Wherever they disagree the membership reading verifies and the stronger reading
    refuses, so the stronger reading is strictly the more refusing of the two. That is
    what a vector encodes when it says `refused`, and it is why the choice between the
    readings cannot be deferred past the fixtures. The direction is the finding; the
    count is arithmetic, for which see `_readings_split`.
    """
    fixture = _fixtures()["01-known-version-verified"]
    record, jwk = fixture["record"], fixture["trusted_key"]

    tally = dict.fromkeys(READINGS, 0)
    opposite: list[list[str]] = []
    for combo in _declared_sets():
        accepted = list(combo)
        m_outcome, m_reason = _membership_only(accepted, record, jwk)
        s_outcome, s_reason = _stronger_reading(accepted, record, jwk)
        if m_outcome != s_outcome:
            tally["opposite verdicts"] += 1
            opposite.append(accepted)
            assert (m_outcome, s_outcome) == ("verified", "refused"), (
                f"{accepted}: the stronger reading is supposed to be the more refusing "
                f"of the two, and here it is not ({m_outcome} vs {s_outcome})")
        elif m_reason != s_reason:
            tally["same verdict, different reason"] += 1
        else:
            tally["identical"] += 1

    assert tally == READINGS, f"the split moved.\n  recorded: {READINGS}\n  measured: {tally}"
    assert sum(READINGS.values()) == len(_declared_sets()), "the three buckets must partition"
    # Positive control: the record has to be one the gates accept, or every set lands in
    # "identical" by being refused before either reading is reached.
    assert _membership_only([V2], record, jwk) == ("verified", None), (
        "control: the reference record is refused by the pre-116 gates, so this test is "
        "comparing two readings neither of which ever runs")
    # Every set the two readings disagree about contains v0.2 alongside something the
    # stronger rules refuse. This is the reason for the closed form in `_readings_split`
    # and it is what makes the count arithmetic rather than evidence.
    assert all(V2 in a and len(a) > 1 for a in opposite), (
        f"the disagreements are no longer 'v0.2 plus an inadmissible entry': {opposite}")


def test_the_readings_split_is_arithmetic_not_a_measurement() -> None:
    """`_readings_split`'s closed form against the enumeration it replaces.

    Run at every universe size from two to seven, with synthetic probes, so the claim
    that the figure is forced by the probe count is checked rather than asserted. If
    this holds, no number in `READINGS` carries information about #116 and none of them
    belongs in an argument about which reading a vector should encode.
    """
    fixture = _fixtures()["01-known-version-verified"]
    record, jwk = fixture["record"], fixture["trusted_key"]
    seen = {}
    for extra_schemas, probe_count in ((0, 0), (0, 1), (0, 2), (0, 3),
                                       (1, 0), (1, 2), (2, 2), (3, 1)):
        extra = {f"tag:example.test,2026:readings-schema-{i}" for i in range(extra_schemas)}
        probes = tuple(f"tag:example.test,2026:readings-probe-{i}" for i in range(probe_count))
        assert not extra & set(probes), "a synthetic schema collided with a synthetic probe"
        # The schemaed set is built from V2 and V01 outright rather than from whatever
        # the build packages, so the pairs below are exactly the ones named in the
        # control and shipping a real second schema does not fail this test with a
        # message about arithmetic. What the build packages is watched by
        # `test_exactly_one_declared_set_is_conformant_today` and by the ratchet.
        schemaed = frozenset({V2, V01}) | extra
        universe = tuple(sorted(schemaed)) + probes
        admissible = tuple(p for p in schemaed if p != V01)
        with mock.patch.object(sys.modules[__name__], "SCHEMAED", schemaed):
            tally = dict.fromkeys(READINGS, 0)
            for size in range(len(universe) + 1):
                for combo in itertools.combinations(universe, size):
                    accepted = list(combo)
                    m_outcome, m_reason = _membership_only(accepted, record, jwk)
                    s_outcome, s_reason = _stronger_reading(accepted, record, jwk)
                    if m_outcome != s_outcome:
                        tally["opposite verdicts"] += 1
                    elif m_reason != s_reason:
                        tally["same verdict, different reason"] += 1
                    else:
                        tally["identical"] += 1
        want = _readings_split(len(universe), len(admissible))
        assert tally == want, (
            f"universe {len(universe)}, admissible {len(admissible)}: the closed form "
            f"says {want} and the enumeration says {tally}")
        seen[(len(universe), len(admissible))] = tally["opposite verdicts"]
    assert seen == {(2, 1): 1, (3, 1): 3, (4, 1): 7, (5, 1): 15,
                    (3, 2): 2, (5, 2): 14, (6, 3): 28, (6, 4): 24}, (
        f"positive control: the disagreement count is supposed to move with both "
        f"quantities, and here it went {seen}")


def test_the_committed_fixtures_already_take_the_stronger_reading() -> None:
    """Which side of that disagreement the committed fixtures already take.

    Vectors 04 and 09 carry declared sets the two readings disagree about, and both
    three expect a refusal, which is the stronger reading's answer. As set values they
    are two, not three: 04 and 09 differ only in the order of the same two members. A
    reader deciding the ruling should know the fixtures are not neutral.

    Membership in the disagreement set is tested by its definition -- v0.2 present
    alongside an entry the stronger rules refuse -- rather than against a count, since
    the count is arithmetic in the probe list and this property is not.
    """
    fixtures = _fixtures()
    encoded = {}
    for name in ("04-unschemaed-profile-refused",
                 "09-unschemaed-profile-first-in-set-refused"):
        vector = fixtures[name]
        accepted = vector["verifier"]["accepted_profiles"]
        assert V2 in accepted and len(accepted) > 1, (
            f"{name}'s declared set {accepted} is not one the two readings disagree "
            "about, so it says nothing about which reading the fixtures encode")
        assert vector["expected"]["outcome"] == "refused", (
            f"{name} no longer expects the stronger reading's answer")
        encoded[frozenset(accepted)] = vector["expected"]["failure"]
    assert len(encoded) == 1, (
        f"expected one declared set across those two vectors, which declare the same two "
        f"members in opposite order, got {len(encoded)}")


def test_exactly_one_declared_set_is_conformant_today() -> None:
    """The fact the recorded shortfall reduces to, enumerated rather than argued.

    While this returns one, obligation 3's statement content is untestable: a conformant
    run has one profile to report and one declared set to report, so a literal cannot be
    told from an observation. The same enumeration is what
    `test_recorded_shortfalls_have_not_closed` watches, and it is kept in one place so
    the two cannot disagree about what conformant means.
    """
    assert len(_declared_sets()) == 2 ** len(DECLARED_SET_UNIVERSE), (
        "positive control: the enumeration is not the powerset of the universe. This "
        "read `== 16` until 2026-09-12, which is a literal in the probe count and not a "
        "property, so adding a probe failed it here rather than where it belongs.")
    ok = _conformant_declared_sets()
    assert ok == [[V2]], (
        f"the conformant declared sets are now {ok}. More than one means the shortfall "
        "recorded above has expired; fewer means nothing verifies.")


# Nominal margin and separating margin, per rule this set names. `KNOWN_THIN` in
# `tests/test_adequacy_all_sets.py` records which rules are carried by a single vector,
# which is #124's property. It counts vectors. Two rules here have two vectors and
# fewer than two that separate anything, so the margin they report is made of vectors a
# defect in the rule would not move. Recorded rather than repaired: the vectors that do
# not separate are the gate-covered ones, and no vector written against this build can
# separate them. The cross-set instrument is left alone; this is a fact about this set.
MARGIN = {
    "no_accepted_profiles":               (1, 1),
    "profile_absent":                     (2, 0),
    "profile_not_accepted":               (2, 0),
    "unschemaed_profile_in_accepted_set": (2, 2),
    "verified":                           (1, 1),
}


def test_margin_measured_in_separating_vectors_is_what_is_recorded() -> None:
    """Two vectors for a rule are two only if a defect in that rule moves both.

    #124 defines two vectors as independent when a single implementation defect makes
    one pass and the other fail, and observes that the definition is mechanically
    checkable by injecting the defect. `PANEL` is that injection. Running it against
    the rules rather than against the set is how a rule with two vectors and one
    discriminating vector becomes visible, which counting vectors cannot show.
    """
    fixtures = _fixtures()
    separating = {name for name in fixtures
                  if any(_panel_separates(PANEL[label], fixtures[name])
                         for label in PANEL)}
    measured: dict[str, tuple[int, int]] = {}
    for name, vector in fixtures.items():
        rule = vector["expected"]["failure"] or "verified"
        total, sep = measured.get(rule, (0, 0))
        measured[rule] = (total + 1, sep + (1 if name in separating else 0))
    assert measured == MARGIN, (
        "margin moved.\n"
        f"  recorded: {dict(sorted(MARGIN.items()))}\n"
        f"  measured: {dict(sorted(measured.items()))}\n"
        "The first number is vectors naming the rule, the second is how many of them "
        "any wrong implementation in the panel is caught by.")
    assert any(sep < total for total, sep in MARGIN.values()), (
        "positive control: if no rule had a nominal margin above its separating "
        "margin, this test would be asserting a tautology")


@pytest.mark.parametrize(
    "value",
    ["tag:agentrust-io.com,2026:trace-v0.2", 123, None, {"a": 1}, b"bytes", [1, 2]],
    ids=["bare-str", "int", "None", "dict", "bytes", "non-str-elements"],
)
def test_accepted_profiles_refuses_the_shapes_that_iterate_wrongly(value):
    """Found by the #325 sweep on the rebase, not by this file. A bare URI string was
    iterated as characters and refused for naming ``'t'`` as an unschemaed profile, which
    is the right verdict with the wrong cause, the class the panel above was widened to
    see. An int or None left ``verify_record`` as ``TypeError``, undocumented. All six
    now refuse with the documented ``ValueError`` and a message about the shape."""
    from agentrust_trace import sign
    with pytest.raises(ValueError, match="accepted_profiles must"):
        sign.verify_record({}, None, accepted_profiles=value)


def test_accepted_profiles_guard_is_load_bearing():
    """Control: a real tuple gets past the shape guard and is refused, if at all, for
    what it contains. Without this the test above could pass against a guard that
    refuses everything."""
    from agentrust_trace import sign
    with pytest.raises(ValueError) as caught:
        sign.verify_record({}, None, accepted_profiles=("tag:example.com,2025:trace-v0.0",))
    assert "carries no schema" in str(caught.value)

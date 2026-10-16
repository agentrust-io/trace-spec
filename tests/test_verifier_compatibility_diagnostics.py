"""What *this* implementation says when it refuses, which is not the portable contract.

`tests/test_verifier_compatibility_fixtures.py` runs the vectors as any implementation
would, and asserts the verdict and the statement and nothing about the refusal's stated
cause. `expected.failure` is informative there: a verifier that applies every agreed rule
and reports one generic refusal conforms, and that module carries the control proving it.

The diagnostics are still worth having, and they are worth having *here*, separately,
for two reasons. They are a promise this library makes to its own operators rather than
a rule the draft text imposes on implementers. And they were load-bearing once already:
the proposal's table states, for three of its rows, that the refusal names the offending
entry, and until 2026-09-12 nothing asserted it, so a change that stopped interpolating
the entry would have left every vector green and the table's third column false.

Nothing in this file may be read as a conformance requirement. A foreign implementation
that fails every assertion here and passes the fixtures module is conformant to #116 as
this set encodes it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentrust_trace import verify_record
from agentrust_trace.validate import profiles_with_schema

FIXTURE_DIR = Path(__file__).parent.parent / "examples" / "verifier-compatibility"
FIXTURE_PATHS = sorted(FIXTURE_DIR.glob("*.json"))
# Each informative label maps to a fragment this implementation emits. Matched against a
# fragment rather than the whole message so the prose stays free to change.
FAILURE_MARKERS = {
    "profile_not_accepted": "not in this verifier's accepted set",
    "profile_absent": "no 'eat_profile'",
    "no_accepted_profiles": "accepted_profiles is empty",
    "unschemaed_profile_in_accepted_set": "which this build carries no schema for",
}

# Which labels are a complaint about a specific member of the declared set, and how to
# find the member the message has to name. A rule name is not an entry: a verifier that
# reported `unschemaed_profile_in_accepted_set` without saying which profile it meant
# would leave the operator to diff their own configuration.
NAMES_AN_ENTRY = {
    "unschemaed_profile_in_accepted_set":
        lambda accepted: [p for p in accepted if p not in profiles_with_schema()],
}
"""One label, carried by 04 and 09.

It was two until 2026-09-15. `superseded_profile_in_accepted_set` was the other, and the
vector that carried it, 08, left for the cutover's own coverage, where the message is
pinned by `test_verify_record_rejects_v0_1_in_the_accepted_set`. A lambda for a label no
vector uses would be a row of this table that never runs, which is the shape of claim
this file exists to keep honest."""


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


REFUSING = [p for p in FIXTURE_PATHS if _load(p)["expected"]["outcome"] == "refused"]


@pytest.mark.parametrize("fixture_path", REFUSING, ids=lambda path: path.stem)
def test_this_verifier_says_which_rule_refused(fixture_path: Path) -> None:
    fixture = _load(fixture_path)
    expected = fixture["expected"]
    with pytest.raises(ValueError) as excinfo:
        verify_record(
            fixture["record"],
            fixture["trusted_key"],
            max_age_seconds=None,
            accepted_profiles=fixture["verifier"]["accepted_profiles"],
        )
    marker = FAILURE_MARKERS[expected["failure"]]
    assert marker in str(excinfo.value), (
        f"{fixture_path.name}: this implementation's message no longer identifies "
        f"{expected['failure']!r}. Got: {excinfo.value}")


@pytest.mark.parametrize("fixture_path", REFUSING, ids=lambda path: path.stem)
def test_a_complaint_about_the_declared_set_names_the_member(fixture_path: Path) -> None:
    """For a complaint about the declared set, the message must name the member."""
    fixture = _load(fixture_path)
    find = NAMES_AN_ENTRY.get(fixture["expected"]["failure"])
    if find is None:
        pytest.skip("this vector's refusal is not a complaint about a set member")
    accepted = fixture["verifier"]["accepted_profiles"]
    offending = find(accepted)
    assert offending, (
        f"{fixture_path.name}: no member of {accepted} is the kind of entry that label "
        "describes, so this vector cannot be checking what it says")
    with pytest.raises(ValueError) as excinfo:
        verify_record(
            fixture["record"],
            fixture["trusted_key"],
            max_age_seconds=None,
            accepted_profiles=accepted,
        )
    missing = [p for p in offending if p not in str(excinfo.value)]
    assert not missing, (
        f"{fixture_path.name}: the refusal does not name {missing}. The label alone "
        "tells an operator which rule fired and not which entry of their declared set "
        "tripped it.")


def test_every_label_the_set_uses_has_a_marker() -> None:
    """A vector may not introduce an informative label nothing here can recognise.

    Positive control on the table above: a regeneration that renames a label would
    otherwise leave these tests passing on the labels they still know and silent about
    the new one.
    """
    used = {_load(p)["expected"]["failure"] for p in REFUSING}
    assert used, "positive control: no refusal vectors found"
    unknown = used - set(FAILURE_MARKERS)
    assert not unknown, f"the set uses labels this file cannot recognise: {sorted(unknown)}"
    # And the other direction, which is the one that went quiet: a marker for a label no
    # vector carries is a row that never runs. Two of them sat here for as long as it
    # took a reader to notice, after the vectors that used them were retired.
    unused = set(FAILURE_MARKERS) - used
    assert not unused, (
        f"this file carries markers no vector uses: {sorted(unused)}. Either a vector was "
        "retired and its row left behind, or a label was renamed on one side only.")

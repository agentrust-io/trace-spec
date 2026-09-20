"""Portable verifier-compatibility vectors (agentrust-io/trace-spec#116).

These fixtures encode behaviour that is **proposed and under review**, not accepted
normative text.

Unlike the vectors in `test_sign.py`, nothing here is written against this library's
API: each fixture states a signed record, the profile set a verifier declares, and
the outcome any conformant verifier must produce. This module is the adapter that
runs them against `agentrust_trace`; another implementation writes its own adapter
and runs the same JSON.

`expected.failure` is **informative**. It names the rule this set believes refused the
record, and no portable assertion is made on it: a verifier that applies every rule
agreed here and reports one generic refusal for all of them conforms, and
`test_a_generic_refusal_passes_this_set` is the control that proves this module lets it.
The draft text for #116 says a verifier SHOULD report refusal-for-an-unimplemented-profile
distinguishably from a verification failure, which is coarser than a rule name and is a
SHOULD, so asserting the label here would have been this set asking more of a foreign
implementation than the text it encodes. The label is kept because it tells a reader of
the JSON what each vector is for, and because this library's own diagnostics are worth
pinning: that is `tests/test_verifier_compatibility_diagnostics.py`, which is about this
implementation's messages and is not part of the portable contract.

One test in this module does read `expected.failure`, and it is worth saying why before a
reader grepping for the field finds it and concludes the contract is looser than it says.
`test_the_precondition_check_fires_and_covers_every_vector_that_needs_one` uses the label
to derive which fixtures must declare a premise. That is an assertion about the fixtures,
not about a verifier: no run of any implementation can change its outcome.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from agentrust_trace import verify_record
from agentrust_trace.sign import TRACE_PROFILE_V0_2
from agentrust_trace.validate import profiles_with_schema

FIXTURE_DIR = Path(__file__).parent.parent / "examples" / "verifier-compatibility"
PROFILE = "trace.verifier_compatibility.proposal.v0"

V0_1 = "tag:agentrust.io,2026:trace-v0.1"

RECORD_SCHEMA_PROFILE = TRACE_PROFILE_V0_2
"""The one profile a record may carry and still reach the signature check.

`verify_record` validates every record against the v0.2 schema, which pins
`eat_profile` with a const, so this is a property of the record schema rather than of
the accepted set. Named separately from the set ceiling because the two coincide only
by accident of there being one usable profile today.
"""

def _check_preconditions(fixture_path: Path, fixture: dict[str, Any]) -> None:
    """A vector whose expectation depends on a fact about the reader states that fact.

    Every other vector in this set is self-contained: the record and the declared set
    are both in the file, and the conformant outcome follows from them. Vectors 04 and
    09 are not. They expect `unschemaed_profile_in_accepted_set`, which is a refusal
    because the *verifier* carries no schema for the profile the declared set names --
    a property of whoever is running the vector.

    `tag:example.com,2025:trace-v0.0` is uncheckable for this build and need not be for
    another. Measured, packaging a schema whose `eat_profile` const is that identifier:
    both vectors fail with pytest's `DID NOT RAISE ValueError`, which reads as this
    verifier being non-conformant when what happened is that it grew a capability and
    the vector's premise lapsed. The README offers this set to other implementations,
    so the diagnosis a foreign adapter gets is the deliverable, not a detail.

    Failing rather than skipping, because a lapsed premise means the rule stopped being
    tested here and a set that quietly stops testing a rule still reports green.
    """
    premise = fixture.get("preconditions")
    if premise is None:
        return
    checkable = [p for p in premise["unschemaed_for_the_verifier_under_test"]
                 if p in profiles_with_schema()]
    assert not checkable, (
        f"{fixture_path.name}: this vector's premise no longer holds. It needs "
        f"{premise['unschemaed_for_the_verifier_under_test']} to be profiles this "
        f"verifier carries no schema for, and it now carries one for {checkable}. "
        "This is not a conformance failure: the rule is that a verifier refuses a "
        "declared set naming a profile whose shape it cannot check, and that rule is "
        "untouched. Substitute an identifier this build cannot check and regenerate, "
        "or the rule is no longer covered by this set.")


FIXTURE_PATHS = sorted(FIXTURE_DIR.glob("*.json"))


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vector_set_is_complete() -> None:
    assert [path.name for path in FIXTURE_PATHS] == [
        "01-known-version-verified.json",
        "02-unknown-version-refused.json",
        "04-unschemaed-profile-refused.json",
        "05-downgrade-silent-is-impossible.json",
        "06-empty-accepted-set-refused.json",
        "07-profile-absent-refused.json",
        "09-unschemaed-profile-first-in-set-refused.json",
        "11-empty-profile-string-refused.json",
    ]


def _verify(record, key, accepted):
    """The verifier under test, as a foreign adapter would wrap its own."""
    return verify_record(record, key, max_age_seconds=None, accepted_profiles=accepted)


def _verify_refusing_generically(record, key, accepted):
    """Every rule of the reference applied, every refusal under one label.

    The control for the portable contract. This verifier is conformant: it reaches the
    same verdict on every vector and declines only to say which rule it reached it by.
    A set that this cannot pass is asking for a diagnostic the draft text does not
    require, which is the finding the review resolved by making `expected.failure`
    informative.
    """
    try:
        return _verify(record, key, accepted)
    except ValueError:
        raise ValueError("refused") from None


def _check_vector(fixture_path: Path, fixture: dict[str, Any], verify) -> None:
    """The portable expectation: the verdict, and every key the statement names.

    The refusal's stated cause is deliberately not compared. `expected.failure` is
    informative; see this module's docstring.
    """
    verifier = fixture["verifier"]
    expected = fixture["expected"]
    # Freshness is disabled by every vector: version skew is the property under test,
    # and a fixed iat would otherwise make the set expire.
    assert verifier["check_freshness"] is False

    if expected["outcome"] == "refused":
        with pytest.raises(ValueError):
            verify(fixture["record"], fixture["trusted_key"], verifier["accepted_profiles"])
        return

    statement = verify(
        fixture["record"], fixture["trusted_key"], verifier["accepted_profiles"])
    want = expected["statement"]
    assert statement.profile == want["profile"]
    assert list(statement.accepted_profiles) == want["accepted_profiles"]

    # Every key the vector names is compared, and nothing is derived here. A key the
    # adapter computes from the statement it was just handed is compared against
    # itself: that is how `downgraded` sat in this set asserting nothing until
    # 2026-09-12. If a future key cannot be read off the result, it does not belong
    # in the expectation.
    assert set(want) == {"profile", "accepted_profiles"}, (
        f"{fixture_path.name}: the statement expectation names {sorted(want)}; this "
        "adapter reads two keys and would silently ignore the rest")


@pytest.mark.parametrize("fixture_path", FIXTURE_PATHS, ids=lambda path: path.stem)
def test_verifier_compatibility_vector(fixture_path: Path) -> None:
    fixture = _load(fixture_path)

    assert fixture["profile"] == PROFILE
    assert fixture["proposal"]["issue"] == "agentrust-io/trace-spec#116"
    assert "not accepted normative text" in fixture["proposal"]["status"]

    _check_preconditions(fixture_path, fixture)
    _check_vector(fixture_path, fixture, _verify)


@pytest.mark.parametrize("fixture_path", FIXTURE_PATHS, ids=lambda path: path.stem)
def test_a_generic_refusal_passes_this_set(fixture_path: Path) -> None:
    """A verifier that applies every agreed rule and names none of them conforms.

    Positive control on the portable contract rather than on a vector. It runs the same
    expectations through `_verify_refusing_generically`, which erases the reason and
    keeps the verdict, and every vector must still pass. Before the review that asked
    for this, the adapter asserted a rule name out of `expected.failure`, and every one of
    the seven refusal vectors refused this verifier: the set failed a conformant
    implementation, and said so nowhere a foreign adapter would see. Measured by putting
    the assertion back, not recalled.

    This control fails the day an assertion on the refusal's cause comes back into
    `_check_vector`, which is the only thing that would make the set stricter than its
    text again.
    """
    fixture = _load(fixture_path)
    _check_preconditions(fixture_path, fixture)
    _check_vector(fixture_path, fixture, _verify_refusing_generically)


def test_every_fixture_signature_is_genuine() -> None:
    """No vector may pass or fail because its signature was malformed.

    All eight records are correctly signed. If one were not, a "refused" expectation
    could be satisfied by the signature check rather than by the profile rule, and the
    vector would silently stop testing what it claims to test.
    """
    for path in FIXTURE_PATHS:
        fixture = _load(path)
        record = fixture["record"]
        profile = record.get("eat_profile")
        # Only a record carrying the profile this build's *record* schema accepts can
        # reach the signature check inside verify_record. `validate_json` runs the v0.2
        # schema unconditionally and that schema pins `eat_profile` with a const, so
        # every other record is refused before the signature is read.
        #
        # This read `profile not in profiles_with_schema()` until 2026-09-12, which is
        # a different set that happens to exclude the same records today. Packaging a
        # second usable profile schema separates them: measured, a schema for
        # `tag:example.com,2025:trace-v0.0` stopped vector 05's record being skipped
        # and this test failed on the v0.2 schema's const, reporting a bad signature
        # for a record whose signature is fine.
        #
        # The skipped records are not re-verified anywhere in this repository. An
        # earlier revision of this comment sent the reader to
        # test_fixture_signatures_independent.py, which has never existed here; the
        # README says what is and is not covered instead of promising a file.
        if profile != RECORD_SCHEMA_PROFILE:
            continue
        # Accept whatever this record carries, so only the signature can fail here.
        verify_record(
            record,
            fixture["trusted_key"],
            max_age_seconds=None,
            accepted_profiles=[profile],
        )


@pytest.mark.parametrize(
    "unschemaed",
    [
        "tag:example.test,2026:made-up-v9",
        "tag:agentrust-io.com,2027:trace-v0.3",
        "urn:not-a-profile",
    ],
)
def test_the_ceiling_refuses_any_profile_no_schema_covers(unschemaed: str) -> None:
    """The ceiling is enforced for every profile outside it, not only for the ones
    a vector happens to name.

    `profiles_with_schema()` is the ceiling on any accepted set: a verifier can only
    honestly accept a profile whose shape it can check. Two things guard that today
    and neither guards this. `test_sign.py` pins the ceiling's *contents*, which a
    widening at the call site does not touch; vector 04 proves one specific
    unschemaed profile is refused, which a widening that admits a *different* one
    leaves green.

    Measured: adding a single fictional identifier to the set the enforcement
    consults, and changing nothing else, passed the whole suite. This is the test that
    fails on it. Synthetic identifiers rather than vector ones, so it cannot be
    satisfied by whatever the corpus currently contains.
    """
    from agentrust_trace.validate import profiles_with_schema

    assert unschemaed not in profiles_with_schema(), (
        f"{unschemaed} is now a packaged profile, so it is the wrong probe for this"
    )

    fixture = _load(FIXTURE_DIR / "01-known-version-verified.json")
    with pytest.raises(ValueError, match="carries no schema|carry no schema|can check"):
        verify_record(
            fixture["record"],
            fixture["trusted_key"],
            max_age_seconds=None,
            accepted_profiles=[unschemaed],
        )


def test_the_precondition_check_fires_and_covers_every_vector_that_needs_one() -> None:
    """Positive control on `_check_preconditions`, and on which vectors declare one.

    Two ways this goes quiet. The check never fires, and a lapsed premise is reported
    as a conformance failure again. Or a vector that needs a premise stops declaring
    one, which a regeneration can do silently because every other assertion here still
    passes.

    The second list is derived, not written down: a vector needs a premise exactly when
    its expected failure is the one whose truth depends on the reader's schema
    inventory. `unschemaed_profile_in_accepted_set` is that failure and it is the only
    one, because every other label in this set is decided by the record and the
    declared set, both of which are in the file.
    """
    needs = {path.name for path in FIXTURE_PATHS
             if _load(path)["expected"].get("failure") == "unschemaed_profile_in_accepted_set"}
    declares = {path.name for path in FIXTURE_PATHS if "preconditions" in _load(path)}
    assert needs, "positive control: no vector expects the reader-dependent failure"
    assert declares == needs, (
        f"vectors expecting 'unschemaed_profile_in_accepted_set' are {sorted(needs)} and "
        f"vectors declaring a premise are {sorted(declares)}. A vector whose expectation "
        "depends on what the reader can check has to say so.")

    lapsed = {
        "preconditions": {
            # A profile this build certainly carries a schema for, standing in for the
            # world where the vector's own identifier becomes checkable.
            "unschemaed_for_the_verifier_under_test": [TRACE_PROFILE_V0_2],
            "why": "control",
        }
    }
    with pytest.raises(AssertionError, match="premise no longer holds"):
        _check_preconditions(Path("control.json"), lapsed)


ROOT = FIXTURE_DIR.parent.parent
SURFACE = (
    FIXTURE_DIR / "README.md",
    FIXTURE_DIR / "gen_vectors.py",
    ROOT / "tests" / "test_verifier_compatibility_fixtures.py",
    ROOT / "tests" / "test_verifier_compatibility_separation.py",
    ROOT / "tests" / "test_verifier_compatibility_diagnostics.py",
)


def _cited(pattern: str) -> set[str]:
    found: set[str] = set()
    for path in SURFACE:
        text = path.read_text(encoding="utf-8")
        # URLs carry paths that belong to other repositories, so they go first.
        text = re.sub(r"https?://\S+", " ", text)
        found |= set(re.findall(pattern, text))
    return found


def test_every_name_this_set_cites_resolves() -> None:
    """Nothing in the set's own surface may point at something that is not there.

    Three defects of this shape shipped inside one change: the README sent an adapter
    author to a constant that had moved to another module, two places named a test file
    that has never existed here, and the generator pointed at a vector the same change
    had deleted. Each was found by a reader, and each was then fixed by a guard aimed at
    that one shape. This is the general form of those three, so the next one does not
    need its own.

    Deliberately not a list of names to keep up to date: the citations are recovered from
    the files, which is what makes it cover a citation added tomorrow.
    """
    # The lookbehind matters: a repository name ending in one of these words, followed
    # by a path, otherwise yields a match starting mid-word. The first thing this test
    # caught was exactly that, in a comment here that spelled the bad match out; the
    # comment is worded rather than quoted now, because a guard whose explanation trips
    # it teaches the reader to weaken the guard.
    paths = _cited(r"(?<![-/\w])((?:tests|examples|src|docs|schema|spec)/[A-Za-z0-9_./-]+)")
    assert paths, "positive control: no paths cited, so this test is measuring nothing"
    missing = sorted(p for p in paths if not (ROOT / p).exists())
    assert not missing, f"the set cites paths that do not exist: {missing}"

    names = _cited(r"`(test_[a-z0-9_]+)`")
    assert names, "positive control: no test names cited"
    tree = "".join(p.read_text(encoding="utf-8")
                   for p in sorted((ROOT / "tests").rglob("*.py")))
    tree += "".join(p.read_text(encoding="utf-8")
                    for p in sorted((ROOT / "examples").rglob("*.py")))
    undefined = sorted(n for n in names if f"def {n}" not in tree)
    assert not undefined, f"the set cites tests that are not defined: {undefined}"

    constants = _cited(r"`([A-Z][A-Z_]{3,})`")
    assert constants, "positive control: no constant names cited"
    everywhere = tree + "".join(
        p.read_text(encoding="utf-8") for p in sorted((ROOT / "src").rglob("*.py")))
    unknown = sorted(c for c in constants if f"{c} =" not in everywhere
                     and f"{c}:" not in everywhere and f"{c}[" not in everywhere)
    assert not unknown, f"the set cites names that are defined nowhere: {unknown}"


def test_the_published_artifacts_name_no_vector_that_is_not_here() -> None:
    """The README and the generator are offered to other implementations, so a pointer
    in either to a vector that is not in this directory is a broken reference in somebody
    else's hands.

    Retiring a vector leaves these behind: `gen_vectors.py` carried "(see vector 08)" for
    the length of the change that deleted 08, and the README sent adapter authors to a
    constant that had moved out of the adapter. History belongs in the test modules,
    which are ours to read; these two files describe the set as it stands.
    """
    present = {path.stem.split("-")[0] for path in FIXTURE_PATHS}
    assert present, "positive control: no fixtures found"
    for name in ("README.md", "gen_vectors.py"):
        text = (FIXTURE_DIR / name).read_text(encoding="utf-8")
        named = set(re.findall(r"vector (\d\d)\b", text))
        named |= set(re.findall(r"\b(\d\d)-[a-z-]+\.json", text))
        missing = sorted(named - present)
        assert not missing, (
            f"{name} names vector(s) {missing}, which are not in this directory. A reader "
            "of the published set follows that pointer and finds nothing.")


def test_the_readme_states_the_real_fixture_count() -> None:
    """The counts in the README are computed here rather than trusted there.

    The proposal document's count was the one this test used to read, and it said "seven
    fixtures" until 2026-09-12, wrong since the set grew past seven, because nothing read
    it. That document has left this branch; the README's two counts, the table and the
    "self-contained" sentence, were read by nothing at all, measured by mutating one and
    watching every test stay green. This is the test that reads them.
    """
    words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
             7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}
    readme = (FIXTURE_DIR / "README.md").read_text(encoding="utf-8")
    count = len(FIXTURE_PATHS)
    rows = [line for line in readme.splitlines()
            if line.startswith("| `") and ".json`" in line]
    assert len(rows) == count, (
        f"README table lists {len(rows)} fixtures, the directory holds {count}")
    with_premise = sum("preconditions" in _load(p) for p in FIXTURE_PATHS)
    self_contained = count - with_premise
    assert count in words and self_contained in words, "write the numeral out"
    claim = f"{words[self_contained].capitalize()} of the {words[count]} are self-contained"
    assert claim in readme, (
        f"README does not state the current counts; the sentence should read {claim!r}.")

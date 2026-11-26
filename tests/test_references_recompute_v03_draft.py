"""`references` entries validated by recomputation, in the v0.3 draft schema (#321).

Spec section 3.1.2, "Entries validated by recomputation". An entry carrying
`validation: "recompute"` has no obliged party, so `resolver` and `retention` must be
absent; an entry without it is checked by resolution and still needs a `resolver`.
The v0.2 schema rejects the member outright, which `test_references_block.py` checks
from its side. Both schemas are run over the same table here so the version gate is
visible in one place: what the draft accepts for the new field, v0.2 refuses.

What the schema cannot express are the rules that bind a verifier: that the
recomputation must bind the entry to this record, and that "could not recompute" and
"recomputed and disagreed" are different outcomes. The reference library does not
read `references[]` at all (`sign.py`, section 3.1.2 rule 3), so those stay
conformance-suite rules, as rules 3 and 4 already are.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
V03_PROFILE = "tag:agentrust-io.com,2026:trace-v0.3"

RECOMPUTE = {"rel": "position-commitment", "id": "sha256:" + "c" * 64, "validation": "recompute"}
RESOLVED = {"rel": "behavior-trace", "id": "trace-7", "resolver": "https://trace.example.org"}


def _schema(name: str) -> dict:
    return json.loads((REPO_ROOT / "schema" / name).read_text(encoding="utf-8"))


def _record(references: list, *, v03: bool) -> dict:
    record = json.loads((REPO_ROOT / "examples" / "amd-sev-snp.json").read_text(encoding="utf-8"))
    record["references"] = copy.deepcopy(references)
    if v03:
        record["eat_profile"] = V03_PROFILE
    return record


# (label, references, accepted by the v0.3 draft)
CASES: list[tuple[str, list, bool]] = [
    ("recompute entry, no resolver", [RECOMPUTE], True),
    ("recompute entry with a digest", [{**RECOMPUTE, "digest": "sha256:" + "d" * 64}], True),
    ("recompute entry beside a resolved one", [RECOMPUTE, RESOLVED], True),
    ("recompute on an unregistered rel", [{**RECOMPUTE, "rel": "slot-claim"}], True),
    ("resolved entry, unchanged from v0.2", [RESOLVED], True),
    # Rule 2 of the proposal: no obliged party, so naming one states an undertaking
    # nobody made.
    ("recompute entry naming a resolver", [{**RECOMPUTE, "resolver": "https://x.example"}], False),
    ("recompute entry with retention", [{**RECOMPUTE, "retention": "P30D"}], False),
    # Absent means resolution, so rule 4 still holds for an entry without the field.
    ("no validation and no resolver", [{"rel": "behavior-trace", "id": "trace-7"}], False),
    ("unknown validation value", [{**RECOMPUTE, "validation": "resolve"}], False),
    ("empty validation value", [{**RECOMPUTE, "validation": ""}], False),
    (
        "recompute entry without id",
        [{"rel": "position-commitment", "validation": "recompute"}],
        False,
    ),
]


@pytest.mark.parametrize(
    ("references", "accepted"), [(r, a) for _, r, a in CASES], ids=[label for label, _, _ in CASES]
)
def test_the_v03_draft_schema(references: list, accepted: bool) -> None:
    validator = jsonschema.Draft202012Validator(_schema("trace-claim-v0.3-draft.json"))
    errors = list(validator.iter_errors(_record(references, v03=True)))
    assert (not errors) is accepted, [e.message for e in errors]


@pytest.mark.parametrize(
    "references",
    [r for _, r, a in CASES if a and "validation" in json.dumps(r)],
    ids=[label for label, r, a in CASES if a and "validation" in json.dumps(r)],
)
def test_v02_rejects_every_shape_the_draft_newly_accepts(references: list) -> None:
    """The version gate, from the draft's side: no accepted recompute shape is v0.2-valid."""
    validator = jsonschema.Draft202012Validator(_schema("trace-claim.json"))
    assert list(validator.iter_errors(_record(references, v03=False)))


def test_a_resolved_entry_is_accepted_by_both() -> None:
    """Existing records keep validating: the draft does not narrow what v0.2 accepts."""
    for name, v03 in (("trace-claim.json", False), ("trace-claim-v0.3-draft.json", True)):
        validator = jsonschema.Draft202012Validator(_schema(name))
        assert not list(validator.iter_errors(_record([RESOLVED], v03=v03))), name


def test_v02_rejects_the_member_itself_not_only_the_missing_resolver() -> None:
    """Every recompute shape also lacks a resolver, which v0.2 requires, so the test
    above would pass even if v0.2 accepted `validation`. This entry keeps its
    resolver, so the member alone is what v0.2 refuses."""
    validator = jsonschema.Draft202012Validator(_schema("trace-claim.json"))
    errors = list(
        validator.iter_errors(_record([{**RESOLVED, "validation": "recompute"}], v03=False))
    )
    assert any("validation" in e.message for e in errors), [e.message for e in errors]

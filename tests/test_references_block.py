"""The `references` block: spec §3.1.2, merged in #198.

The spec text landed without the schema, so nothing checked that a record
carrying the block is valid. It was not: `additionalProperties: false` at the
top level rejected `references` outright, and `TrustRecord` is `extra="forbid"`,
so a record the specification permits was rejected by both of the artifacts a
producer would test against. That is the failure mode this file exists to keep
shut, from both directions: a valid entry must be accepted, and each way of
getting one wrong must be rejected for its own reason.

The schema and the model are checked against the *same* case table rather than
separately. Two artifacts that each pass their own tests can still disagree, and
a producer that validates against one and is consumed by the other only finds
out in production. `test_validate.py` makes the same argument for the packaged
copy of the schema.

Of the four MUST/MUST NOT rules in §3.1.2, two are expressible here. Rule 1
(`references` MUST NOT affect `runtime.platform`) and rule 2 (the signature MUST
cover `references`) are properties of a record and are asserted below. Rules 3
and 4 are verifier behaviour: a verifier MUST NOT reject on an unresolvable
entry, and MUST NOT treat a resolved one as evidence, and a schema cannot say
either; they belong to the conformance suite.
"""

from __future__ import annotations

import copy
import json
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from agentrust_trace import (
    TrustRecord,
    generate_key,
    iter_errors,
    key_to_jwk,
    sign_record,
    verify_record,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

# All fields populated, so a case that drops or corrupts one is isolating that
# field and not also tripping a missing-required error somewhere else.
FULL_ENTRY = {
    "rel": "authorized-intent",
    "id": "req-9f2c41",
    "resolver": "https://approvals.example.com",
    "retention": "P30D",
    "digest": "sha256:" + "a" * 64,
}

MINIMAL_ENTRY = {"rel": "behavior-trace", "id": "run-77", "resolver": "obs.example.com"}


def _entry(**overrides) -> dict:
    return {**FULL_ENTRY, **overrides}


def _example() -> dict:
    """intel-tdx.json: a hardware record with no `origin` and no `references`."""
    return json.loads((EXAMPLES / "intel-tdx.json").read_text(encoding="utf-8"))


def _with(references) -> dict:
    record = _example()
    record["references"] = references
    return record


# (label, references value, accepted?)
CASES: list[tuple[str, object, bool]] = [
    ("full entry", [_entry()], True),
    ("required fields only", [MINIMAL_ENTRY], True),
    ("two entries", [_entry(), MINIMAL_ENTRY], True),
    ("rel authorized-intent", [_entry(rel="authorized-intent")], True),
    ("rel approval-outcome", [_entry(rel="approval-outcome")], True),
    ("rel behavior-trace", [_entry(rel="behavior-trace")], True),
    ("sha384 digest", [_entry(digest="sha384:" + "b" * 96)], True),
    # rel is a registry rather than a closed set (spec 3.1.2, unlike 3.1.1 on kind),
    # so a value this schema has never heard of is accepted rather than rejected.
    ("unregistered rel", [_entry(rel="policy-decision")], True),
    ("rel absent", [{"id": "x", "resolver": "y"}], False),
    ("id absent", [{"rel": "behavior-trace", "resolver": "y"}], False),
    ("resolver absent", [{"rel": "behavior-trace", "id": "x"}], False),
    # An empty resolver is the self-asserted entry rule 4 tells a producer to
    # omit; an empty id is a pointer that points nowhere. Both look populated.
    # `rel` is open but not absent. An empty string is not a future registered
    # relation, it carries no relation at all, so it is rejected the same way an
    # empty `id` or `resolver` is. Checked against both artifacts by this table,
    # which is what keeps minLength and min_length from drifting apart.
    ("empty rel", [_entry(rel="")], False),
    ("empty resolver", [_entry(resolver="")], False),
    ("empty id", [_entry(id="")], False),
    ("malformed digest", [_entry(digest="sha256:zz")], False),
    ("uppercase digest hex", [_entry(digest="sha256:" + "A" * 64)], False),
    ("unknown member in entry", [_entry(note="human comment")], False),
    # Rule 4 tells a producer to omit the entry, not the block, and nothing in 3.1.2
    # says the array must be non-empty. The schema does not get to assert what the
    # normative text does not, which is this PR's own argument pointed the other way.
    ("empty array", [], True),
    ("object instead of array", _entry(), False),
    ("string instead of entry", ["req-9f2c41"], False),
]

# `retention` is an ISO 8601 duration. The rejected column is the point: a
# pattern loose enough to accept "P" or "P1H" is not checking anything.
CASES += [(f"retention {v}", [_entry(retention=v)], True) for v in (
    "P30D", "P1Y", "P1Y6M", "P1Y6M15D", "P1Y15D", "P7D", "P2W", "P10Y",
    "PT12H", "PT30M", "PT1H30M15S", "P1DT12H",
)]
CASES += [(f"retention {v!r}", [_entry(retention=v)], False) for v in (
    "P",        # no components at all
    "PT",       # a time designator with no time
    "P1DT",     # same, after a valid date part
    "30D",      # no duration designator
    "P1H",      # hours outside the time part
    "P1D1Y",    # components out of order
    "P1Y2W",    # the week form does not combine
    "P2WT12H",  # nor with a time part
    "P-1D",
    "P1.5D",
    "p30d",
    "PT12h",
    "P1D ",
    "",
)]

IDS = [label for label, _, _ in CASES]
PARAMS = [(references, accepted) for _, references, accepted in CASES]


@pytest.mark.parametrize(("references", "accepted"), PARAMS, ids=IDS)
def test_json_schema_agrees_with_the_case(references, accepted) -> None:
    errors = iter_errors(_with(references))
    assert (not errors) == accepted, [e.message for e in errors[:2]]
    if not accepted:
        # Attributable, or this table would still pass if the base example broke
        # and every case failed for a reason that has nothing to do with the block.
        assert any(
            e.absolute_path and e.absolute_path[0] == "references" for e in errors
        ), f"rejected, but not because of references: {[e.message for e in errors[:2]]}"


@pytest.mark.parametrize(("references", "accepted"), PARAMS, ids=IDS)
def test_the_model_agrees_with_the_case(references, accepted) -> None:
    record = _with(references)
    try:
        TrustRecord.model_validate(record)
    except ValidationError as exc:
        assert not accepted, "the model rejects a record the specification permits"
        assert any(
            e["loc"] and e["loc"][0] == "references" for e in exc.errors()
        ), f"rejected, but not because of references: {exc.errors()[:2]}"
    else:
        assert accepted, "the model accepts a record the specification does not permit"


def test_the_unmodified_example_is_a_clean_baseline() -> None:
    """Every case above is this record plus a `references` block. If it were not
    valid to begin with, the rejection half of the table would prove nothing."""
    record = _example()
    assert iter_errors(record) == []
    TrustRecord.model_validate(record)


def test_the_block_stays_optional() -> None:
    """Every published example predates §3.1.2 and must keep validating."""
    for name in ("intel-tdx.json", "amd-sev-snp.json", "nvidia-h100.json"):
        record = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
        assert "references" not in record
        assert iter_errors(record) == []


def test_references_does_not_touch_the_platform() -> None:
    """Rule 1. `references` is not `origin` and must not behave like it.

    The block exists because a record that needed to name something external had
    to use `origin` and take `software-only` with it. A hardware record that adds
    `references` and nothing else is still the hardware record it was.
    """
    record = _with([_entry()])
    assert record["runtime"]["platform"] == "intel-tdx"
    assert "origin" not in record
    assert iter_errors(record) == []
    TrustRecord.model_validate(record)


def test_origin_still_constrains_the_platform_alongside_references() -> None:
    """The converse of rule 1: adding `references` must not relax `origin`.

    Without this, "references does not lower assurance" could be satisfied by a
    schema that had stopped enforcing anything on that record at all.
    """
    record = _with([_entry()])
    record["origin"] = {"kind": "log-import", "producer": "siem/1.0"}
    assert record["runtime"]["platform"] == "intel-tdx"
    assert iter_errors(record), "a non-self origin on a hardware platform must still fail"


def _signed_with_references() -> tuple[dict, object]:
    key = generate_key()
    record = _example()
    record.pop("signature", None)
    record["cnf"] = {"jwk": key_to_jwk(key)}
    record["iat"] = int(time.time())  # verify_record enforces freshness
    record["references"] = [_entry(), MINIMAL_ENTRY]
    return sign_record(record, key), key.public_key()


def test_the_signature_covers_references() -> None:
    signed, public_key = _signed_with_references()
    verify_record(signed, public_key)  # must not raise


@pytest.mark.parametrize(
    ("label", "tamper"),
    [
        ("rel", lambda r: r["references"][0].update(rel="behavior-trace")),
        ("id", lambda r: r["references"][0].update(id="req-000000")),
        ("resolver", lambda r: r["references"][0].update(resolver="https://evil.example")),
        ("retention", lambda r: r["references"][0].update(retention="P1D")),
        ("digest", lambda r: r["references"][0].update(digest="sha256:" + "c" * 64)),
        ("entry appended", lambda r: r["references"].append(MINIMAL_ENTRY)),
        ("entry removed", lambda r: r["references"].pop()),
        ("order swapped", lambda r: r["references"].reverse()),
        ("block removed", lambda r: r.pop("references")),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_tampering_with_references_breaks_the_signature(label, tamper) -> None:
    """Rule 2. Not automatic: it holds because canonicalisation covers the whole
    record minus `signature`, and a block excluded from that would verify after
    being rewritten in transit."""
    signed, public_key = _signed_with_references()
    tampered = copy.deepcopy(signed)
    tamper(tampered)
    assert tampered != signed, f"the {label} case did not change the record"
    with pytest.raises(InvalidSignature):
        verify_record(tampered, public_key)


def test_the_model_and_the_schema_share_the_pattern_strings() -> None:
    """The two constraints on `retention` and `digest` are one decision written
    twice, and a case table only catches a divergence it happens to sample.

    Byte equality is the check that does not depend on sampling. It is possible
    here only because the pattern avoids look-around: pydantic's default regex
    engine has none, so a lookahead form would force the two files apart.
    """
    from agentrust_trace import SCHEMA
    from agentrust_trace.models import _DIGEST_RE, _DURATION_RE

    entry = SCHEMA["properties"]["references"]["items"]["properties"]
    assert entry["retention"]["pattern"] == _DURATION_RE
    assert entry["digest"]["pattern"] == _DIGEST_RE


def test_the_registered_rel_values_stay_documented_in_all_three_places() -> None:
    """`rel` is open, so nothing enforces the registry. Documentation is all there is.

    The enum is gone deliberately: section 3.1.2 calls these values a registry, and
    section 3.1.1 says of the neighbouring `kind` that it is closed *because* a verifier
    keys on it: a distinction the two sections draw on purpose. What replaces the
    enum as a guard is that the three values cannot quietly stop being written down.
    """
    from agentrust_trace import SCHEMA

    registered = ("authorized-intent", "approval-outcome", "behavior-trace")
    rel = SCHEMA["properties"]["references"]["items"]["properties"]["rel"]
    assert "enum" not in rel, (
        "rel is a registry; closing it makes every new relation a schema change too"
    )
    assert rel["minLength"] == 1, "open is not the same as absent; an empty rel names nothing"

    doc = (Path(__file__).resolve().parents[1] / "docs" / "schema.md").read_text(encoding="utf-8")
    section = doc.split("## `references`", 1)[1].split("\n## ", 1)[0]
    for value in registered:
        assert value in rel["description"], f"{value} is not named in the schema description"
        assert value in section, f"{value} is not named in docs/schema.md"


def test_the_block_does_not_require_a_non_empty_array() -> None:
    """`minItems` is gone: nothing in 3.1.2 says the array must be non-empty, and a schema
    asserting what the normative text does not is the drift this file exists to prevent."""
    from agentrust_trace import SCHEMA

    assert "minItems" not in SCHEMA["properties"]["references"]


def _doc_table() -> dict[str, bool]:
    """Field -> required, parsed from the `references` table in docs/schema.md.

    Same parser shape as ``test_build_provenance_depth_doc.py``, for the same
    reason: the doc is the copy a reader consults, and it can drift from the
    schema without anything failing, since both files stay individually valid.
    """
    doc = (Path(__file__).resolve().parents[1] / "docs" / "schema.md").read_text(encoding="utf-8")
    section = doc.split("## `references`", 1)[1].split("\n## ", 1)[0]
    fields = {}
    for line in section.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        fields[cells[0].strip("`")] = "yes" in cells[2].lower()
    assert fields, "no references field rows found in docs/schema.md"
    return fields


def test_the_doc_table_matches_the_schema() -> None:
    from agentrust_trace import SCHEMA

    entry = SCHEMA["properties"]["references"]["items"]
    documented = _doc_table()
    assert set(documented) == set(entry["properties"]), "docs/schema.md lists a different field set"
    for field, required in documented.items():
        assert required == (field in entry["required"]), f"docs/schema.md is wrong about {field}"


def test_the_doc_lists_references_as_an_optional_top_level_field() -> None:
    from agentrust_trace import SCHEMA

    doc = (Path(__file__).resolve().parents[1] / "docs" / "schema.md").read_text(encoding="utf-8")
    top = doc.split("## Top-level fields", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in top.splitlines() if line.startswith("| `references` |")]
    assert len(rows) == 1, "docs/schema.md does not list references exactly once"
    cells = [cell.strip() for cell in rows[0].strip("|").split("|")]
    assert cells[1] == "array", "the doc and the schema disagree on the type"
    assert "yes" not in cells[2].lower(), "references is optional"
    assert "references" not in SCHEMA["required"]

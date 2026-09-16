"""Every schema field and every enum value is documented, checked directly (#247).

Four surfaces state the rules and, until the precedence section lands, nothing
says which wins. This guard covers the narrower question that is mechanically
decidable: does the documentation mention every field and every enum value the
schema carries? A field the schema accepts and the docs never name is one a
producer meets only by reading JSON Schema, and a value the schema permits and
the docs omit is one a producer cannot know to use.

Two design choices, each made so the guard cannot go vacuous.

- **Coverage is asserted directly against the two hand-maintained surfaces.**
  Nothing here is generated from the schema. Generated prose cannot drift from
  the source it was generated from, so a drift test over it would exercise the
  generator and not the agreement between two surfaces. The counterfactual
  that matters is: remove a doc entry, or add a schema field, and this file
  goes red. ``test_the_guard_fails_when_*`` below runs both directions rather
  than asserting them.

- **A field counts as documented only as an inline-code token.** The token
  ``kid`` in prose or a table row is documentation; ``"kid": "..."`` inside a
  fenced example is an example. Matching prose words would let the enum value
  ``none`` be satisfied by the English word, and matching fenced JSON would let
  a copy-pasted record stand in for a description.

The corpus is every markdown file under ``docs/`` except ``docs/rfcs/``, which
disclaim being normative and are not where a producer is sent for a field's
meaning. ``docs/schema.md`` is additionally held on its own: it is the schema
reference, the page a producer is pointed at for the field table, and a field
documented only in a tutorial is missing from the place it is looked for.

What this file does not decide, and is not scoped to: whether the description
attached to a field agrees with the spec, or whether an example is correct.
Neither is mechanically decidable, and a guard that reaches past what it can
decide produces failures nobody can act on.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_SCHEMA_PATH = ROOT / "schema" / "trace-claim.json"
PACKAGED_SCHEMA_PATH = ROOT / "src" / "agentrust_trace" / "schema" / "trace-v0.2.json"
DOCS = ROOT / "docs"
SCHEMA_DOC = DOCS / "schema.md"

# Inline code spans only. A fenced block opens with three backticks on its own
# line and is stripped before this runs, so ``"kid": "..."`` in an example does
# not count and `kid` in a table row does.
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_FENCE = re.compile(r"^```.*?^```\s*$", re.MULTILINE | re.DOTALL)

# Keywords whose values describe the shape of the schema itself rather than a
# record. Walked for nested properties and enums; never counted as fields.
_SUBSCHEMA_KEYS = ("items", "additionalProperties", "if", "then", "else", "not")
_SUBSCHEMA_LISTS = ("allOf", "anyOf", "oneOf")

# (dotted path, name). A property declared twice on the same path, once under
# `properties` and once inside a conditional branch, is one field.
Field = tuple[str, str]
# (dotted path, value).
EnumValue = tuple[str, str]


def _walk(node: Any, path: str, fields: set[Field], enums: set[EnumValue]) -> None:
    if not isinstance(node, dict):
        return
    for name, sub in node.get("properties", {}).items():
        fields.add((path, name))
        _walk(sub, f"{path}.{name}" if path else name, fields, enums)
    for value in node.get("enum", []):
        if isinstance(value, str):
            enums.add((path, value))
    for key in _SUBSCHEMA_KEYS:
        sub = node.get(key)
        if isinstance(sub, dict):
            _walk(sub, f"{path}[]" if key == "items" else path, fields, enums)
    for key in _SUBSCHEMA_LISTS:
        for sub in node.get(key, []):
            _walk(sub, path, fields, enums)
    for name, sub in node.get("$defs", {}).items():
        _walk(sub, f"$defs.{name}", fields, enums)


def schema_fields_and_enums(schema: dict[str, Any]) -> tuple[set[Field], set[EnumValue]]:
    """Every property name and every enum value the schema carries, with the path it sits on."""
    fields: set[Field] = set()
    enums: set[EnumValue] = set()
    _walk(schema, "", fields, enums)
    return fields, enums


def documented_tokens(markdown: str) -> set[str]:
    """Inline-code tokens in *markdown*, fenced blocks excluded."""
    return set(_INLINE_CODE.findall(_FENCE.sub("", markdown)))


def undocumented(
    schema: dict[str, Any], corpus: str
) -> tuple[list[Field], list[EnumValue]]:
    """Fields and enum values in *schema* that *corpus* never names as an inline-code token."""
    fields, enums = schema_fields_and_enums(schema)
    tokens = documented_tokens(corpus)
    return (
        sorted(f for f in fields if f[1] not in tokens),
        sorted(e for e in enums if e[1] not in tokens),
    )


def _corpus_paths() -> list[Path]:
    return sorted(p for p in DOCS.rglob("*.md") if "rfcs" not in p.relative_to(DOCS).parts)


def _corpus() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in _corpus_paths())


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(CANONICAL_SCHEMA_PATH.read_text(encoding="utf-8"))
    return loaded


def _report(missing_fields: list[Field], missing_enums: list[EnumValue], where: str) -> str:
    lines = [f"the schema carries members that {where} never names as an inline-code token:"]
    lines += [f"  field  {path + '.' if path else ''}{name}" for path, name in missing_fields]
    lines += [f"  enum   {path}: {value}" for path, value in missing_enums]
    lines.append(
        "Document each one where a producer will look for it (a table row in "
        "docs/schema.md for a field, the field's row for an enum value), or remove it "
        "from the schema. An example in a fenced block does not count as documentation."
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- the guard


def test_the_two_schema_copies_are_the_same_bytes() -> None:
    """The guard reads one file and claims coverage for both, which is only true while
    they are identical. `test_validate.py` pins the same fact for the packaged copy; it
    is repeated here so this file's claim does not depend on another file's test."""
    assert CANONICAL_SCHEMA_PATH.read_bytes() == PACKAGED_SCHEMA_PATH.read_bytes()


def test_every_schema_field_and_enum_value_is_documented(schema: dict[str, Any]) -> None:
    missing_fields, missing_enums = undocumented(schema, _corpus())
    assert not missing_fields and not missing_enums, _report(
        missing_fields, missing_enums, "docs/ (rfcs excluded)"
    )


def test_the_schema_reference_page_names_every_field_and_enum_value(
    schema: dict[str, Any],
) -> None:
    """docs/schema.md is the schema reference. A field documented only in a tutorial
    passes the corpus-wide check and is still missing from the page a producer is sent
    to, so the reference page is held on its own."""
    missing_fields, missing_enums = undocumented(
        schema, SCHEMA_DOC.read_text(encoding="utf-8")
    )
    assert not missing_fields and not missing_enums, _report(
        missing_fields, missing_enums, "docs/schema.md"
    )


# --------------------------------------------------------------------- it can go red


def test_the_extraction_reaches_the_whole_schema(schema: dict[str, Any]) -> None:
    """Floors, so a walker that silently stopped descending could not pass. The counts
    are lower bounds rather than pins: a new field is expected to raise them, and a
    drop below either is a bug in the walker, not in the schema."""
    fields, enums = schema_fields_and_enums(schema)
    names = {name for _, name in fields}
    assert len(fields) >= 60, f"only {len(fields)} fields found"
    assert len(enums) >= 27, f"only {len(enums)} enum values found"
    # One member from each nesting shape the schema uses: a top-level field, a nested
    # object member, an array item member, a conditional branch, and a nested enum.
    assert ("", "subject") in fields
    assert ("cnf.jwk", "kid") in fields
    assert ("references[]", "rel") in fields
    assert ("policy.enforcement_mode", "declared") in enums
    assert ("appraisal", "provenance_depth_verified") in fields
    assert "canonicalizableValue" not in names, "$defs names are not fields"


def test_the_corpus_is_what_this_file_says_it_is() -> None:
    paths = _corpus_paths()
    assert SCHEMA_DOC in paths
    assert not any("rfcs" in p.parts for p in paths)
    assert any("tutorials" in p.parts for p in paths), "docs/ subdirectories are in scope"


def test_fenced_examples_do_not_count_as_documentation() -> None:
    """The reason the token rule exists. A record pasted into a code block names every
    field it carries, and if that counted, the guard would be satisfied by an example
    with no description attached."""
    markdown = (
        'Text.\n\n```json\n{"kid": "k1", "status": "none"}\n```\n\n'
        "Only `kty` is described.\n"
    )
    assert documented_tokens(markdown) == {"kty"}


def test_the_guard_fails_when_the_schema_gains_an_undocumented_field(
    schema: dict[str, Any],
) -> None:
    """Counterfactual, schema side: a field nobody documented is reported by name."""
    mutated = copy.deepcopy(schema)
    mutated["properties"]["appraisal"]["properties"]["nonexistent_audit_token"] = {
        "type": "string"
    }
    missing_fields, missing_enums = undocumented(mutated, _corpus())
    assert missing_fields == [("appraisal", "nonexistent_audit_token")]
    assert missing_enums == []


def test_the_guard_fails_when_the_schema_gains_an_undocumented_enum_value(
    schema: dict[str, Any],
) -> None:
    """Counterfactual, schema side: an enum value nobody documented is reported."""
    mutated = copy.deepcopy(schema)
    mutated["properties"]["appraisal"]["properties"]["status"]["enum"].append(
        "nonexistent-outcome"
    )
    missing_fields, missing_enums = undocumented(mutated, _corpus())
    assert missing_fields == []
    assert missing_enums == [("appraisal.status", "nonexistent-outcome")]


@pytest.mark.parametrize(
    ("token", "expected_fields", "expected_enums"),
    [
        ("kid", [("cnf.jwk", "kid")], []),
        ("declared", [], [("policy.enforcement_mode", "declared")]),
    ],
)
def test_the_guard_fails_when_a_doc_entry_is_removed(
    schema: dict[str, Any],
    token: str,
    expected_fields: list[Field],
    expected_enums: list[EnumValue],
) -> None:
    """Counterfactual, doc side: the two members #247 found missing from the schema
    reference are the mutation. Strip every inline mention of one from the corpus and
    the guard names exactly that member, so the green run above is a finding and not
    a coincidence of the corpus."""
    corpus = _corpus()
    stripped = corpus.replace(f"`{token}`", "`[removed]`")
    assert stripped != corpus, f"`{token}` is not in the corpus, so nothing was removed"
    missing_fields, missing_enums = undocumented(schema, stripped)
    assert missing_fields == expected_fields
    assert missing_enums == expected_enums

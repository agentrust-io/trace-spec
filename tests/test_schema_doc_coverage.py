"""Every schema field has a row in its section of docs/schema.md, and every enum
value is named in that row (#247).

Four surfaces state the rules and, until the precedence section lands, nothing
says which wins. This guard covers the narrower question that is mechanically
decidable: does the schema reference document every field and every fixed value
the schema carries, in the place a producer looks for it?

Three design choices, each made so the guard cannot go vacuous.

- **Coverage is asserted directly against the hand-maintained page.** Nothing is
  generated from the schema. Generated prose cannot drift from the source it was
  generated from, so a drift test over it would exercise the generator and not
  the agreement between two surfaces.

- **Coverage is keyed on position, not on the bare name.** A field on schema
  path ``policy`` is documented only by a row whose first cell is its name in the
  ``policy`` section of ``docs/schema.md``; an enum value of that field only by an
  inline-code span in that row's description cell. A bare-name rule ("the token
  appears somewhere in the docs") lets a row be deleted while the name survives
  in a sentence, a heading, or an unrelated field two sections away that shares
  it: ``version`` under ``model`` and under ``policy``, or the seven ``cnf.jwk``
  members named in the paragraph above their own table. The position rule is the
  one ``_report`` states and the one the two older table-parsing tests already
  apply to ``references`` and ``build_provenance``.

- **The counterfactual is run, not asserted.** ``test_the_guard_fails_when_*``
  below adds an undocumented field, an undocumented enum value and an undocumented
  ``const`` to a copy of the schema, deletes a field's row while its name stays in
  the page's prose, deletes one of two same-named rows, and strips an enum value
  from its own row while it survives in another. Each mutation reds the guard and
  names exactly the member it removed.

What this file does not decide, and is not scoped to: whether the description
attached to a field agrees with the spec, or whether an example is correct.
Neither is mechanically decidable, and a guard that reaches past what it can
decide produces failures nobody can act on. The wider corpus under ``docs/`` is
not consulted: a mention on a tutorial page is not documentation of a field, and
a corpus-wide token check is a strict subset of this page-level one, so it could
never be the only failure.
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
SCHEMA_DOC = ROOT / "docs" / "schema.md"

# Schema path (dotted, `[]` for array items) -> the heading of the docs/schema.md
# section whose table documents that object's members. Hand-maintained on
# purpose: a new nested object with no entry here fails
# `test_every_object_in_the_schema_has_a_section_mapped` rather than passing
# unchecked. The empty path is the top-level record.
SECTION_OF_PATH: dict[str, str] = {
    "": "## Top-level fields",
    "model": "## `model`",
    "runtime": "## `runtime`",
    "policy": "## `policy`",
    "tool_transcript": "## `tool_transcript`",
    "delegation": "## `delegation`",
    "origin": "## `origin`",
    "references[]": "## `references`",
    "build_provenance": "## `build_provenance`",
    "appraisal": "## `appraisal`",
    "cnf": "## `cnf`",
    "cnf.jwk": "### `cnf.jwk` members",
    "reproducibility": "## `reproducibility`",
    "reproducibility.input_closure[]": "### `reproducibility.input_closure` entries",
    "appraisal.re_execution": "### `appraisal.re_execution` members",
}

_INLINE_CODE = re.compile(r"`([^`\n]+)`")
# A fenced block, ``` or ~~~, opened and closed on lines of its own. Stripped
# before any table is parsed, so a record pasted as an example is not a row.
_FENCE = re.compile(r"^(```|~~~).*?^\1\s*$", re.MULTILINE | re.DOTALL)
_HEADING = re.compile(r"^#{2,3} ", re.MULTILINE)
_CELL_SEP = re.compile(r"(?<!\\)\|")

# (dotted path of the containing object, member name).
Field = tuple[str, str]
# (dotted path of the field, fixed value): every `enum` member and every `const`.
Value = tuple[str, str]


def _walk(node: Any, path: str, fields: set[Field], values: set[Value]) -> None:
    if not isinstance(node, dict):
        return
    for name, sub in node.get("properties", {}).items():
        fields.add((path, name))
        _walk(sub, f"{path}.{name}" if path else name, fields, values)
    for value in node.get("enum", []):
        if isinstance(value, str):
            values.add((path, value))
    if isinstance(node.get("const"), str):
        values.add((path, node["const"]))
    items = node.get("items")
    if isinstance(items, dict):
        _walk(items, f"{path}[]", fields, values)
    # Conditional branches. On today's schema they reach nothing `properties` does
    # not already reach (the top-level `allOf` re-declares `runtime.platform` and
    # `origin.kind`; the `cnf.jwk` branches re-declare `kty` as a `const`), so they
    # are walked for the `const` values and so that a member declared only inside
    # a branch is not missed the day one appears.
    for key in ("if", "then"):
        if isinstance(node.get(key), dict):
            _walk(node[key], path, fields, values)
    for sub in node.get("allOf", []):
        _walk(sub, path, fields, values)


def schema_fields_and_values(schema: dict[str, Any]) -> tuple[set[Field], set[Value]]:
    """Every property name, and every fixed string value, the schema carries."""
    fields: set[Field] = set()
    values: set[Value] = set()
    _walk(schema, "", fields, values)
    return fields, values


def _sections(markdown: str) -> dict[str, str]:
    """Heading line (without its `{#anchor}`) -> the text under it, up to the next `##`."""
    text = _FENCE.sub("", markdown)
    starts = [m.start() for m in _HEADING.finditer(text)] + [len(text)]
    out: dict[str, str] = {}
    for begin, end in zip(starts[:-1], starts[1:], strict=True):
        block = text[begin:end]
        heading, _, body = block.partition("\n")
        out[re.sub(r"\s*\{#[^}]*\}\s*$", "", heading).strip()] = body
    return out


def _rows(section: str) -> dict[str, str]:
    """Field name -> description cell, for every table row whose first cell is a code span."""
    rows: dict[str, str] = {}
    for line in section.splitlines():
        if not line.startswith("| `"):
            continue
        # Split on unescaped pipes only: a description that lists alternatives
        # as `a` \| `b` is one cell, not two.
        cells = [cell.strip() for cell in _CELL_SEP.split(line.strip().strip("|"))]
        rows.setdefault(cells[0].strip("`"), cells[-1])
    return rows


def undocumented(schema: dict[str, Any], page: str) -> tuple[list[Field], list[Value]]:
    """Fields with no row in their section, and values absent from their field's row.

    A field whose containing object has no section in ``SECTION_OF_PATH`` is
    reported as undocumented rather than skipped.
    """
    fields, values = schema_fields_and_values(schema)
    sections = _sections(page)
    tables = {path: _rows(sections.get(heading, "")) for path, heading in SECTION_OF_PATH.items()}
    missing_fields = sorted(f for f in fields if f[1] not in tables.get(f[0], {}))

    missing_values: list[Value] = []
    for path, value in sorted(values):
        parent, _, name = path.rpartition(".")
        description = tables.get(parent, {}).get(name, "")
        if value not in _INLINE_CODE.findall(description):
            missing_values.append((path, value))
    return missing_fields, missing_values


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(CANONICAL_SCHEMA_PATH.read_text(encoding="utf-8"))
    return loaded


@pytest.fixture(scope="module")
def page() -> str:
    return SCHEMA_DOC.read_text(encoding="utf-8")


def _report(missing_fields: list[Field], missing_values: list[Value]) -> str:
    lines = ["docs/schema.md does not document these schema members where a producer looks:"]
    lines += [
        f"  field  {path + '.' if path else ''}{name}: no row `{name}` under "
        f"{SECTION_OF_PATH.get(path, '<no section mapped for ' + path + '>')}"
        for path, name in missing_fields
    ]
    lines += [
        f"  value  {path}: `{value}` is not an inline-code span in that field's row"
        for path, value in missing_values
    ]
    lines.append(
        "Add the row to the object's own section (a table row whose first cell is the field "
        "name), or name the value in the field's description cell. A mention elsewhere on the "
        "page, or in a fenced example, does not count."
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- the guard


def test_the_two_schema_copies_are_the_same_bytes() -> None:
    """The guard reads one file and claims coverage for both, which is only true while
    they are identical. `test_validate.py` pins the same fact for the packaged copy; it
    is repeated here so this file's claim does not depend on another file's test."""
    assert CANONICAL_SCHEMA_PATH.read_bytes() == PACKAGED_SCHEMA_PATH.read_bytes()


def test_every_object_in_the_schema_has_a_section_mapped(schema: dict[str, Any]) -> None:
    """The path-to-section map is hand-maintained. A nested object the schema gains
    without an entry here would otherwise report every one of its members as
    undocumented with a confusing reason, or, worse, not at all."""
    fields, _ = schema_fields_and_values(schema)
    unmapped = sorted({path for path, _ in fields} - set(SECTION_OF_PATH))
    assert not unmapped, f"schema objects with no docs/schema.md section mapped: {unmapped}"


def test_every_mapped_section_exists_and_has_a_table(page: str) -> None:
    sections = _sections(page)
    for path, heading in SECTION_OF_PATH.items():
        assert heading in sections, f"{heading!r} (for schema path {path!r}) is not on the page"
        assert _rows(sections[heading]), f"{heading!r} has no field rows"


def test_every_schema_field_and_value_is_documented_in_its_place(
    schema: dict[str, Any], page: str
) -> None:
    missing_fields, missing_values = undocumented(schema, page)
    assert not missing_fields and not missing_values, _report(missing_fields, missing_values)


# --------------------------------------------------------------------- it can go red


def test_the_extraction_reaches_the_whole_schema(schema: dict[str, Any]) -> None:
    """Floors with slack, so a walker that silently stopped descending could not pass
    while an ordinary schema edit does not trip them: 62 fields and 31 values today.
    One member is pinned for each shape the walker has to descend through: a top-level
    field, a nested object member, an array item member, a nested enum value, and a
    `const` declared only inside a conditional branch."""
    fields, values = schema_fields_and_values(schema)
    assert len(fields) >= 55, f"only {len(fields)} fields found"
    assert len(values) >= 26, f"only {len(values)} fixed values found"
    assert ("", "subject") in fields
    assert ("cnf.jwk", "kid") in fields
    assert ("references[]", "rel") in fields
    assert ("policy.enforcement_mode", "declared") in values
    assert ("cnf.jwk.kty", "RSA") in values
    assert ("eat_profile", "tag:agentrust-io.com,2026:trace-v0.2") in values
    assert "canonicalizableValue" not in {name for _, name in fields}, "$defs are not fields"


def test_fenced_examples_are_not_rows() -> None:
    """Both fence styles are stripped before tables are parsed."""
    page = (
        "## `x`\n\n| Field | Type | Description |\n|---|---|---|\n| `a` | string | `v1` |\n\n"
        "```\n| `b` | string | `v2` |\n```\n\n~~~json\n| `c` | string | `v3` |\n~~~\n"
    )
    assert _rows(_sections(page)["## `x`"]) == {"a": "`v1`"}


def test_an_escaped_pipe_does_not_split_a_description_cell() -> None:
    row = "| `a` | string | one of `v1` \\| `v2` |\n"
    assert _rows(row) == {"a": "one of `v1` \\| `v2`"}


def _with_field(schema: dict[str, Any], parent: str, name: str) -> dict[str, Any]:
    mutated = copy.deepcopy(schema)
    node = mutated
    for part in parent.split(".") if parent else []:
        node = node["properties"][part]
    node["properties"][name] = {"type": "string"}
    return mutated


def test_the_guard_fails_when_the_schema_gains_an_undocumented_field(
    schema: dict[str, Any], page: str
) -> None:
    missing_fields, missing_values = undocumented(
        _with_field(schema, "appraisal", "nonexistent_audit_token"), page
    )
    assert missing_fields == [("appraisal", "nonexistent_audit_token")]
    assert missing_values == []


def test_the_guard_fails_when_the_schema_gains_an_undocumented_enum_value(
    schema: dict[str, Any], page: str
) -> None:
    mutated = copy.deepcopy(schema)
    mutated["properties"]["appraisal"]["properties"]["status"]["enum"].append("nonexistent-outcome")
    missing_fields, missing_values = undocumented(mutated, page)
    assert missing_fields == []
    assert missing_values == [("appraisal.status", "nonexistent-outcome")]


def test_the_guard_fails_when_an_enum_value_becomes_an_undocumented_const(
    schema: dict[str, Any], page: str
) -> None:
    """Moving a value from `enum` to `const` must not drop it from coverage."""
    mutated = copy.deepcopy(schema)
    mutated["properties"]["data_class"] = {"type": "string", "const": "nonexistent-class"}
    missing_fields, missing_values = undocumented(mutated, page)
    assert missing_fields == []
    assert missing_values == [("data_class", "nonexistent-class")]


def test_the_guard_fails_when_a_new_object_has_no_section_mapped(
    schema: dict[str, Any], page: str
) -> None:
    mutated = copy.deepcopy(schema)
    mutated["properties"]["nonexistent_block"] = {
        "type": "object",
        "properties": {"inner": {"type": "string"}},
    }
    missing_fields, _ = undocumented(mutated, page)
    assert ("nonexistent_block", "inner") in missing_fields
    fields, _ = schema_fields_and_values(mutated)
    assert "nonexistent_block" in {path for path, _ in fields} - set(SECTION_OF_PATH)


def _without_row(page: str, heading: str, name: str) -> str:
    """The page with the row `name` deleted from the section under `heading`, and nothing else."""
    sections = _sections(page)
    assert heading in sections
    row = next(line for line in sections[heading].splitlines() if line.startswith(f"| `{name}` "))
    assert page.count(row) == 1
    return page.replace(row + "\n", "")


@pytest.mark.parametrize(
    ("heading", "name", "expected_fields", "expected_values", "survives"),
    [
        # The member #247 found missing. Its name is on three other docs pages, and
        # nowhere else on this one: a corpus-wide bare-name rule stays green.
        ("### `cnf.jwk` members", "kid", [("cnf.jwk", "kid")], [], False),
        # Named in the sentence directly above its own table, which a bare-name rule
        # accepted as documentation of the row it makes redundant. The row also
        # carries the three `const` values, so they go missing with it.
        (
            "### `cnf.jwk` members",
            "kty",
            [("cnf.jwk", "kty")],
            [("cnf.jwk.kty", "EC"), ("cnf.jwk.kty", "OKP"), ("cnf.jwk.kty", "RSA")],
            True,
        ),
        # Two rows share the name `version`; deleting one must red exactly that one.
        ("## `model`", "version", [("model", "version")], [], True),
        ("## `policy`", "version", [("policy", "version")], [], True),
        # A top-level field whose name is also a section heading further down.
        ("## Top-level fields", "appraisal", [("", "appraisal")], [], True),
    ],
)
def test_the_guard_fails_when_a_fields_row_is_deleted(
    schema: dict[str, Any],
    page: str,
    heading: str,
    name: str,
    expected_fields: list[Field],
    expected_values: list[Value],
    survives: bool,
) -> None:
    """Doc side: delete one row and nothing else. Where the name stays elsewhere on
    the page, a guard that keyed on the bare name would stay green."""
    stripped = _without_row(page, heading, name)
    assert (f"`{name}`" in stripped) is survives
    missing_fields, missing_values = undocumented(schema, stripped)
    assert missing_fields == expected_fields
    assert missing_values == expected_values


@pytest.mark.parametrize(
    ("heading", "name", "value", "expected", "survives"),
    [
        # The value #247 found missing. It is not named anywhere else on the page.
        (
            "## `policy`",
            "enforcement_mode",
            "declared",
            ("policy.enforcement_mode", "declared"),
            False,
        ),
        # The same three depth values are listed on two fields' rows; stripping one
        # row's copy must red that field only, while the other row keeps the name.
        (
            "## `appraisal`",
            "provenance_depth_verified",
            "builder",
            ("appraisal.provenance_depth_verified", "builder"),
            True,
        ),
    ],
)
def test_the_guard_fails_when_a_value_is_removed_from_its_fields_row(
    schema: dict[str, Any],
    page: str,
    heading: str,
    name: str,
    value: str,
    expected: Value,
    survives: bool,
) -> None:
    sections = _sections(page)
    row = next(line for line in sections[heading].splitlines() if line.startswith(f"| `{name}` "))
    assert page.count(row) == 1
    stripped = page.replace(row, row.replace(f"`{value}`", "`[removed]`"))
    assert stripped != page
    assert (f"`{value}`" in stripped) is survives
    missing_fields, missing_values = undocumented(schema, stripped)
    assert missing_fields == []
    assert missing_values == [expected]

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

One thing a description says *is* decided here, and the boundary is worth stating
exactly. Where a field's ``pattern`` admits more than one digest algorithm, the row
has to name each one. That is not a judgement about whether prose agrees with the
spec; it is a comparison against the field's own machine-readable constraint, which
is why it can be checked at all and why the failure names the field and the missing
algorithm rather than asking a reader to adjudicate wording.

What this file does not decide, and is not scoped to: whether the description
attached to a field agrees with the spec in any wider sense, or whether an example
is correct. Neither is mechanically decidable, and a guard that reaches past what
it can decide produces failures nobody can act on. The wider corpus under ``docs/`` is
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


#: Every digest algorithm the project spells, with the hex length that follows it.
#: A probe value is built from each and offered to the field's own `pattern`, so
#: "admits sha384" is answered by the pattern rather than by reading it: the
#: alternation `^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$` factors the prefix out, so it
#: contains neither `sha256` nor `sha384` as text.
_DIGEST_ALGORITHMS: tuple[tuple[str, int], ...] = (
    ("sha256", 64),
    ("sha384", 96),
    ("sha512", 128),
)


def _subschema(schema: dict[str, Any], path: str, name: str) -> dict[str, Any]:
    """The subschema for a field, addressed the way `SECTION_OF_PATH` addresses it.

    This follows `properties` and `items` only, while `_walk` also descends `if`,
    `then` and `allOf`. A member declared solely inside a conditional branch is
    therefore reachable by `_walk` and not by this, and raises `KeyError` here rather
    than being passed over, so the day one appears this fails loudly instead of
    exempting the field from the algorithm check without saying so.
    """
    node: Any = schema
    for part in filter(None, path.split(".")):
        array = part.endswith("[]")
        node = node["properties"][part[:-2] if array else part]
        if array:
            node = node["items"]
    member: dict[str, Any] = node["properties"][name]
    return member


def admitted_algorithms(subschema: dict[str, Any]) -> set[str]:
    """The digest algorithms a field's `pattern` actually accepts.

    `re.search` rather than `fullmatch`, because an unanchored JSON Schema `pattern`
    matches anywhere and these are anchored in the schema itself.
    """
    pattern = subschema.get("pattern")
    if not isinstance(pattern, str) or "sha" not in pattern:
        return set()
    matcher = re.compile(pattern)
    return {
        label for label, width in _DIGEST_ALGORITHMS if matcher.search(f"{label}:{'a' * width}")
    }


def undocumented_algorithms(schema: dict[str, Any], page: str) -> list[tuple[Field, set[str]]]:
    """Fields whose `pattern` admits more than one digest algorithm, paired with the
    ones their row does not name.

    A row that documents a field into existence can still misdescribe it, and the
    coverage guard above cannot see that: it asks whether a row exists, never what the
    row claims. A producer reading `sha256:` where the schema also takes `sha384:`
    writes the narrower record, and a verifier author reading it may refuse a valid one.

    The field set comes from `schema_fields_and_values`, not from a second enumeration,
    so a field this file cannot reach is equally invisible to both guards rather than to
    one of them. Resolving each field's subschema is a separate lookup, `_subschema`,
    which reaches less of the schema than that walk does and says so.
    """
    fields, _ = schema_fields_and_values(schema)
    sections = _sections(page)
    tables = {path: _rows(sections.get(heading, "")) for path, heading in SECTION_OF_PATH.items()}

    gaps: list[tuple[Field, set[str]]] = []
    for path, name in sorted(fields):
        admitted = admitted_algorithms(_subschema(schema, path, name))
        if len(admitted) < 2:
            continue
        description = tables.get(path, {}).get(name, "")
        spelled = {
            label
            for label in admitted
            if re.search(label.replace("sha", "sha-?"), description, re.IGNORECASE)
        }
        if spelled != admitted:
            gaps.append(((path, name), admitted - spelled))
    return gaps


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


def test_every_digest_field_names_each_algorithm_its_pattern_admits(
    schema: dict[str, Any], page: str
) -> None:
    """A row that names one algorithm where the pattern takes two sends a producer to
    the narrower record and a verifier author to the narrower rule."""
    gaps = undocumented_algorithms(schema, page)
    assert not gaps, "\n".join(
        ["docs/schema.md describes these fields more narrowly than the schema accepts:"]
        + [
            f"  {path + '.' if path else ''}{name}: the row does not name "
            f"{', '.join(sorted(unnamed))}, which the pattern admits"
            for (path, name), unnamed in gaps
        ]
        + ["Name every algorithm the pattern takes, as the other digest rows do."]
    )


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


def test_admitted_algorithms_reads_the_alternation_the_schema_actually_uses() -> None:
    """The schema factors the prefix out: `^sha(256:...|384:...)$` contains neither the
    literal `sha256` nor `sha384`. A check that searched the pattern text for either
    would find no algorithm at all, conclude the field constrains none, and skip it, so
    the probe offers the pattern a value and believes the answer. The reading version of
    this check was written first and reported no gaps anywhere, which is what this pins."""
    both = r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$"
    assert admitted_algorithms({"pattern": both}) == {"sha256", "sha384"}
    assert admitted_algorithms({"pattern": "^sha256:[0-9a-f]{64}$"}) == {"sha256"}
    assert admitted_algorithms({"type": "string"}) == set()


def test_the_guard_fails_when_a_row_stops_naming_an_algorithm_its_pattern_admits(
    schema: dict[str, Any], page: str
) -> None:
    """Narrowing a corrected row back to its previous wording reports exactly that
    field, and only it."""
    sections = _sections(page)
    row = next(
        line for line in sections["## `policy`"].splitlines() if line.startswith("| `bundle_hash` ")
    )
    assert page.count(row) == 1
    narrowed = row.replace("`sha256:` or `sha384:`", "`sha256:`")
    assert narrowed != row, "the row no longer carries the form this test narrows"
    gaps = undocumented_algorithms(schema, page.replace(row, narrowed))
    assert gaps == [(("policy", "bundle_hash"), {"sha384"})]


def test_the_guard_ignores_a_field_whose_pattern_admits_one_algorithm(
    schema: dict[str, Any], page: str
) -> None:
    """The rule is that a row names what its own pattern takes, not that every digest row
    lists every algorithm the project spells. A field narrowed to one is not a gap even
    though its row still names two."""
    narrowed = copy.deepcopy(schema)
    narrowed["properties"]["policy"]["properties"]["bundle_hash"]["pattern"] = (
        "^sha256:[0-9a-f]{64}$"
    )
    assert admitted_algorithms(_subschema(narrowed, "policy", "bundle_hash")) == {"sha256"}
    gaps = undocumented_algorithms(narrowed, page)
    assert not [gap for gap in gaps if gap[0][1] == "bundle_hash"]

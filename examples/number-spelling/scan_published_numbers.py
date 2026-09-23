"""Find integer-typed members written with a fraction or an exponent (agentrust-io/trace-spec#247).

Deciding integers by value changes a verdict only where an integer-typed member is
written with a fraction or an exponent, such as `1785000000.0` or `1.785e9` for
`1785000000`. This script counts the published documents that carry one. Every
verdict the proposal changes is on such a document, so a count of zero means that no
published verdict changes.

    python examples/number-spelling/scan_published_numbers.py [ROOT ...]

Each ROOT is a directory, searched for `*.json` files and for fenced blocks labelled
`json` in `*.md` files; the default is this repository's `examples/`. One that does
not parse, such as an elided example, is counted and skipped; `jsonc` blocks are not
read. This directory is skipped when it sits inside a ROOT, because its vectors are
re-spelled on purpose; name it as a ROOT to scan it, which is a check that the scan
finds what it is looking for. Exit status 1 means an integer-typed member was found
written with a fraction or an exponent.

A member is integer-typed when a schema in `schema/` types it `integer`, matched on
the member's name and its parent's; when it sits in `cnf.jwk`, whose undeclared
members the schema holds to integers; or when a profile types it in prose, as
`observed_at` (docs/integration/pic-trace-bridge-v1.md) and `tool_catalog.tool_count`
(spec/server-provenance-v1.md) are. Python's `json` module keeps the spelling of
every number in reach through its `parse_int` and `parse_float` hooks, which is how
the spelling is read here; a parser that returns only values cannot see it.
Standard library only.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SCHEMAS = REPO / "schema"

# Integer-typed in prose, with no schema to read it from.
PROSE_MEMBERS = {("after", "observed_at"), ("tool_catalog", "tool_count")}
# `cnf.jwk` members the schema does not name are held to `canonicalizableValue`,
# which admits integers and no `number`.
INTEGER_SUBTREE = ("cnf", "jwk")

FENCE = re.compile(r"^```json[ \t]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
SKIPPED_DIRECTORIES = {"node_modules", "__pycache__", "site"}


class Number:
    """A JSON number together with the text it was written as."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text

    @property
    def fraction_or_exponent(self) -> bool:
        return any(c in self.text for c in ".eE")


def _integer_chains(node: Any, chain: tuple[str, ...], out: set[tuple[str, ...]]) -> None:
    if isinstance(node, dict):
        kind = node.get("type")
        if chain and (kind == "integer" or (isinstance(kind, list) and "integer" in kind)):
            out.add(chain[-2:])
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                for name, member in value.items():
                    _integer_chains(member, (*chain, name), out)
            else:
                _integer_chains(value, chain, out)
    elif isinstance(node, list):
        for item in node:
            _integer_chains(item, chain, out)


def integer_members() -> set[tuple[str, ...]]:
    """Name-and-parent pairs, or a lone name at a schema's top level, typed integer."""
    out: set[tuple[str, ...]] = set(PROSE_MEMBERS)
    for path in sorted(SCHEMAS.glob("*.json")):
        _integer_chains(json.loads(path.read_text(encoding="utf-8")), (), out)
    return out


def _parse(text: str) -> Any:
    return json.loads(text, parse_int=Number, parse_float=Number)


# Where a number sits in a document: member names and array indices from the root.
Location = tuple[str | int, ...]


def _numbers(node: Any, path: Location) -> Iterator[tuple[Location, Number]]:
    if isinstance(node, Number):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _numbers(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _numbers(value, (*path, index))


def is_integer_typed(path: Location, members: set[tuple[str, ...]]) -> bool:
    names = [p for p in path if isinstance(p, str)]
    for i in range(len(names) - 1):
        if tuple(names[i:i + 2]) == INTEGER_SUBTREE:
            return True
    if not path or not isinstance(path[-1], str):
        return False
    last = path[-1]
    parent = path[-2] if len(path) > 1 and isinstance(path[-2], str) else None
    return (last,) in members or (parent, last) in members


def documents(root: Path) -> Iterator[tuple[str, str]]:
    """(label, text) for every JSON file and every fenced `json` block under *root*."""
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part.startswith(".") or part in SKIPPED_DIRECTORIES for part in relative.parts):
            continue
        if HERE != root and HERE in path.parents:
            continue
        if path.suffix == ".json" and path.is_file():
            yield str(relative), path.read_text(encoding="utf-8")
        elif path.suffix == ".md" and path.is_file():
            text = path.read_text(encoding="utf-8")
            for n, match in enumerate(FENCE.finditer(text), start=1):
                yield f"{relative} (json block {n})", match.group(1)


def scan(root: Path, members: set[tuple[str, ...]]) -> dict[str, Any]:
    counts = {"documents": 0, "not_json": 0, "numbers": 0, "integer_typed": 0}
    findings: list[str] = []
    other: list[str] = []
    for label, text in documents(root):
        try:
            parsed = _parse(text)
        except ValueError:
            counts["not_json"] += 1
            continue
        counts["documents"] += 1
        for path, number in _numbers(parsed, ()):
            counts["numbers"] += 1
            where = f"{label}: {'.'.join(map(str, path))} = {number.text}"
            if is_integer_typed(path, members):
                counts["integer_typed"] += 1
                if number.fraction_or_exponent:
                    findings.append(where)
            elif number.fraction_or_exponent:
                other.append(where)
    return {"counts": counts, "findings": findings, "other": other}


def main(argv: list[str]) -> int:
    roots = [Path(a).resolve() for a in argv] or [REPO / "examples"]
    members = integer_members()
    total = 0
    for root in roots:
        if not root.is_dir():
            print(f"{root}: not a directory", file=sys.stderr)
            return 2
        result = scan(root, members)
        c = result["counts"]
        print(f"{root.name}/")
        if HERE != root and root in HERE.parents:
            print(f"  skipped {HERE.relative_to(root)}/: its vectors are re-spelled on purpose")
        print(f"  JSON documents parsed:  {c['documents']}")
        print(f"  unparseable, skipped:   {c['not_json']}")
        print(f"  numbers:                {c['numbers']}")
        print(f"  integer-typed members:  {c['integer_typed']}")
        print(f"  integer-typed, written with a fraction or an exponent: {len(result['findings'])}")
        for where in result["findings"]:
            print(f"    {where}")
        print(f"  other numbers written with a fraction or an exponent:  {len(result['other'])}")
        for where in result["other"]:
            print(f"    {where}")
        total += len(result["findings"])
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

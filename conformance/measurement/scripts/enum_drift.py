#!/usr/bin/env python3
"""Compare every hand-written enum in `trace-tests` against the normative schema.

A set literal in a test file that restates a schema `enum` is a copy, and a copy is
correct only until someone changes one side. The failure is silent in the direction that
matters: the copy keeps accepting what it always accepted, while the specification has
moved.

This finds those copies by AST rather than by grep — a set assigned to a name, holding
only string constants — and diffs each against the schema property it mirrors, matched by
content rather than by naming convention.

Usage:
    python enum_drift.py [path-to-trace-tests] [path-or-url-to-schema]
"""

from __future__ import annotations

import ast
import json
import os
import sys
import urllib.request
from pathlib import Path

DEFAULT_SCHEMA = (
    "https://raw.githubusercontent.com/agentrust-io/trace-spec/main/schema/trace-claim.json"
)

# Derived from this file's location, not the working directory — see mutate_modules.py.
_DEFAULT = str(Path(__file__).resolve().parent.parent.parent)
_RAW = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRACE_TESTS")) or _DEFAULT
SCHEMA_REF = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("SCHEMA", DEFAULT_SCHEMA)

# An empty string becomes Path("."), which is a directory, so the obvious `is_dir()`
# guard passes and the script silently measures the wrong tree. Reject the empty case
# before it can look like a valid one.
TRACE_TESTS = Path(_RAW).expanduser()
if not TRACE_TESTS.is_dir():
    sys.exit(f"trace-tests checkout not found: {TRACE_TESTS}")


def load_schema(ref: str) -> dict:
    if ref.startswith(("http://", "https://")):
        with urllib.request.urlopen(ref, timeout=20) as response:
            return json.load(response)
    return json.loads(Path(ref).read_text(encoding="utf-8"))


def schema_enums(schema: dict) -> dict[tuple[str, ...], set[str]]:
    """Every `enum` in the schema, keyed by its property path."""
    found: dict[tuple[str, ...], set[str]] = {}

    def walk(node: object, path: tuple[str, ...]) -> None:
        if not isinstance(node, dict):
            return
        if isinstance(node.get("enum"), list):
            values = {v for v in node["enum"] if isinstance(v, str)}
            if values:
                found[path] = values
        for key, child in node.get("properties", {}).items():
            walk(child, path + (key,))

    walk(schema, ())
    return found


def literal_sets(root: Path) -> list[tuple[Path, int, str, set[str]]]:
    """(path, lineno, name, values) for every name bound to a set of string constants."""
    out: list[tuple[Path, int, str, set[str]]] = []
    for path in sorted(root.rglob("*.py")):
        if ".git" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            value = node.value
            # frozenset({...}) / set({...}) unwrap to the inner literal
            if isinstance(value, ast.Call) and getattr(value.func, "id", "") in {
                "frozenset",
                "set",
            }:
                value = value.args[0] if value.args else value
            if not isinstance(value, ast.Set):
                continue
            values = {
                e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
            }
            if len(values) >= 2 and len(values) == len(value.elts):
                out.append((path, node.lineno, target.id, values))
    return out


def main() -> int:
    schema = load_schema(SCHEMA_REF)
    enums = schema_enums(schema)
    if not enums:
        sys.exit("no enums found in the schema; refusing to report agreement over nothing")

    candidates = literal_sets(TRACE_TESTS)
    if not candidates:
        sys.exit("no string-set literals found; the walk matched nothing")

    print(f"schema:   {SCHEMA_REF}")
    print(f"enums:    {len(enums)}   candidate set literals: {len(candidates)}\n")

    drifted: list[str] = []
    compared = 0
    for path, lineno, name, values in candidates:
        # Match by content: the schema enum sharing the most values, provided the
        # overlap is a majority. Naming conventions are not reliable across repos.
        best, overlap = None, 0
        for enum_path, enum_values in enums.items():
            shared = len(values & enum_values)
            if shared > overlap:
                best, overlap = enum_path, shared
        if best is None or overlap < max(2, len(values) // 2):
            continue
        compared += 1
        expected = enums[best]
        missing = expected - values
        extra = values - expected
        where = f"{path.relative_to(TRACE_TESTS)}:{lineno}"
        dotted = ".".join(best)
        if missing or extra:
            drifted.append(f"{where}  {name}  vs  {dotted}")
            print(f"  DRIFT  {where}")
            print(f"         {name} ({len(values)}) vs schema {dotted} ({len(expected)})")
            if missing:
                print(f"         missing: {', '.join(sorted(missing))}")
            if extra:
                print(f"         extra:   {', '.join(sorted(extra))}")
        else:
            print(f"  ok     {where}  {name} == {dotted} ({len(expected)})")

    print(f"\n  compared: {compared}   drifted: {len(drifted)}")
    if compared == 0:
        sys.exit(
            "\nno set literal matched any schema enum, so nothing was compared. That is "
            "not agreement — it is a measurement that did not happen, and reporting it "
            "as success is the failure this script exists to find elsewhere."
        )
    if drifted:
        print(
            "\nA hand-written copy of a schema enum accepts what it always accepted. The "
            "specification moving is exactly the case it cannot see."
        )
    return 1 if drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())

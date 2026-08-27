#!/usr/bin/env python3
"""House style: no em dashes, en dashes or horizontal bars in what we publish.

The hyphen-minus (U+002D) is fine and is what to use.

Two trees are exempt, for different reasons, and both exemptions are meant to
shrink:

``examples/``
    Conformance vectors and the generators that emit them. These are published
    data that third-party implementations score against, shipped in the
    ``agentrust-trace-tests`` package, and ``tests/test_generators_reproduce_
    fixtures.py`` pins each generator to its committed output. Rewriting a
    string inside a vector is a release-affecting change with its own review
    discipline, not a style edit. Prose in this tree is worth cleaning; do it as
    a deliberate change to the vectors, not as part of a sweep.

``spec/trace-v0.1.md``
    A superseded specification, published as a historical document and listed in
    the docs nav as "TRACE v0.1 (superseded)". Someone citing v0.1 section 3.2
    should find the text as it was. The current specs are swept; this one is a
    record, not living prose.

Run it directly; it takes no arguments beyond an optional --root.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

SKIP_DIRS = {
    ".git", "site", ".venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "node_modules", "dist", "build", ".nox",
}
EXTENSIONS = {".md", ".py", ".json", ".yml", ".yaml", ".toml", ".cfg", ".txt", ".html"}

#: Not swept, and each for a stated reason above. Shrink this; do not grow it.
EXEMPT_PREFIXES = ("examples/", "spec/trace-v0.1.md")

# Built from code points rather than written as literals. A checker containing
# the characters it bans reports itself, which sounds like a joke until it is
# the only failure in the log and somebody exempts the checker to get CI green.
OFFENDERS = {
    chr(0x2014): ("em dash", "use a colon, a comma, or two sentences"),
    chr(0x2013): ("en dash", 'write the range out: "1 to 3", "50 to 200 ms"'),
    chr(0x2015): ("horizontal bar", "use a colon or a comma"),
    chr(0x2212): ("minus sign", "use a hyphen-minus (-) outside mathematics"),
}


def candidates(root: pathlib.Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        relative = path.relative_to(root).as_posix()
        if relative.startswith(EXEMPT_PREFIXES):
            continue
        yield path, relative


def findings(root: pathlib.Path):
    for path, relative in candidates(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if not any(ch in text for ch in OFFENDERS):
            continue
        for number, line in enumerate(text.split("\n"), 1):
            for ch, (name, fix) in OFFENDERS.items():
                start = line.find(ch)
                while start != -1:
                    yield relative, number, name, fix, line[max(0, start - 45): start + 45].strip()
                    start = line.find(ch, start + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    found = list(findings(pathlib.Path(args.root).resolve()))
    if not found:
        print(f"no dashes outside {', '.join(EXEMPT_PREFIXES)}")
        return 0

    for relative, number, name, fix, context in found:
        print(f"{relative}:{number}: {name} ({fix})", file=sys.stderr)
        print(f"  ...{context}...", file=sys.stderr)
    print(
        f"\n{len(found)} occurrence(s). House style is no em dashes anywhere we publish.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

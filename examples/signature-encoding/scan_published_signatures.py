#!/usr/bin/env python3
"""Count how many published embedded signatures are canonically encoded (#247).

Spec section 3.2.2 already names the embedded `signature` field's encoding as
base64url, no padding. What was open is whether a non-canonical spelling of the
same 64 bytes is the same record: an Ed25519 or ES256 signature is 64 bytes,
base64url without padding spends 86 characters (516 bits) on 512 real bits, so
the final character carries 4 unused bits. RFC 4648 section 3.5 requires those
bits to be zero; a spelling that leaves them non-zero is non-canonical.

This script answers the question the schema tightening needs answered before it
ships: which published records would stop passing. It walks every `*.json` file
under one or more root directories, finds every string value at the key
`signature` that is exactly 86 characters from the base64url alphabet, and
checks whether decoding and re-encoding it without padding reproduces the same
string.

Only the `signature` key is scanned. `sig.value` in a revocation statement or
bundle (`schema/trace-revocation.json`, `schema/trace-revocation-bundle.json`)
carries the same base64url pattern and the same unused-bits question, but that
pattern is not touched by this change, so it is out of scope here.

Usage:
    python scan_published_signatures.py [ROOT ...]

With no ROOT given, scans this repository's own `examples/` directory. Pass one
root per tree to reproduce a combined count over other checkouts, for example:

    python scan_published_signatures.py \\
        ../../examples \\
        /path/to/trace-tests-checkout-at-3af2b53 \\
        /path/to/trace-registry-checkout

Exit code is 1 if any non-canonical signature is found, 0 otherwise, so the
script can also run as a regression gate.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

#: 86 base64url characters: the shape of a 64-byte (Ed25519 or ES256) signature
#: with no padding. See the module docstring for the bit-counting argument.
SIGNATURE_SHAPE = re.compile(r"^[A-Za-z0-9_-]{86}$")


class Finding(NamedTuple):
    root: Path
    file: Path
    path: str
    value: str
    canonical: bool


def is_canonical(value: str) -> bool:
    """True if *value* is the canonical base64url spelling of its decoded bytes.

    Decodes *value* (restoring the padding an unpadded encoding strips), then
    re-encodes the result the same way `sign_record` does. A canonical spelling
    round-trips to itself; a spelling with non-zero unused bits does not,
    because encoding always emits zero there.
    """
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == value


def _walk(node: object, path: tuple[str, ...]) -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, path + (str(key),))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, path + (str(index),))
    elif isinstance(node, str):
        if path and path[-1] == "signature" and SIGNATURE_SHAPE.match(node):
            yield ".".join(path), node


def scan(root: Path) -> Iterator[Finding]:
    """Yield a `Finding` for every 86-character `signature` value under *root*."""
    for file in sorted(root.rglob("*.json")):
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        for path, value in _walk(data, ()):
            yield Finding(root, file, path, value, is_canonical(value))


#: This repository's own examples/, used when no ROOT is given.
DEFAULT_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else None
    )
    parser.add_argument(
        "roots",
        nargs="*",
        metavar="ROOT",
        help="directories to scan recursively for *.json "
        f"(default: {DEFAULT_ROOT})",
    )
    args = parser.parse_args(argv)

    roots = [Path(r).resolve() for r in args.roots] or [DEFAULT_ROOT]

    findings: list[Finding] = []
    for root in roots:
        if not root.is_dir():
            print(f"skipping {root}: not a directory", file=sys.stderr)
            continue
        findings.extend(scan(root))

    non_canonical = [f for f in findings if not f.canonical]

    for root in roots:
        in_root = [f for f in findings if f.root == root]
        canonical_in_root = sum(1 for f in in_root if f.canonical)
        print(f"{root}: {len(in_root)} signature(s), {canonical_in_root} canonical")

    print(
        f"total: {len(findings)} signature(s), "
        f"{len(findings) - len(non_canonical)} canonical, "
        f"{len(non_canonical)} non-canonical"
    )

    for finding in non_canonical:
        print(
            f"  NON-CANONICAL: {finding.file} ({finding.path}): {finding.value}",
            file=sys.stderr,
        )

    return 1 if non_canonical else 0


if __name__ == "__main__":
    sys.exit(main())

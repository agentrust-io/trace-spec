"""Compare the two verdict files and report every case where they differ.

A case agrees when both sides reach the same verdict for the same stated reason:
the same failure code for a rejection, the same canonical bytes or digest for the
other kinds, and for a record that verifies, the same key thumbprint and the same
revocation outcome, cause and evidence. Evidence is compared with the two members
that carry a human-readable message removed, since those are prose.

A disagreement listed in `known-divergences.json` is reported as known and does
not fail the run; every other one does. The ledger is the place where a difference
is argued, so no difference can be absorbed by quietly matching the other side.

    python differential/compare.py
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import pathlib
from typing import Any


def load(path: pathlib.Path) -> dict[str, dict[str, Any]]:
    out = {}
    # split("\n"), not splitlines(): a canonical form may contain U+2028, which
    # splitlines treats as a line boundary and JSON does not.
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.strip():
            verdict = json.loads(line)
            out[verdict["id"]] = verdict
    return out


def summarise(verdict: dict[str, Any]) -> tuple:
    """What has to match. Anything outside this tuple is commentary."""
    kind = verdict["verdict"]
    if kind == "rejected":
        return ("rejected", verdict.get("code"))
    if kind == "verified":
        revocation = verdict.get("revocation") or {}
        return (
            "verified",
            verdict.get("thumbprint"),
            revocation.get("outcome"),
            revocation.get("cause"),
            json.dumps(revocation.get("evidence"), sort_keys=True),
        )
    if kind in {"canonical", "thumbprint", "digest"}:
        return (kind, verdict.get("bytes") or verdict.get("value"))
    return (kind,)


def observed_pair(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    return [left.get("code") or left["verdict"], right.get("code") or right["verdict"]]


def ledger_entry(
    ledger: list[dict[str, Any]], case_id: str, pair: list[str]
) -> dict[str, Any] | None:
    """The ledger entry that covers this divergence, or None.

    An entry matches on both the case and the pair of reported reasons. Matching on
    the case alone would let a broad pattern absorb a *different* divergence
    appearing later in the same family, which is the failure mode the ledger exists
    to prevent.
    """
    for entry in ledger:
        if not any(fnmatch.fnmatch(case_id, pattern) for pattern in entry["ids"]):
            continue
        if pair in [list(known) for known in entry["pairs"]]:
            return entry
    return None


def main() -> int:
    here = pathlib.Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=pathlib.Path, default=here / "build" / "python.jsonl")
    parser.add_argument(
        "--typescript", type=pathlib.Path, default=here / "build" / "typescript.jsonl"
    )
    parser.add_argument("--ledger", type=pathlib.Path, default=here / "known-divergences.json")
    parser.add_argument("--report", type=pathlib.Path, default=None)
    arguments = parser.parse_args()

    python = load(arguments.python)
    typescript = load(arguments.typescript)
    ledger = json.loads(arguments.ledger.read_text(encoding="utf-8"))["divergences"] \
        if arguments.ledger.exists() else []

    ids = sorted(set(python) | set(typescript))
    agreed: list[str] = []
    known: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []
    unclassified: list[str] = []
    path_only: list[dict[str, Any]] = []

    for case_id in ids:
        left = python.get(case_id)
        right = typescript.get(case_id)
        if left is None or right is None:
            unexpected.append({"id": case_id, "python": left, "typescript": right})
            continue
        if left.get("code") == "unclassified":
            unclassified.append(f"{case_id}: {left.get('detail')}")
        if summarise(left) == summarise(right):
            agreed.append(case_id)
            if left.get("code") == "schema_invalid" and left.get("path") != right.get("path"):
                path_only.append({
                    "id": case_id,
                    "python": left.get("path"),
                    "typescript": right.get("path"),
                })
            continue
        record = {
            "id": case_id,
            "group": left.get("group"),
            "python": {k: v for k, v in left.items() if k not in {"id", "group"}},
            "typescript": {k: v for k, v in right.items() if k not in {"id", "group"}},
        }
        entry = ledger_entry(ledger, case_id, observed_pair(left, right))
        if entry is not None:
            known.append({
                **record,
                "reason": entry["reason"],
                "classification": entry["classification"],
            })
        else:
            unexpected.append(record)

    total = len(ids)
    print(f"cases:              {total}")
    print(f"identical verdicts: {len(agreed)}")
    print(f"known divergences:  {len(known)}")
    print(f"unexpected:         {len(unexpected)}")
    if unclassified:
        print(f"unclassified Python exceptions: {len(unclassified)}")
        for line in unclassified[:20]:
            print(f"  {line}")
    if path_only:
        print(f"schema locations that differ while the code agrees: {len(path_only)}")
    for record in unexpected:
        print(json.dumps(record, sort_keys=True))

    if arguments.report is not None:
        arguments.report.write_text(json.dumps({
            "totals": {
                "cases": total,
                "identical": len(agreed),
                "known_divergences": len(known),
                "unexpected": len(unexpected),
                "unclassified_python_exceptions": len(unclassified),
            },
            "known": known,
            "unexpected": unexpected,
            "schema_location_differences": path_only,
        }, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    return 1 if unexpected or unclassified else 0


if __name__ == "__main__":
    raise SystemExit(main())

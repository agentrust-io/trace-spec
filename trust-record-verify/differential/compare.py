"""Compare the two verdict files and report every case where they differ.

A case agrees when both sides reach the same verdict for the same stated reason:
the same failure code for a rejection, and for a schema failure the same location,
since both implementations run the same checks in the same order and the first
member they fault must be the same one; the same canonical bytes or digest for the
other kinds; and for a record that verifies, the same key thumbprint, the same
source of that key (the caller's, or the record's own `cnf.jwk`) and the same
revocation outcome, cause and evidence. Evidence is compared with the two members
that carry a human-readable message removed, since those are prose.

A disagreement listed in `known-divergences.json` is reported as known and does
not fail the run; every other one does. The ledger is the place where a difference
is argued, so no difference can be absorbed by quietly matching the other side.

The ledger holds in the other direction too. An entry that no case reaches, or a
declared pair of reasons that no case produces, fails the run: a divergence that
stops happening, on either side, has to leave the ledger rather than stay as a
claim nothing checks. `--expect-external N` fails the run unless exactly N cases
came from the published conformance vectors, so a checkout that did not happen
prints as a failure rather than as a smaller corpus with `unexpected: 0`.

    python differential/compare.py [--expect-external N]
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
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
            if verdict["id"] in out:
                # A second verdict under one id would replace the first and take
                # its case out of the comparison without a trace.
                raise SystemExit(f"{path}: case id {verdict['id']!r} appears twice")
            out[verdict["id"]] = verdict
    return out


def summarise(verdict: dict[str, Any]) -> tuple:
    """What has to match. Anything outside this tuple is commentary."""
    kind = verdict["verdict"]
    if kind == "rejected":
        if verdict.get("code") == "schema_invalid":
            return ("rejected", "schema_invalid", verdict.get("path"))
        return ("rejected", verdict.get("code"))
    if kind == "verified":
        revocation = verdict.get("revocation") or {}
        return (
            "verified",
            verdict.get("thumbprint"),
            verdict.get("key_source"),
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
) -> tuple[int, dict[str, Any]] | None:
    """The ledger entry that covers this divergence, with its position, or None.

    An entry matches on both the case and the pair of reported reasons. Matching on
    the case alone would let a broad pattern absorb a *different* divergence
    appearing later in the same family, which is the failure mode the ledger exists
    to prevent.
    """
    for index, entry in enumerate(ledger):
        if not any(fnmatch.fnmatch(case_id, pattern) for pattern in entry["ids"]):
            continue
        if pair in [list(known) for known in entry["pairs"]]:
            return index, entry
    return None


def unreached(ledger: list[dict[str, Any]], hits: dict[tuple[int, str], int]) -> list[str]:
    """Every ledger claim the run did not bear out: an entry no case reached, a
    declared pair no case produced, or a `count` the entry did not land on. Each is
    a divergence that was resolved, renamed, moved to another entry or never
    existed, and the ledger did not follow."""
    out = []
    for index, entry in enumerate(ledger):
        pairs = [list(known) for known in entry["pairs"]]
        observed = {json.dumps(pair): hits.get((index, json.dumps(pair)), 0) for pair in pairs}
        if not any(observed.values()):
            out.append(f"entry {index + 1} {entry['ids']}: no case reached it")
            continue
        for pair in pairs:
            if not observed[json.dumps(pair)]:
                out.append(f"entry {index + 1} {entry['ids']}: pair {pair} never observed")
        landed = sum(observed.values())
        if "count" in entry and landed != entry["count"]:
            where = f"entry {index + 1} {entry['ids']}"
            out.append(f"{where}: declares {entry['count']} cases, {landed} landed")
    return out


def main() -> int:
    here = pathlib.Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=pathlib.Path, default=here / "build" / "python.jsonl")
    parser.add_argument(
        "--typescript", type=pathlib.Path, default=here / "build" / "typescript.jsonl"
    )
    parser.add_argument("--ledger", type=pathlib.Path, default=here / "known-divergences.json")
    parser.add_argument("--report", type=pathlib.Path, default=None)
    parser.add_argument(
        "--manifest", type=pathlib.Path, default=here / "build" / "manifest.json",
        help="the SHA-256 manifest generate_cases.py wrote for the published vectors",
    )
    parser.add_argument(
        "--expect-external", type=int, default=None, metavar="N",
        help="fail unless exactly N cases came from the published conformance vectors",
    )
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
    hits: dict[tuple[int, str], int] = {}

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
            continue
        record = {
            "id": case_id,
            "group": left.get("group"),
            "python": {k: v for k, v in left.items() if k not in {"id", "group"}},
            "typescript": {k: v for k, v in right.items() if k not in {"id", "group"}},
        }
        pair = observed_pair(left, right)
        found = ledger_entry(ledger, case_id, pair)
        if found is not None:
            index, entry = found
            hits[(index, json.dumps(pair))] = hits.get((index, json.dumps(pair)), 0) + 1
            known.append({
                **record,
                "reason": entry["reason"],
                "classification": entry["classification"],
            })
        else:
            unexpected.append(record)

    stale = unreached(ledger, hits)
    external = [
        case_id for case_id in ids
        if (python.get(case_id) or typescript.get(case_id) or {}).get("group")
        == "D6-published-vectors"
    ]
    manifest = (
        json.loads(arguments.manifest.read_text(encoding="utf-8"))
        if arguments.manifest.exists() else {}
    )
    manifest_digest = hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode("utf-8")
    ).hexdigest()
    external_short = (
        None if arguments.expect_external is None
        else arguments.expect_external - len(external)
    )

    total = len(ids)
    print(f"cases:              {total}")
    print(f"identical verdicts: {len(agreed)}")
    print(f"known divergences:  {len(known)}")
    print(f"unexpected:         {len(unexpected)}")
    print(f"ledger:             {len(ledger)} entries, "
          f"{sum(len(e['pairs']) for e in ledger)} pairs, {len(stale)} unreached")
    print(f"published vectors:  {len(external)} cases from {len(manifest)} files, "
          f"manifest sha256:{manifest_digest[:16]}")
    if external_short:
        print(f"  expected {arguments.expect_external} published-vector cases, "
              f"got {len(external)}")
    for line in stale:
        print(f"  {line}")
    if unclassified:
        print(f"unclassified Python exceptions: {len(unclassified)}")
        for line in unclassified[:20]:
            print(f"  {line}")
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
                "published_vector_cases": len(external),
                "ledger_unreached": len(stale),
            },
            "published_vectors": {
                "files": manifest,
                "manifest_sha256": manifest_digest,
                "expected_cases": arguments.expect_external,
            },
            "ledger_unreached": stale,
            "known": known,
            "unexpected": unexpected,
        }, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    return 1 if unexpected or unclassified or stale or external_short else 0


if __name__ == "__main__":
    raise SystemExit(main())

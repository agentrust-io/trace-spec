"""Python and TypeScript must agree on runs neither was written against.

Seeded random structural changes to valid runs, re-signed so they reach the
run-level checks, then verified by both implementations.
"""

from __future__ import annotations

import copy
import json
import pathlib
import random
import subprocess
from collections import Counter
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prototype import behavior_trace as bt
from tests.test_trust_record_verify_citations_and_platform import PACKAGE, _ensure_built

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "examples" / "behavior-trace"
SEEDS = {"wrapper": 1, "cmcp": 2, "model-gateway": 3, "egress-proxy": 4}
KEYS = {e: Ed25519PrivateKey.from_private_bytes(bytes([s]) * 32) for e, s in SEEDS.items()}
ROGUE = Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)
CASES = 600


def _base(name: str) -> list[dict[str, Any]]:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))["blocks"]


BASES = [_base("01-valid-two-edges"), _base("02-valid-four-edges-shuffled"),
         _base("33-valid-escaped-pointers")]
PINNED = json.loads((VECTORS / "01-valid-two-edges.json").read_text(encoding="utf-8"))[
    "pinned_keys"]


def _resign(block: dict[str, Any], key: Ed25519PrivateKey | None = None) -> dict[str, Any]:
    return bt.sign_block(block, key or KEYS.get(block["edge"], ROGUE))


def _mutate(rng: random.Random, blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocks = copy.deepcopy(blocks)
    digests = [bt.block_digest(b) for b in blocks]
    i = rng.randrange(len(blocks))
    b = blocks[i]
    op = rng.choice([
        "drop", "duplicate", "seq", "prev", "parents", "run_id", "edge", "kind",
        "peers", "provenance", "rogue_key", "tamper", "shuffle", "schema", "drop_end",
    ])
    if op == "drop":
        del blocks[i]
    elif op == "drop_end":
        blocks = [x for x in blocks if x["kind"] != "run_end"]
    elif op == "duplicate":
        blocks.insert(rng.randrange(len(blocks) + 1), copy.deepcopy(b))
    elif op == "shuffle":
        rng.shuffle(blocks)
    elif op == "tamper":
        b["body"]["tampered"] = rng.random() < 0.5
    elif op == "rogue_key":
        blocks[i] = _resign(b, ROGUE)
    elif op == "schema":
        b[rng.choice(["note", "seq"])] = rng.choice(["x", 1.5])
        blocks[i] = _resign(b)
    else:
        if op == "seq":
            b["seq"] = rng.choice([0, 1, 2, 3, b["seq"] + 1])
        elif op == "prev" and b["kind"] != "run_start":
            b["prev"] = rng.choice(digests)
        elif op == "parents":
            b["parents"] = sorted(set(rng.sample(digests, rng.randrange(3))))
            if rng.random() < 0.3:
                b["parents"].append("sha256:" + "c" * 64)
        elif op == "run_id" and "run_id" in b:
            b["run_id"] = rng.choice(digests)
        elif op == "edge":
            b["edge"] = rng.choice([*SEEDS, "sandbox"])
        elif op == "kind":
            kind = rng.choice(["run_start", "run_end", "heartbeat", "tool_call"])
            b["kind"] = kind
            if kind == "run_start":
                b.pop("run_id", None)
                b["prev"] = None
            elif "run_id" not in b:
                b["run_id"] = digests[0]
                b["prev"] = digests[0]
            if kind == "run_end":
                b["body"] = {"outcome": rng.choice(["completed", "failed"])}
            if kind == "heartbeat":
                b["body"] = {"peers": {rng.choice(list(SEEDS)): rng.choice(digests)}}
        elif op == "peers":
            b["kind"] = "heartbeat" if b["kind"] != "run_start" else b["kind"]
            b["body"] = {"peers": {rng.choice([*SEEDS, "sandbox"]): rng.choice(digests)}}
        elif op == "provenance":
            b["provenance"] = {rng.choice(
                ["/body", "/kind", "/parents/0", "/parents/9", "/body/nope", "/sig/kid", "/t/~0x"]
            ): "observed"}
        blocks[i] = _resign(b)
    return blocks


def _cases() -> list[list[dict[str, Any]]]:
    rng = random.Random(20261116)
    out = []
    for _ in range(CASES):
        blocks = rng.choice(BASES)
        for _ in range(rng.randrange(1, 4)):
            if blocks:
                blocks = _mutate(rng, blocks)
        out.append(blocks)
    return out


def _typescript(cases: list[list[dict[str, Any]]], tmp: pathlib.Path) -> list[dict[str, Any]]:
    path = tmp / "cases.json"
    path.write_text(json.dumps({"pinned": PINNED, "cases": cases}), encoding="utf-8")
    script = (
        'import { readFileSync } from "node:fs";'
        'import { verifyRun } from "./dist/index.js";'
        "const d = JSON.parse(readFileSync(process.argv[1], 'utf8'));"
        "const out = [];"
        "for (const c of d.cases) out.push(await verifyRun(c, d.pinned));"
        "process.stdout.write(JSON.stringify(out));"
    )
    done = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(path)],
        cwd=PACKAGE, capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return json.loads(done.stdout)


@pytest.fixture(scope="module")
def results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    _ensure_built()
    cases = _cases()
    python = [bt.verify_run(c, PINNED) for c in cases]
    return {"python": python, "typescript": _typescript(cases, tmp_path_factory.mktemp("bt"))}


def test_both_implementations_agree_on_every_case(results: dict[str, Any]) -> None:
    py, ts = results["python"], results["typescript"]
    assert len(py) == len(ts) == CASES
    differ = [i for i in range(CASES) if py[i] != ts[i]]
    first = differ[0] if differ else None
    assert not differ, f"{len(differ)} cases differ; first {first}: {py[first]} vs {ts[first]}"


def test_the_cases_reach_every_code_and_outcome(results: dict[str, Any]) -> None:
    codes = Counter(c for r in results["python"] for c in r["codes"])
    outcomes = Counter(r["classification"] for r in results["python"])
    assert set(codes) == set(bt.BLOCK_CODES + bt.RUN_CODES), sorted(codes)
    assert set(outcomes) == {"verified", "truncated", "rejected"}

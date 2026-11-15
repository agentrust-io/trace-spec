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
SEEDS = {
    "wrapper": 1, "cmcp": 2, "model-gateway": 3, "egress-proxy": 4, "sandbox": 5, "ca2a": 6,
}
KEYS = {e: Ed25519PrivateKey.from_private_bytes(bytes([s]) * 32) for e, s in SEEDS.items()}
ROGUE = Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)
CASES = 600


def _base(name: str) -> list[dict[str, Any]]:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))["blocks"]


BASES = [_base("01-valid-two-edges"), _base("02-valid-four-edges-shuffled"),
         _base("33-valid-escaped-pointers"), _base("42-valid-every-kind")]
C = "hmac-sha256:" + "e" * 64
BODIES = {
    "run_start": {},
    "run_end": {"outcome": "failed"},
    "tool_call": {"tool": "search", "args": C, "decision": "deny"},
    "approval": {"approver": "bob@example.org", "approves": "sha256:" + "d" * 64,
                 "decision": "rejected"},
}
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
        b["t"]["observed_at"] += 1  # changed after signing: the signature must fail
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
            b["edge"] = rng.choice(list(SEEDS))
        elif op == "kind":
            kind = rng.choice([*BODIES, "heartbeat"])
            b["kind"] = kind
            b.pop("provenance", None)
            if kind == "run_start":
                b.pop("run_id", None)
                b["prev"] = None
            elif "run_id" not in b:
                b["run_id"] = digests[0]
                b["prev"] = digests[0]
            if kind == "heartbeat":
                b["body"] = {"peers": {rng.choice(list(SEEDS)): rng.choice(digests)}}
            else:
                b["body"] = copy.deepcopy(BODIES[kind])
        elif op == "peers" and b["kind"] != "run_start":
            b["kind"] = "heartbeat"
            b.pop("provenance", None)
            b["body"] = {"peers": {rng.choice(list(SEEDS)): rng.choice(digests)}}
        elif op == "provenance":
            b["provenance"] = {rng.choice(
                ["/body", "/body/tool", "/body/model", "/body/requested_tools",
                 "/body/requested_tools/0/tool", "/body/requested_tools/9/tool",
                 "/body/nope", "/body/ext/~0x", "/kind", "/sig/kid"]
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


def _boundary_cases() -> list[tuple[str, Any, Any, Any]]:
    """Inputs at the line between a configuration error and a verdict."""
    a = _base("01-valid-two-edges")
    jwk = PINNED["cmcp"][0]
    bad_sig = copy.deepcopy(a)
    bad_sig[2]["sig"]["value"] = "!" + bad_sig[2]["sig"]["value"][1:]
    wrong_edge = copy.deepcopy(a)
    wrong_edge[3]["edge"] = "sandbox"
    several = copy.deepcopy(a)
    several[1]["body"]["model"] = "has a space"
    several[2]["body"]["tool"] = "changed"
    several[3]["edge"] = "sandbox"
    return [
        ("private-jwk", a, {**PINNED, "cmcp": [{**jwk, "d": jwk["x"]}]}, None),
        ("padded-x", a, {**PINNED, "cmcp": [{**jwk, "x": jwk["x"] + "="}]}, None),
        ("short-x", a, {**PINNED, "cmcp": [{**jwk, "x": "AAAA"}]}, None),
        ("unknown-edge", a, {**PINNED, "cmpc": []}, None),
        ("not-a-list", a, {**PINNED, "cmcp": jwk}, None),
        ("blocks-not-a-list", {"blocks": a}, PINNED, None),
        ("bad-sig-encoding", bad_sig, PINNED, None),
        ("wrong-edge", wrong_edge, PINNED, None),
        ("duplicate-jwk", a, {**PINNED, "cmcp": [jwk, jwk]}, None),
        ("empty-list", a, {**PINNED, "cmcp": []}, None),
        ("unused-edge", a, {k: v for k, v in PINNED.items() if k != "egress-proxy"}, None),
        ("several-bad", several, PINNED, None),
        ("max-blocks-hit", a, PINNED, len(a) - 1),
        ("max-blocks-none", a, PINNED, "none"),
        ("max-blocks-negative", a, PINNED, -1),
        ("over-default-limit", ["x"] * (bt.MAX_BLOCKS + 1), {}, None),
        ("over-default-none", ["x"] * (bt.MAX_BLOCKS + 1), {}, "none"),
    ]


def _python_outcome(blocks: Any, pinned: Any, limit: Any) -> Any:
    kwargs = {} if limit is None else {"max_blocks": None if limit == "none" else limit}
    try:
        return bt.verify_run(blocks, pinned, **kwargs)
    except ValueError:
        return "error"


def test_both_draw_the_same_line_between_errors_and_verdicts(
    tmp_path: pathlib.Path,
) -> None:
    _ensure_built()
    cases = _boundary_cases()
    path = tmp_path / "boundary.json"
    path.write_text(json.dumps([[n, b, p, lim] for n, b, p, lim in cases]), encoding="utf-8")
    script = (
        'import { readFileSync } from "node:fs";'
        'import { verifyRun, TraceVerificationError } from "./dist/index.js";'
        "const out = {};"
        "const cases = JSON.parse(readFileSync(process.argv[1], 'utf8'));"
        "for (const [name, blocks, pinned, limit] of cases) {"
        "  const options = limit === null ? {} : { maxBlocks: limit === 'none' ? null : limit };"
        "  try { out[name] = await verifyRun(blocks, pinned, options); }"
        "  catch (e) { if (!(e instanceof TraceVerificationError)) throw e; out[name] = 'error'; }"
        "}"
        "process.stdout.write(JSON.stringify(out));"
    )
    done = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(path)],
        cwd=PACKAGE, capture_output=True, text=True, encoding="utf-8", check=True,
    )
    typescript = json.loads(done.stdout)
    python = {n: _python_outcome(b, p, lim) for n, b, p, lim in cases}
    assert python == typescript
    errors = sorted(n for n, r in python.items() if r == "error")
    assert errors == sorted(["private-jwk", "padded-x", "short-x", "unknown-edge", "not-a-list",
                             "blocks-not-a-list", "max-blocks-hit", "max-blocks-negative",
                             "over-default-limit"])
    assert python["over-default-none"]["codes"] == ["schema_invalid"]
    assert python["bad-sig-encoding"]["codes"] == ["schema_invalid"]
    assert python["wrong-edge"]["codes"] == ["key_not_pinned"]
    assert python["empty-list"]["codes"] == ["key_not_pinned"]
    for name in ("duplicate-jwk", "unused-edge", "max-blocks-none"):
        assert python[name]["classification"] == "verified", name
    assert python["several-bad"]["codes"] == [
        "key_not_pinned", "schema_invalid", "signature_invalid"]

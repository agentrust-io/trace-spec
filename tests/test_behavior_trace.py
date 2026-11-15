"""Tests for the behavior-trace reference code against its vectors."""

from __future__ import annotations

import copy
import json
import pathlib
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.sign import _b64url_decode, _pubkey_from_jwk
from prototype import behavior_trace as bt

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "examples" / "behavior-trace"
ALL = sorted(VECTORS.glob("*.json"))
VALID = [p for p in ALL if json.loads(p.read_text(encoding="utf-8"))["expected"]["codes"] == []]


def _load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vectors_were_found() -> None:
    assert len(ALL) == 39
    assert len(VALID) == 6


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.stem)
def test_vector(path: pathlib.Path) -> None:
    v = _load(path)
    assert bt.verify_run(v["blocks"], v["pinned_keys"]) == v["expected"]


def test_every_code_has_at_least_two_vectors() -> None:
    seen: dict[str, int] = {}
    for path in ALL:
        for code in _load(path)["expected"]["codes"]:
            seen[code] = seen.get(code, 0) + 1
    assert set(seen) == set(bt.BLOCK_CODES + bt.RUN_CODES)
    assert min(seen.values()) >= 2


def test_signer_matches_the_generator() -> None:
    # Same seeds as gen_vectors.py. Ed25519 is deterministic, so the bytes must match.
    keys = {"wrapper": 1, "cmcp": 2, "model-gateway": 3, "egress-proxy": 4}
    for block in _load(VECTORS / "01-valid-two-edges.json")["blocks"]:
        key = Ed25519PrivateKey.from_private_bytes(bytes([keys[block["edge"]]]) * 32)
        assert bt.sign_block(block, key) == block


def _leaf_paths(node: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    if isinstance(node, dict):
        out = [path] if path else []
        for k, v in node.items():
            out += _leaf_paths(v, (*path, k))
        return out
    if isinstance(node, list):
        out = [path]
        for i, v in enumerate(node):
            out += _leaf_paths(v, (*path, i))
        return out
    return [path]


def _mutate(block: dict[str, Any], path: tuple[Any, ...]) -> dict[str, Any]:
    out = copy.deepcopy(block)
    parent = out
    for step in path[:-1]:
        parent = parent[step]
    value = parent[path[-1]]
    if isinstance(value, bool):
        parent[path[-1]] = not value
    elif isinstance(value, int):
        parent[path[-1]] = value + 1
    elif isinstance(value, str):
        parent[path[-1]] = value + "x"
    elif value is None:
        parent[path[-1]] = "x"
    elif isinstance(value, list):
        parent[path[-1]] = [*value, "x"]
    else:
        parent[path[-1]] = {**value, "x": "x"}
    return out


def _signature_holds(block: dict[str, Any], jwk: dict[str, Any]) -> bool:
    try:
        _pubkey_from_jwk(jwk).verify(
            _b64url_decode(block["sig"]["value"], field="sig"), bt._signing_bytes(block)
        )
    except InvalidSignature:
        return False
    return True


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.stem)
def test_every_member_is_signed(path: pathlib.Path) -> None:
    v = _load(path)
    checked = 0
    for block in v["blocks"]:
        jwk = v["pinned_keys"][block["edge"]][0]
        assert _signature_holds(block, jwk)
        unsigned = {k: val for k, val in block.items() if k != "sig"}
        for leaf in _leaf_paths(unsigned):
            assert not _signature_holds(_mutate(block, leaf), jwk), leaf
            checked += 1
        added = {**block, "extra": "x"}
        assert not _signature_holds(added, jwk)
    assert checked > 0


def test_block_digest_covers_the_signature() -> None:
    block = _load(VECTORS / "01-valid-two-edges.json")["blocks"][0]
    other = copy.deepcopy(block)
    other["sig"]["value"] = other["sig"]["value"][:-1] + "A"
    assert bt.block_digest(block) != bt.block_digest(other)


@pytest.mark.parametrize("blocks", [None, {}, "x", ({},)])
def test_blocks_must_be_a_list(blocks: Any) -> None:
    with pytest.raises(ValueError):
        bt.verify_run(blocks, {})


@pytest.mark.parametrize(
    "pinned",
    [None, [], {"cmcp": "x"}, {"cmcp": [{"kty": "EC"}]}, {1: []}],
)
def test_pinned_keys_must_be_well_formed(pinned: Any) -> None:
    with pytest.raises(ValueError):
        bt.verify_run([], pinned)


def test_a_non_object_block_is_schema_invalid() -> None:
    assert bt.verify_run(["x"], {}) == {"classification": "rejected", "codes": ["schema_invalid"]}


def test_an_empty_run_has_no_start() -> None:
    assert bt.verify_run([], {}) == {"classification": "rejected", "codes": ["run_start_invalid"]}


RUN_A = _load(VECTORS / "01-valid-two-edges.json")


def test_unknown_edge_in_pinned_keys_is_a_config_error() -> None:
    with pytest.raises(ValueError):
        bt.verify_run(RUN_A["blocks"], {**RUN_A["pinned_keys"], "cmpc": []})


def test_pinned_keys_duplicate_unused_and_empty() -> None:
    pinned = RUN_A["pinned_keys"]
    doubled = {**pinned, "cmcp": pinned["cmcp"] * 2}
    assert bt.verify_run(RUN_A["blocks"], doubled)["classification"] == "verified"
    unused = {**pinned, "sandbox": pinned["cmcp"]}
    assert bt.verify_run(RUN_A["blocks"], unused)["classification"] == "verified"
    empty = {**pinned, "cmcp": []}
    assert bt.verify_run(RUN_A["blocks"], empty)["codes"] == ["key_not_pinned"]


def _nested(depth: int) -> Any:
    value: Any = "x"
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize("where", ["body", "parents"])
def test_deep_nesting_is_schema_invalid_not_an_exception(where: str) -> None:
    blocks = copy.deepcopy(RUN_A["blocks"])
    if where == "body":
        blocks[2]["body"]["deep"] = _nested(100_000)
    else:
        blocks[2]["parents"] = [_nested(100_000), _nested(100_000)]
    got = bt.verify_run(blocks, RUN_A["pinned_keys"])
    assert got == {"classification": "rejected", "codes": ["schema_invalid"]}

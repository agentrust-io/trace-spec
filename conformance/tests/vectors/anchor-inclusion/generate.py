"""Regenerate portable anchor vectors without importing the verifier under test."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent


def canonical(claim: dict) -> bytes:
    return json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def leaf(claim: dict) -> bytes:
    return hashlib.sha256(b"\x00" + canonical(claim)).digest()


def root(leaves: list[bytes]) -> bytes:
    """RFC 6962 recursive split, independent of the verifier's fn/sn walk."""
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + root(leaves[:split]) + root(leaves[split:])).digest()


def path(leaves: list[bytes], index: int) -> list[bytes]:
    if len(leaves) == 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return path(leaves[:split], index) + [root(leaves[split:])]
    return path(leaves[split:], index - split) + [root(leaves[:split])]


def digest(value: bytes) -> str:
    return "sha256:" + value.hex()


def claim(index: int) -> dict:
    return {
        "transparency": "https://log.example.org/batches/anchor-vectors",
        "subject": f"agent-{index}",
        "iat": 1000 + index,
        # This is an opaque artifact-binding field, not a valid signature.
        "signature": f"fixture-signature-{index}",
    }


def vectors() -> list[dict]:
    out = []

    def positive(name: str, claims: list[dict], index: int) -> dict:
        leaves = [leaf(c) for c in claims]
        v = {
            "name": name,
            "claim": claims[index],
            "receipt": {
                "leaf_index": index,
                "leaf_count": len(claims),
                "audit_path": [digest(p) for p in path(leaves, index)],
                "merkle_root": digest(root(leaves)),
            },
            "construction": {
                "canonical_ascii": canonical(claims[index]).decode("ascii"),
                "leaf_hash": digest(leaves[index]),
                "ordered_leaf_hashes": [digest(p) for p in leaves],
            },
            "expected": {"tr_anc_002": "pass"},
        }
        out.append(v)
        return v

    for count, index in [(1, 0), (2, 0), (2, 1), (3, 2), (5, 0), (5, 3), (5, 4), (9, 8)]:
        positive(f"tree-{count}-index-{index}", [claim(i) for i in range(count)], index)
    unicode_claim = claim(0)
    unicode_claim["subject"] = "agent-é-😀"
    unicode_claim["metadata"] = {"😀": [True, None, "é"], "\ue000": {"z": 1, "a": -1}}
    unicode_positive = positive("unicode-codepoint-order", [unicode_claim, claim(1)], 0)

    def negative(name: str, twin: dict, reason: str) -> dict:
        v = copy.deepcopy(twin)
        v.update(name=name, positive_twin=twin["name"], reason=reason)
        v["expected"]["tr_anc_002"] = "fail"
        # Construction belongs to the accepted twin, not the mutated input.
        del v["construction"]
        out.append(v)
        return v

    base = out[5]  # five leaves, index 3: mixed left/right siblings
    negative("changed-subject", base, "Claim body changed after anchoring.")["claim"]["subject"] = (
        "other"
    )
    negative("changed-signature", base, "The signature field is part of the anchored object.")[
        "claim"
    ]["signature"] = "other"
    negative("wrong-root", base, "Committed root differs.")["receipt"]["merkle_root"] = digest(
        bytes(32)
    )
    negative("wrong-index", base, "Proof belongs to a different position.")["receipt"][
        "leaf_index"
    ] = 2
    negative("reversed-path", base, "Siblings must be supplied leaf-to-root.")["receipt"][
        "audit_path"
    ].reverse()
    negative("short-path", base, "Proof does not reach the root.")["receipt"]["audit_path"].pop()
    negative("long-path", base, "Extra node after reaching the root.")["receipt"][
        "audit_path"
    ].append(digest(bytes(32)))
    negative("out-of-range-index", base, "Index equals leaf_count.")["receipt"]["leaf_index"] = 5
    negative("negative-index", base, "Negative index.")["receipt"]["leaf_index"] = -1
    negative("boolean-index", base, "A boolean is not an integer index.")["receipt"][
        "leaf_index"
    ] = True
    negative("empty-tree", out[0], "Zero-leaf batches are invalid.")["receipt"]["leaf_count"] = 0
    negative("boolean-count", out[0], "A boolean is not a leaf count.")["receipt"]["leaf_count"] = (
        True
    )
    negative("malformed-sibling", base, "Hashes require 64 lowercase hex digits.")["receipt"][
        "audit_path"
    ][0] = "sha256:xyz"
    negative("missing-receipt", base, "A URI alone does not prove inclusion.")["receipt"] = None
    # Plausible JCS/UTF-8 leaf: compute a fully matching alternative tree, so
    # failure isolates the canonicalization rather than an arbitrary root.
    v = negative(
        "utf8-leaf",
        unicode_positive,
        "Anchor leaves escape non-ASCII; UTF-8 JSON is a different preimage.",
    )
    wrong_leaf = hashlib.sha256(
        b"\x00"
        + json.dumps(
            unicode_claim, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).digest()
    v["receipt"]["merkle_root"] = digest(root([wrong_leaf, leaf(claim(1))]))
    v = negative("missing-leaf-prefix", out[0], "Leaf hashing includes the 0x00 prefix.")
    v["receipt"]["merkle_root"] = digest(hashlib.sha256(canonical(v["claim"])).digest())
    v = negative("duplicated-odd-leaf", out[6], "Odd leaves are promoted, not duplicated.")
    level = [leaf(claim(i)) for i in range(5)]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    v["receipt"]["merkle_root"] = digest(level[0])
    v = negative("utf16-key-order", unicode_positive, "Anchor keys sort by code point, not UTF-16.")

    def utf16_order(value):
        if isinstance(value, dict):
            return {
                k: utf16_order(value[k]) for k in sorted(value, key=lambda k: k.encode("utf-16be"))
            }
        if isinstance(value, list):
            return [utf16_order(x) for x in value]
        return value

    wrong_bytes = json.dumps(
        utf16_order(unicode_claim), separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    wrong_leaf = hashlib.sha256(b"\x00" + wrong_bytes).digest()
    v["receipt"]["merkle_root"] = digest(root([wrong_leaf, leaf(claim(1))]))
    return out


def main() -> None:
    for i, v in enumerate(vectors(), 1):
        (HERE / f"{i:02}-{v['name']}.json").write_text(
            json.dumps(v, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()

"""Reference code for behavior-trace blocks (docs/rfcs/behavior-trace.md).

Experimental. Builds, signs and verifies blocks, and verifies a whole run.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib
import re
from collections import defaultdict
from functools import lru_cache
from typing import Any

import jsonschema
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.sign import (
    _b64url_decode,
    _canonical_bytes,
    _pubkey_from_jwk,
    jwk_thumbprint,
    key_to_jwk,
)

PROFILE = "behavior-trace-block/experimental-v1"
SCHEMA_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "schema"
    / "behavior-trace-block-experimental-v1.json"
)

BLOCK_CODES = ("schema_invalid", "key_not_pinned", "signature_invalid")
RUN_CODES = (
    "run_start_invalid",
    "run_id_mismatch",
    "fork",
    "chain_gap",
    "chain_link_broken",
    "parent_missing",
    "heartbeat_peer_unknown",
    "block_after_end",
)


def _pattern(validator: Any, pattern: str, instance: Any, schema: Any) -> Any:
    # JSON Schema patterns are ECMA-262. Python's "$" also matches before a final
    # newline, so anchor with \Z to reject what a JavaScript verifier rejects.
    if validator.is_type(instance, "string") and not re.search(
        pattern.replace("$", r"\Z"), instance
    ):
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")


_Validator = jsonschema.validators.extend(  # type: ignore[no-untyped-call]
    jsonschema.Draft202012Validator, {"pattern": _pattern}
)


@lru_cache(maxsize=1)
def _validator() -> Any:
    return _Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def block_digest(block: dict[str, Any]) -> str:
    """SHA-256 over the RFC 8785 form of the whole block, sig included."""
    return "sha256:" + hashlib.sha256(_canonical_bytes(block)).hexdigest()


def _signing_bytes(block: dict[str, Any]) -> bytes:
    return _canonical_bytes({k: v for k, v in block.items() if k != "sig"})


def sign_block(block: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """Return a copy of *block* with ``sig`` set by *key*."""
    if not isinstance(block, dict):
        raise ValueError(f"block must be a JSON object, got {type(block).__name__}")
    unsigned = {k: copy.deepcopy(v) for k, v in block.items() if k != "sig"}
    value = base64.urlsafe_b64encode(key.sign(_signing_bytes(unsigned))).rstrip(b"=").decode()
    return {
        **unsigned,
        "sig": {"alg": "Ed25519", "kid": jwk_thumbprint(key_to_jwk(key)), "value": value},
    }


def _pinned_index(pinned_keys: Any) -> dict[str, dict[str, dict[str, Any]]]:
    """Map edge -> kid -> JWK. Rejects a malformed key set up front."""
    if not isinstance(pinned_keys, dict):
        raise ValueError("pinned_keys must map an edge name to a list of JWKs")
    index: dict[str, dict[str, dict[str, Any]]] = {}
    for edge, jwks in pinned_keys.items():
        if not isinstance(edge, str) or not isinstance(jwks, list):
            raise ValueError("pinned_keys must map an edge name to a list of JWKs")
        index[edge] = {}
        for jwk in jwks:
            _pubkey_from_jwk(jwk)  # refuses non-Ed25519 and private keys
            index[edge][jwk_thumbprint(jwk)] = jwk
    return index


def _block_code(block: Any, pinned: dict[str, dict[str, dict[str, Any]]]) -> str | None:
    """The first per-block failure, or None if the block verifies."""
    try:
        if not _validator().is_valid(block):
            return "schema_invalid"
        signed = _signing_bytes(block)
    except (rfc8785.CanonicalizationError, RecursionError):
        return "schema_invalid"
    jwk = pinned.get(block["edge"], {}).get(block["sig"]["kid"])
    if jwk is None:
        return "key_not_pinned"
    try:
        raw = _b64url_decode(block["sig"]["value"], field="sig.value")
        _pubkey_from_jwk(jwk).verify(raw, signed)
    except (InvalidSignature, ValueError):
        return "signature_invalid"
    return None


def verify_run(blocks: Any, pinned_keys: Any) -> dict[str, Any]:
    """Verify the blocks of one run.

    Returns ``{"classification": "verified" | "truncated" | "rejected", "codes": [...]}``.
    """
    if not isinstance(blocks, list):
        raise ValueError("blocks must be a list")
    pinned = _pinned_index(pinned_keys)

    codes = {code for block in blocks if (code := _block_code(block, pinned))}
    if codes:
        return _result(codes, ended=False)

    digests = [block_digest(b) for b in blocks]
    by_digest = dict(zip(digests, blocks, strict=True))

    starts = [i for i, b in enumerate(blocks) if b["kind"] == "run_start"]
    if len(starts) != 1 or blocks[starts[0]]["edge"] != "wrapper" or blocks[starts[0]]["seq"] != 0:
        return _result({"run_start_invalid"}, ended=False)
    run_id = digests[starts[0]]

    if any(b.get("run_id", run_id) != run_id for b in blocks):
        codes.add("run_id_mismatch")

    chains: dict[str, dict[int, list[int]]] = defaultdict(lambda: defaultdict(list))
    for i, b in enumerate(blocks):
        chains[b["edge"]][b["seq"]].append(i)

    for edge, by_seq in chains.items():
        if any(len(idx) > 1 for idx in by_seq.values()):
            codes.add("fork")
        if sorted(by_seq) != list(range(len(by_seq))):
            codes.add("chain_gap")
        for seq, idx in by_seq.items():
            for i in idx:
                if seq == 0:
                    want = None if edge == "wrapper" else run_id
                elif len(by_seq.get(seq - 1, [])) == 1:
                    want = digests[by_seq[seq - 1][0]]
                else:
                    continue  # gap or fork already reported
                if blocks[i]["prev"] != want:
                    codes.add("chain_link_broken")

    for b in blocks:
        if any(p not in by_digest for p in b["parents"]):
            codes.add("parent_missing")
        if b["kind"] == "heartbeat":
            for edge, d in b["body"]["peers"].items():
                if d not in by_digest or by_digest[d]["edge"] != edge:
                    codes.add("heartbeat_peer_unknown")

    ends = [b for b in blocks if b["kind"] == "run_end"]
    wrapper_last = max(chains["wrapper"])
    if len(ends) > 1 or any(e["edge"] != "wrapper" or e["seq"] != wrapper_last for e in ends):
        codes.add("block_after_end")

    return _result(codes, ended=bool(ends))


def _result(codes: set[str], *, ended: bool) -> dict[str, Any]:
    if codes:
        return {"classification": "rejected", "codes": sorted(codes)}
    return {"classification": "verified" if ended else "truncated", "codes": []}

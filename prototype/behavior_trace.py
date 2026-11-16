"""Reference code for behavior-trace blocks (docs/rfcs/behavior-trace.md).

Experimental. Builds, signs and verifies blocks, and verifies a whole run.

Bad configuration (``pinned_keys``, a non-list ``blocks``) raises ValueError.
Bad blocks never raise: they are reported as codes in the result.
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
MAX_BLOCKS = 100_000
SCHEMA_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "schema"
    / "behavior-trace-block-experimental-v1.json"
)

EDGES = ("wrapper", "model-gateway", "cmcp", "egress-proxy", "sandbox", "ca2a")

BLOCK_CODES = ("schema_invalid", "key_not_pinned", "signature_invalid", "provenance_path_invalid")
RUN_CODES = (
    "duplicate_block",
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
        if edge not in EDGES or not isinstance(jwks, list):
            raise ValueError(f"pinned_keys must map an edge name in {EDGES} to a list of JWKs")
        index[edge] = {}
        for jwk in jwks:
            _pubkey_from_jwk(jwk)  # refuses non-Ed25519 and private keys
            index[edge][jwk_thumbprint(jwk)] = jwk
    return index


_INDEX = re.compile(r"(0|[1-9][0-9]*)\Z")
# A longer index names nothing in any list, so it is refused without int(),
# whose limit on digits depends on how the interpreter is configured.
_MAX_INDEX_DIGITS = 15


def _resolves(block: dict[str, Any], pointer: str) -> bool:
    """True if the RFC 6901 pointer names a leaf value (not an object or array).

    The schema already holds every pointer to start with /body.
    """
    tokens = [t.replace("~1", "/").replace("~0", "~") for t in pointer.split("/")[1:]]
    node: Any = block
    for token in tokens:
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif (
            isinstance(node, list)
            and _INDEX.match(token)
            and len(token) <= _MAX_INDEX_DIGITS
            and int(token) < len(node)
        ):
            node = node[int(token)]
        else:
            return False
    return not isinstance(node, (dict, list))


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
    if not all(_resolves(block, path) for path in block.get("provenance", {})):
        return "provenance_path_invalid"
    return None


def verify_run(
    blocks: Any, pinned_keys: Any, *, max_blocks: int | None = MAX_BLOCKS
) -> dict[str, Any]:
    """Verify the blocks of one run.

    Returns ``{"classification": "verified" | "truncated" | "rejected", "codes": [...]}``.

    ``verified`` means every block is authentic and correctly linked and the run is
    closed by a run_end. It does not mean the record is complete: an edge can stop
    writing, and a chain cannot show blocks that were never written.

    Cost grows with the total size of the input. More than ``max_blocks`` blocks
    raises ValueError; pass None to lift the limit. Bound the input's size in
    bytes before parsing it.
    """
    if not isinstance(blocks, list):
        raise ValueError("blocks must be a list")
    if max_blocks is not None and (
        isinstance(max_blocks, bool) or not isinstance(max_blocks, int) or max_blocks < 0
    ):
        raise ValueError("max_blocks must be a non-negative integer or None")
    if max_blocks is not None and len(blocks) > max_blocks:
        raise ValueError(f"{len(blocks)} blocks is more than max_blocks={max_blocks}")
    pinned = _pinned_index(pinned_keys)

    codes = {code for block in blocks if (code := _block_code(block, pinned))}
    if codes:
        return _result(codes, ended=False)

    # The same block twice is reported once, then dropped, so `fork` below only
    # ever means two different blocks in one position.
    by_digest: dict[str, dict[str, Any]] = {}
    for block in blocks:
        d = block_digest(block)
        if d in by_digest:
            codes.add("duplicate_block")
        by_digest.setdefault(d, block)
    digests = list(by_digest)
    blocks = list(by_digest.values())

    starts = [i for i, b in enumerate(blocks) if b["kind"] == "run_start"]
    if len(starts) != 1 or blocks[starts[0]]["edge"] != "wrapper" or blocks[starts[0]]["seq"] != 0:
        return _result(codes | {"run_start_invalid"}, ended=False)
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

    # A run_end must be the one block at the end of the wrapper chain, and no
    # block may name it as a parent: a parent link means "happened before".
    # A heartbeat may still name it as a peer, recording that its edge saw the end.
    ends = [i for i, b in enumerate(blocks) if b["kind"] == "run_end"]
    wrapper = chains.get("wrapper", {})
    terminal = wrapper[max(wrapper)] if wrapper else []
    end_digests = {digests[i] for i in ends}
    # Two run_ends can never both be the one terminal block, so a second one is
    # caught here too.
    if any(terminal != [i] for i in ends) or any(
        end_digests.intersection(b["parents"]) for b in blocks
    ):
        codes.add("block_after_end")

    return _result(codes, ended=bool(ends))


def _result(codes: set[str], *, ended: bool) -> dict[str, Any]:
    if codes:
        return {"classification": "rejected", "codes": sorted(codes)}
    return {"classification": "verified" if ended else "truncated", "codes": []}

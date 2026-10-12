"""RFC 9162 inclusion-proof verification for TRACE anchor receipts.

Standard library only, and deliberately self-contained so it can be audited or
reimplemented in isolation. This is the same algorithm as
``tools/verify_inclusion.py`` in ``agentrust-io/trace-registry``, ported here so
the conformance suite can check an anchor offline rather than trusting a URI.

**On canonicalisation.** The leaf pre-image is sorted-key ASCII JSON, not
RFC 8785 JCS. That is not an oversight and must not be "fixed": TRACE uses two
canonicalisations by design, JCS for the signature pre-image and sorted-key
ASCII for the anchor leaf, specified in ``registry-anchor-v1.md`` section 0. A
verifier that used JCS here would recompute a different leaf and reject every
genuine proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")  # fullmatch: $ admits a trailing newline

__all__ = ["InclusionError", "canonical_claim_bytes", "decode_hash", "verify_inclusion"]


class InclusionError(ValueError):
    """The receipt is malformed, as opposed to proving nothing."""


_SAFE_INT = 2**53 - 1


def _outside_profile(value: Any) -> str | None:
    """Name the first value registry-anchor-v1 section 1 excludes, or None.

    Non-integer numbers (NaN and the infinities among them) and integers outside
    -(2**53 - 1) to 2**53 - 1 are outside the anchor-leaf profile: two
    implementations of the four serialization rules write different bytes for
    them, so a proof over them only proves what Python's ``json.dumps`` wrote.
    Iterative, because the claim is attacker-controlled and may be deep.
    """
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, bool) or v is None or isinstance(v, str):
            continue
        if isinstance(v, int):
            if not -_SAFE_INT <= v <= _SAFE_INT:
                return f"integer {v} is outside the safe-integer range"
        elif isinstance(v, float):
            return f"non-integer number {v!r}"
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return None


def canonical_claim_bytes(claim: dict[str, Any]) -> bytes:
    """Canonical anchor-leaf JSON bytes of the complete signed claim."""
    if not isinstance(claim, dict):
        raise InclusionError("claim must be a JSON object")
    excluded = _outside_profile(claim)
    if excluded is not None:
        raise InclusionError(
            f"claim is outside the anchor-leaf profile (registry-anchor-v1 section 1): {excluded}"
        )
    return json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def decode_hash(value: object) -> bytes:
    """Decode ``sha256:<64 lowercase hex>`` to 32 raw bytes."""
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise InclusionError(f"malformed hash value: {value!r}")
    return bytes.fromhex(value.split(":", 1)[1])


def verify_inclusion(
    claim: dict[str, Any],
    leaf_index: int,
    audit_path: list[bytes],
    leaf_count: int,
    merkle_root: bytes,
) -> bool:
    """Return True iff *claim*'s leaf is proven included under *merkle_root*.

    RFC 9162 section 2.1.3.2 inclusion-proof verification over an RFC 6962 tree.
    """
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        return False
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool):
        return False
    if leaf_index < 0 or leaf_count < 1 or leaf_index >= leaf_count:
        return False

    r = hashlib.sha256(LEAF_PREFIX + canonical_claim_bytes(claim)).digest()
    fn, sn = leaf_index, leaf_count - 1

    for p in audit_path:
        if sn == 0:
            return False  # path longer than the tree height
        if fn & 1 or fn == sn:
            r = hashlib.sha256(NODE_PREFIX + p + r).digest()
            if not fn & 1:
                # Right edge: skip levels whose ancestor was promoted unpaired.
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(NODE_PREFIX + r + p).digest()
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == merkle_root


def parse_receipt(receipt: object) -> tuple[int, list[bytes], int, bytes]:
    """Validate a receipt object and return (leaf_index, audit_path, leaf_count, merkle_root).

    Raises InclusionError with a specific reason rather than returning a bare
    False, so a malformed receipt and a receipt that proves nothing are
    reported differently.
    """
    if not isinstance(receipt, dict):
        raise InclusionError(f"receipt must be a JSON object, got {type(receipt).__name__}")

    missing = [k for k in ("leaf_index", "audit_path", "leaf_count", "merkle_root") if k not in receipt]
    if missing:
        raise InclusionError(f"receipt is missing required field(s): {', '.join(missing)}")

    raw_path = receipt["audit_path"]
    if not isinstance(raw_path, list):
        raise InclusionError(f"audit_path must be an array, got {type(raw_path).__name__}")

    return (
        receipt["leaf_index"],
        [decode_hash(node) for node in raw_path],
        receipt["leaf_count"],
        decode_hash(receipt["merkle_root"]),
    )

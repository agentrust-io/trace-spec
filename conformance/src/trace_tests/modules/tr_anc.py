"""TR-ANC: Transparency anchoring checks (spec section 3.2)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from trace_tests.inclusion import InclusionError, parse_receipt, verify_inclusion
from trace_tests.result import Finding, Status


def check(trace: dict[str, Any], receipt: dict[str, Any] | None = None) -> list[Finding]:
    """Return TR-ANC findings for the transparency claim.

    TR-ANC-001 checks the shape of the ``transparency`` URI. TR-ANC-002 checks
    that the record is actually anchored, by replaying the inclusion proof in
    *receipt* against the committed Merkle root. Without a receipt there is
    nothing to replay, and TR-ANC-002 fails: Level 2 means anchored, and a URI
    is a pointer at an anchor rather than evidence of one.
    """
    findings: list[Finding] = []
    transparency = trace.get("transparency")

    if not transparency:
        return [Finding("TR-ANC-001", Status.FAIL, "TR-ANC-001: transparency field is required at Level 2")]

    if not isinstance(transparency, str):
        return [Finding("TR-ANC-001", Status.FAIL, f"TR-ANC-001: transparency must be a string URI, got {type(transparency).__name__}")]

    try:
        parsed = urlparse(transparency)
    except Exception as exc:
        return [Finding("TR-ANC-001", Status.FAIL, f"TR-ANC-001: could not parse transparency URI: {exc}")]

    if parsed.scheme != "https" or not parsed.netloc:
        return [Finding(
            "TR-ANC-001", Status.FAIL,
            f"TR-ANC-001: transparency must be an https URI, got scheme={parsed.scheme!r}",
        )]

    findings.append(Finding(
        "TR-ANC-001", Status.PASS,
        f"transparency is a well-formed https URI ({transparency[:80]}); "
        "this checks the pointer, not the anchor (see TR-ANC-002)",
    ))
    findings.append(_check_inclusion(trace, receipt))
    return findings


def _check_inclusion(trace: dict[str, Any], receipt: dict[str, Any] | None) -> Finding:
    """Replay the inclusion proof, or say why it could not be replayed."""
    if receipt is None:
        return Finding(
            "TR-ANC-002", Status.FAIL,
            "TR-ANC-002: no anchor receipt supplied, so inclusion was not proven. "
            "The transparency URI names where the anchor lives; it is not evidence "
            "the record is in it. Pass the receipt with --receipt.",
        )

    try:
        leaf_index, audit_path, leaf_count, merkle_root = parse_receipt(receipt)
    except InclusionError as exc:
        return Finding("TR-ANC-002", Status.FAIL, f"TR-ANC-002: malformed anchor receipt: {exc}")

    try:
        proven = verify_inclusion(trace, leaf_index, audit_path, leaf_count, merkle_root)
    except InclusionError as exc:
        return Finding("TR-ANC-002", Status.FAIL, f"TR-ANC-002: could not verify inclusion: {exc}")

    if proven:
        return Finding(
            "TR-ANC-002", Status.PASS,
            f"inclusion proven against merkle_root {merkle_root.hex()[:16]}... "
            f"(leaf {leaf_index} of {leaf_count})",
        )
    return Finding(
        "TR-ANC-002", Status.FAIL,
        f"TR-ANC-002: inclusion proof does not reproduce the committed merkle_root "
        f"(leaf {leaf_index} of {leaf_count}). The record is not in the tree this "
        "receipt commits to, or it has been modified since it was anchored.",
    )

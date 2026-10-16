"""TR-ANC: Transparency anchoring checks (spec section 3.2)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from trace_tests.inclusion import InclusionError, parse_entry, parse_proof, verify_inclusion
from trace_tests.result import Finding, Status


def check(
    trace: dict[str, Any],
    receipt: dict[str, Any] | None = None,
    entry: dict[str, Any] | None = None,
) -> list[Finding]:
    """Return TR-ANC findings for the transparency claim.

    TR-ANC-001 checks the shape of the ``transparency`` URI. TR-ANC-002 checks
    that the record is actually anchored: the inclusion proof in *receipt*
    (``leaf_index`` and ``audit_path``, registry-anchor-v1 section 5) must replay
    to the ``merkle_root`` and ``leaf_count`` of the registry *entry* (section 4),
    which section 5.1 takes as its third input. A receipt that also carries its
    own ``merkle_root`` or ``leaf_count`` must carry the entry's (section 6).
    Without a receipt or without the entry, TR-ANC-002 fails: Level 2 means
    anchored in a named entry, and a URI is a pointer at an anchor rather than
    evidence of one. Nothing yet ties the URI to the entry (trace-spec#448
    finding 21), and the TR-ANC-002 message says so.
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
    findings.append(_check_inclusion(trace, receipt, entry))
    return findings


def _check_inclusion(
    trace: dict[str, Any],
    receipt: dict[str, Any] | None,
    entry: dict[str, Any] | None,
) -> Finding:
    """Bind the receipt to the entry and replay the proof, or say why not."""
    if receipt is None:
        return Finding(
            "TR-ANC-002", Status.FAIL,
            "TR-ANC-002: no anchor receipt supplied, so inclusion was not proven. "
            "The transparency URI names where the anchor lives; it is not evidence "
            "the record is in it. Pass the receipt with --receipt.",
        )

    try:
        leaf_index, audit_path, leaf_count, merkle_root = parse_proof(receipt)
    except InclusionError as exc:
        return Finding("TR-ANC-002", Status.FAIL, f"TR-ANC-002: malformed anchor receipt: {exc}")

    if entry is None:
        return Finding(
            "TR-ANC-002", Status.FAIL,
            "TR-ANC-002: no registry entry supplied, so the receipt's merkle_root and "
            "leaf_count were not shown to belong to any entry and Level 2 is not earned. "
            "Pass the registry-anchor-v1 section 4 entry with --entry.",
        )

    try:
        entry_root, entry_count, producer, batch_id = parse_entry(entry)
    except InclusionError as exc:
        return Finding("TR-ANC-002", Status.FAIL, f"TR-ANC-002: malformed registry entry: {exc}")

    if merkle_root is not None and merkle_root != entry_root:
        return Finding(
            "TR-ANC-002", Status.FAIL,
            f"TR-ANC-002: receipt merkle_root {merkle_root.hex()[:16]}... does not equal "
            f"the merkle_root of registry entry {producer} {batch_id} "
            f"({entry_root.hex()[:16]}...). The receipt does not describe that entry.",
        )

    if leaf_count is not None and leaf_count != entry_count:
        return Finding(
            "TR-ANC-002", Status.FAIL,
            f"TR-ANC-002: receipt leaf_count {leaf_count!r} does not equal the leaf_count "
            f"of registry entry {producer} {batch_id} ({entry_count}). The receipt does "
            "not describe that entry.",
        )

    try:
        proven = verify_inclusion(trace, leaf_index, audit_path, entry_count, entry_root)
    except InclusionError as exc:
        return Finding("TR-ANC-002", Status.FAIL, f"TR-ANC-002: could not verify inclusion: {exc}")

    if proven:
        return Finding(
            "TR-ANC-002", Status.PASS,
            f"inclusion proven against merkle_root {entry_root.hex()[:16]}... "
            f"(leaf {leaf_index} of {entry_count}) of registry entry {producer} {batch_id}; "
            "the link from the transparency URI to this entry is not checked "
            "(trace-spec#448 finding 21)",
        )
    return Finding(
        "TR-ANC-002", Status.FAIL,
        f"TR-ANC-002: inclusion proof does not reproduce the committed merkle_root "
        f"(leaf {leaf_index} of {entry_count}). The record is not in the tree this "
        "receipt commits to, or it has been modified since it was anchored.",
    )

"""TR-ANC: Transparency anchoring checks (spec section 3.2)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from trace_tests.inclusion import (
    InclusionError,
    entry_uri,
    parse_entry,
    parse_proof,
    verify_inclusion,
)
from trace_tests.loader import LoadError, loads_strict
from trace_tests.result import Finding, Status

from ._https_uri import valid_https_uri


def check(
    trace: dict[str, Any],
    receipt: dict[str, Any] | None = None,
    entry: dict[str, Any] | None = None,
    subject: dict[str, Any] | None = None,
    entry_resolver: Callable[[str], bytes] | None = None,
    entry_source_authenticated: bool = False,
) -> list[Finding]:
    """Return TR-ANC findings for the transparency claim.

    *subject* is the object the anchor leaf commits to: the complete signed
    claim, signature included (registry-anchor-v1 section 1). For an enveloping
    format such as ``cmcp-runtime`` that is the whole envelope, not the nested
    *trace*; the runner passes it. It defaults to *trace*, which is the complete
    claim for a bare TRACE record.

    TR-ANC-001 checks the shape of the ``transparency`` URI. TR-ANC-002 resolves
    that exact signed URI through a verifier-controlled resolver, checks the
    resolved entry's ``log_id`` and ``entry_id``, and then checks that the record
    is actually anchored: the inclusion proof in *receipt*
    (``leaf_index`` and ``audit_path``, registry-anchor-v1 section 5) must replay
    to the ``merkle_root`` and ``leaf_count`` of the registry *entry* (section 4),
    which section 5.1 takes as its third input. A receipt that also carries its
    own ``merkle_root`` or ``leaf_count`` must carry the entry's (section 6).
    Without a receipt or resolved entry, TR-ANC-002 cannot pass: Level 2 means
    anchored in the exact signed entry, and a URI or presenter-supplied entry is
    not evidence that the named log published it. The caller must set
    *entry_source_authenticated* only after independently authenticating the
    resolver's source. An arbitrary local URI-to-file map does not do so.
    """
    findings: list[Finding] = []
    transparency = trace.get("transparency")

    if not transparency:
        return [
            Finding(
                "TR-ANC-001",
                Status.FAIL,
                "TR-ANC-001: transparency field is required at Level 2",
            )
        ]

    if not isinstance(transparency, str):
        return [
            Finding(
                "TR-ANC-001",
                Status.FAIL,
                f"TR-ANC-001: transparency must be a string URI, got {type(transparency).__name__}",
            )
        ]

    try:
        urlparse(transparency)
    except Exception as exc:
        return [Finding(
            "TR-ANC-001", Status.FAIL,
            f"TR-ANC-001: could not parse transparency URI: {exc}",
        )]

    if not valid_https_uri(transparency):
        return [
            Finding(
                "TR-ANC-001",
                Status.FAIL,
                "TR-ANC-001: transparency must be a valid https URI without whitespace or "
                f"control characters, got {transparency!r}",
            )
        ]

    findings.append(Finding(
        "TR-ANC-001", Status.PASS,
        f"transparency is a well-formed https URI ({transparency[:80]}); "
        "TR-ANC-002 checks entry identity, source authentication, and inclusion",
    ))
    resolved_entry, resolution_finding = _resolve_entry(transparency, entry_resolver)
    if resolution_finding is not None:
        findings.append(resolution_finding)
        return findings

    selected_entry = resolved_entry if resolved_entry is not None else entry
    if resolved_entry is not None:
        try:
            _, _, _, _, log_id, entry_id = parse_entry(resolved_entry)
            named_uri = entry_uri(log_id, entry_id)
        except InclusionError as exc:
            findings.append(
                Finding("TR-ANC-002", Status.FAIL, f"TR-ANC-002: malformed resolved entry: {exc}")
            )
            return findings
        if named_uri != transparency:
            findings.append(Finding(
                "TR-ANC-002",
                Status.FAIL,
                f"TR-ANC-002: signed transparency URI {transparency!r} does not equal "
                f"the resolved entry identity {named_uri!r}; the entry is from another "
                "log or checkpoint",
            ))
            return findings

    inclusion = _check_inclusion(
        trace if subject is None else subject,
        receipt,
        selected_entry,
    )
    if inclusion.status is Status.PASS:
        if resolved_entry is None:
            inclusion = Finding(
                "TR-ANC-002",
                Status.UNVERIFIED,
                "TR-ANC-002: inclusion is valid against the supplied entry, but the exact signed "
                "transparency URI was not resolved through the named log or an authenticated "
                "mirror; a presenter-supplied entry cannot earn Level 2",
            )
        elif entry_source_authenticated is not True:
            inclusion = Finding(
                "TR-ANC-002",
                Status.UNVERIFIED,
                "TR-ANC-002: inclusion and signed entry identity match, but the "
                "resolver's source was not independently authenticated; "
                "a local entry map alone cannot earn Level 2",
            )
        else:
            inclusion = Finding(
                "TR-ANC-002",
                Status.PASS,
                f"{inclusion.message}; the signed transparency URI resolved to this exact log "
                "entry",
            )
    findings.append(inclusion)
    return findings


def _resolve_entry(
    transparency: str,
    resolver: Callable[[str], bytes] | None,
) -> tuple[dict[str, Any] | None, Finding | None]:
    """Resolve the exact signed entry URI, separating absence from malformed evidence."""
    if resolver is None:
        return None, None
    try:
        raw = resolver(transparency)
    except Exception as exc:  # resolver failures are evidence-reachability failures
        return None, Finding(
            "TR-ANC-002",
            Status.UNVERIFIED,
            f"TR-ANC-002: could not resolve the signed transparency URI through the "
            f"verifier's entry resolver: {type(exc).__name__}: {exc}",
        )
    try:
        resolved = loads_strict(raw)
    except LoadError as exc:
        return None, Finding(
            "TR-ANC-002", Status.FAIL,
            f"TR-ANC-002: the signed transparency URI resolved to malformed JSON: {exc}",
        )
    if not isinstance(resolved, dict):
        return None, Finding(
            "TR-ANC-002", Status.FAIL,
            "TR-ANC-002: the signed transparency URI must resolve to one registry entry object, "
            f"got {type(resolved).__name__}",
        )
    return resolved, None


def _check_inclusion(
    subject: dict[str, Any],
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
        entry_root, entry_count, producer, batch_id, _, _ = parse_entry(entry)
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
        proven = verify_inclusion(subject, leaf_index, audit_path, entry_count, entry_root)
    except InclusionError as exc:
        return Finding("TR-ANC-002", Status.FAIL, f"TR-ANC-002: could not verify inclusion: {exc}")

    if proven:
        return Finding(
            "TR-ANC-002", Status.PASS,
            f"inclusion proven against merkle_root {entry_root.hex()[:16]}... "
            f"(leaf {leaf_index} of {entry_count}) of registry entry {producer} {batch_id}, "
            "over the complete signed claim",
        )
    return Finding(
        "TR-ANC-002", Status.FAIL,
        f"TR-ANC-002: inclusion proof does not reproduce the committed merkle_root "
        f"(leaf {leaf_index} of {entry_count}). The record is not in the tree this "
        "receipt commits to, or it has been modified since it was anchored.",
    )

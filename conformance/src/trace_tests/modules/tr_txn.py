"""TR-TXN: Tool-call transcript checks (spec §3.1, Phase 2+ records)."""

from __future__ import annotations

import re
from typing import Any

from trace_tests.result import Finding, Status

# Byte-equal to the schema pattern (test_digest_parity) and always applied with
# fullmatch: Python's $ also matches before a trailing newline, ECMA-262's does not.
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")


def check(trace: dict[str, Any]) -> list[Finding]:
    """Return TR-TXN findings for the tool transcript claim."""
    findings: list[Finding] = []
    txn = trace.get("tool_transcript")

    if txn is None:
        return [Finding("TR-TXN-001", Status.FAIL, "TR-TXN-001: tool_transcript is required at Level 2")]

    if not isinstance(txn, dict):
        return [Finding("TR-TXN-001", Status.FAIL, "TR-TXN-001: tool_transcript must be an object")]

    h = txn.get("hash", "")
    if _DIGEST_RE.fullmatch(str(h)):
        findings.append(Finding("TR-TXN-001", Status.PASS, "tool_transcript.hash has valid digest format"))
    else:
        findings.append(Finding(
            "TR-TXN-001", Status.FAIL,
            f"TR-TXN-001: tool_transcript.hash must match sha256:<64hex> or sha384:<96hex>, got {h!r}",
        ))

    call_count = txn.get("call_count")
    if call_count is None:
        findings.append(Finding("TR-TXN-002", Status.SKIP, "tool_transcript.call_count not present (optional)"))
    # bool is an int subclass, so True would otherwise report as a call count of
    # one and False as zero. A record that says true here is malformed, and a
    # conformance suite that silently reads it as a number is answering a
    # question nobody asked.
    elif isinstance(call_count, int) and not isinstance(call_count, bool) and call_count >= 0:
        findings.append(Finding("TR-TXN-002", Status.PASS, f"tool_transcript.call_count is non-negative ({call_count})"))
    else:
        findings.append(Finding(
            "TR-TXN-002", Status.FAIL,
            f"TR-TXN-002: tool_transcript.call_count must be a non-negative integer, got {call_count!r}",
        ))

    return findings

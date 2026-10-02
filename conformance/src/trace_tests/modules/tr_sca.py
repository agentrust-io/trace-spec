"""TR-SCA: Supply-chain provenance checks (spec §3.1)."""

from __future__ import annotations

import re
from typing import Any

from trace_tests.accounting import (
    BranchRule,
    ObligationSpec,
    ProducerRole,
    _checker_binding,
    _normative_sources,
    _observe,
)
from trace_tests.result import Finding, Status

# Byte-equal to the schema pattern (test_digest_parity) and always applied with
# fullmatch: Python's $ also matches before a trailing newline, ECMA-262's does not.
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")
_SLSA_LEVELS = frozenset({0,1, 2, 3})

_ACCOUNTING_SPEC = ObligationSpec(
    "TR-SCA-002",
    "TR-SCA",
    _normative_sources(
        "/required/7",
        "/properties/build_provenance/type",
        "/properties/build_provenance/required/1",
        "/properties/build_provenance/properties/digest/pattern",
    ),
    _checker_binding("TR-SCA"),
    (
        BranchRule(
            "build_provenance_missing",
            ProducerRole.PREREQUISITE,
            prerequisite_code="TR-SCA-001",
            prerequisite_statuses=(Status.FAIL,),
            prerequisite_message_prefix="TR-SCA-001: build_provenance is required",
        ),
        BranchRule(
            "build_provenance_not_object",
            ProducerRole.PREREQUISITE,
            prerequisite_code="TR-SCA-001",
            prerequisite_statuses=(Status.FAIL,),
            prerequisite_message_prefix="TR-SCA-001: build_provenance must be an object",
        ),
        BranchRule("digest_valid", ProducerRole.TARGET_COMPLETED, "TR-SCA-002", (Status.PASS,)),
        BranchRule("digest_invalid", ProducerRole.TARGET_COMPLETED, "TR-SCA-002", (Status.FAIL,)),
        BranchRule("level0_scheduler_nonexecution", ProducerRole.SCHEDULER_NONEXECUTION_APPLICABLE),
    ),
)


def check(trace: dict[str, Any]) -> list[Finding]:
    """Return TR-SCA findings for the build provenance claim."""
    findings: list[Finding] = []
    prov = trace.get("build_provenance")

    if prov is None:
        _observe("TR-SCA", "build_provenance_missing")
        return [Finding("TR-SCA-001", Status.FAIL, "TR-SCA-001: build_provenance is required at Level 1+")]

    if not isinstance(prov, dict):
        _observe("TR-SCA", "build_provenance_not_object")
        return [Finding("TR-SCA-001", Status.FAIL, "TR-SCA-001: build_provenance must be an object")]

    slsa_level = prov.get("slsa_level")
    # JSON booleans are not integers, although Python makes bool an int subclass.
    # JSON Schema does admit 1.0 as an integer, so numeric membership remains valid
    # after booleans are excluded explicitly.
    if (
        isinstance(slsa_level, (int, float))
        and not isinstance(slsa_level, bool)
        and slsa_level in _SLSA_LEVELS
    ):
        findings.append(Finding("TR-SCA-001", Status.PASS, f"build_provenance.slsa_level is valid ({slsa_level})"))
    else:
        findings.append(Finding(
            "TR-SCA-001", Status.FAIL,
            f"TR-SCA-001: build_provenance.slsa_level must be 0,1, 2, or 3, got {slsa_level!r}",
        ))

    digest = prov.get("digest", "")
    if _DIGEST_RE.fullmatch(str(digest)):
        findings.append(_observe(
            "TR-SCA", "digest_valid",
            Finding(
                "TR-SCA-002", Status.PASS,
                "build_provenance.digest has valid digest format",
            ),
        ))
    else:
        findings.append(_observe(
            "TR-SCA", "digest_invalid",
            Finding(
                "TR-SCA-002", Status.FAIL,
                "TR-SCA-002: build_provenance.digest must match sha256:<64hex> or "
                f"sha384:<96hex>, got {digest!r}",
            ),
        ))

    return findings

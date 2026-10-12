"""TR-APR: Evidence appraisal checks (spec §3.1).

Well-formedness only. TR-APR never resolves anything: it performs no network
access, no filesystem access, and takes no resolver. `appraisal.policy_ref`
names the appraisal policy and this module checks the *shape* of that name;
resolving the enforced bundle at `policy.policy_uri` against
`policy.bundle_hash` is TR-POL-003's business. Two fields, two objects, no
overlapping assertion.

Every code here emits PASS, FAIL or SKIP and never UNVERIFIED, so none of them
appears in `unverified.UNVERIFIED_FAILS_FROM_LEVEL`. That absence is a decision
rather than an oversight: UNVERIFIED means a check could not be executed
against the evidence the record cites, and nothing here has a referent to lose.
With no resolver and no remote object, every predicate is a total function of
the record, the level and the clock.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlsplit

from trace_tests.accounting import (
    BranchRule,
    ObligationSpec,
    ProducerRole,
    _checker_binding,
    _normative_sources,
    _observe,
)
from trace_tests.result import Finding, Status

#: Mirrors `appraisal.status` in the packaged schema; `test_enum_parity` fails if
#: it drifts from that copy.
_VALID_STATUS = frozenset({"affirming", "warning", "contraindicated", "none"})
#: RFC 3986 scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*$")
#: Clock skew tolerated when deciding an appraisal timestamp is in the future.
#: Held equal to the tolerance TR-ENV-002 applies to a future `iat` at
#: `tr_env.py:36`, which is likewise an inline literal rather than a named
#: constant; `test_tr_apr` asserts the two stay equal.
_MAX_FUTURE_SKEW_SECONDS = 60

_ACCOUNTING_SPEC = ObligationSpec(
    "TR-APR-001",
    "TR-APR",
    _normative_sources(
        "/required/8",
        "/properties/appraisal/type",
        "/properties/appraisal/required/0",
        "/properties/appraisal/properties/status/enum",
    ),
    _checker_binding("TR-APR"),
    (
        BranchRule(
            "appraisal_missing", ProducerRole.TARGET_COMPLETED, "TR-APR-001", (Status.FAIL,)
        ),
        BranchRule(
            "appraisal_not_object", ProducerRole.TARGET_COMPLETED, "TR-APR-001", (Status.FAIL,)
        ),
        BranchRule("status_valid", ProducerRole.TARGET_COMPLETED, "TR-APR-001", (Status.PASS,)),
        BranchRule("status_invalid", ProducerRole.TARGET_COMPLETED, "TR-APR-001", (Status.FAIL,)),
    ),
)


def _not_absolute_uri(value: str) -> str | None:
    """Say why *value* is not an absolute URI, or None when it is one.

    Duplicated deliberately from `tr_pol._not_absolute_uri` rather than
    imported: no module in this tree imports another, and a cross-module import
    would be a structural change this module has no mandate to make. The twins
    are held behaviourally equal by a parity test, in the same spirit as
    `test_enum_parity` holding the hand-written enums equal to the schema.

    Two rules, kept apart because they catch different mistakes. A reference
    with no scheme is a relative reference: the packaged schema asks for
    ``format: "uri"``, which is the absolute form, and a reader who writes the
    ``uri-reference`` form gets something no verifier can dereference on its
    own. A reference carrying whitespace or a control character is a
    transcription accident, and one that survives a diff unnoticed.
    """
    for ch in value:
        if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F:
            return f"contains whitespace or a control character ({ch!r})"
    try:
        scheme = urlsplit(value).scheme
    except ValueError as exc:  # pragma: no cover - urlsplit is total for str
        return f"cannot be parsed as a URI ({exc})"
    if not scheme:
        return "has no scheme, so it is a relative reference rather than an absolute URI"
    if not _SCHEME_RE.match(scheme):
        return f"has a scheme that RFC 3986 does not admit ({scheme!r})"
    return None


def _uri_finding(code: str, field: str, value: Any) -> Finding:
    """Return the PASS/FAIL finding for an absolute-URI field that is present."""
    if not isinstance(value, str):
        return Finding(
            code, Status.FAIL,
            f"{code}: appraisal.{field} must be a string, got {type(value).__name__}",
        )
    malformed = _not_absolute_uri(value)
    if malformed is not None:
        return Finding(code, Status.FAIL, f"{code}: appraisal.{field} {malformed}: {value!r}")
    return Finding(code, Status.PASS, f"appraisal.{field} is an absolute URI ({value!r})")


def _timestamp_finding(appraisal: dict[str, Any]) -> Finding:
    """Return the TR-APR-004 finding for the optional `timestamp` field.

    An appraisal produced in the future is not a stylistic defect: it is the
    record asserting something that has not happened. That is the same ground
    TR-ENV-002 stands on for `iat`, so the tolerance is the one TR-ENV-002
    applies. No staleness bound is applied in the other direction, because the
    docs state none and this module enforces only what is stated.
    """
    if "timestamp" not in appraisal:
        return Finding("TR-APR-004", Status.SKIP, "appraisal.timestamp not present (optional)")

    timestamp = appraisal.get("timestamp")
    # bool is a subclass of int; a JSON `true` is not an epoch second.
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        return Finding(
            "TR-APR-004", Status.FAIL,
            f"TR-APR-004: appraisal.timestamp must be an integer of epoch seconds, "
            f"got {type(timestamp).__name__}",
        )

    now = int(time.time())
    if timestamp > now + _MAX_FUTURE_SKEW_SECONDS:
        return Finding(
            "TR-APR-004", Status.FAIL,
            f"TR-APR-004: appraisal.timestamp {timestamp} is in the future (now={now}), so the "
            f"record asserts an appraisal that has not happened",
        )
    return Finding(
        "TR-APR-004", Status.PASS, f"appraisal.timestamp is not in the future ({timestamp})",
    )


def check(trace: dict[str, Any], level: int) -> list[Finding]:
    """Return TR-APR findings for the evidence appraisal claim.

    *level* is the conformance level being checked. TR-APR-001 through
    TR-APR-004 are structural and apply at every level; TR-APR-005 self-gates,
    because `docs/levels.md` requires an affirming appraisal from Level 1 and
    its own minimum conformant Level 0 record carries `"none"`.
    """
    appraisal = trace.get("appraisal")

    if appraisal is None:
        return [
            _observe(
                "TR-APR",
                "appraisal_missing",
                Finding("TR-APR-001", Status.FAIL, "TR-APR-001: appraisal is required"),
            )
        ]
    if not isinstance(appraisal, dict):
        return [
            _observe(
                "TR-APR",
                "appraisal_not_object",
                Finding(
                    "TR-APR-001",
                    Status.FAIL,
                    f"TR-APR-001: appraisal must be an object, got {type(appraisal).__name__}",
                ),
            )
        ]

    findings: list[Finding] = []

    status = appraisal.get("status")
    # `in` against a frozenset raises on an unhashable value, and a record is
    # not trusted to carry a hashable one; `test_modules_never_raise` fuzzes
    # this field with a list.
    if isinstance(status, str) and status in _VALID_STATUS:
        findings.append(
            _observe(
                "TR-APR",
                "status_valid",
                Finding("TR-APR-001", Status.PASS, f"appraisal.status is valid ({status!r})"),
            )
        )
    else:
        findings.append(
            _observe(
                "TR-APR",
                "status_invalid",
                Finding(
                    "TR-APR-001",
                    Status.FAIL,
                    "TR-APR-001: appraisal.status must be one of "
                    f"{sorted(_VALID_STATUS)}, got {status!r}",
                ),
            )
        )

    if "verifier" not in appraisal:
        findings.append(
            Finding("TR-APR-002", Status.FAIL, "TR-APR-002: appraisal.verifier is required")
        )
    else:
        findings.append(_uri_finding("TR-APR-002", "verifier", appraisal.get("verifier")))

    if "policy_ref" not in appraisal:
        findings.append(
            Finding("TR-APR-003", Status.SKIP, "appraisal.policy_ref not present (optional)")
        )
    else:
        findings.append(_uri_finding("TR-APR-003", "policy_ref", appraisal.get("policy_ref")))

    findings.append(_timestamp_finding(appraisal))

    if level < 1:
        findings.append(Finding(
            "TR-APR-005", Status.SKIP,
            "the affirming-appraisal requirement applies from Level 1",
        ))
    elif status == "affirming":
        findings.append(Finding(
            "TR-APR-005", Status.PASS, f"appraisal.status is affirming, as Level {level} requires",
        ))
    else:
        findings.append(Finding(
            "TR-APR-005", Status.FAIL,
            f"TR-APR-005: Level {level} requires appraisal.status 'affirming', got {status!r}",
        ))

    return findings

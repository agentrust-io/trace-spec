"""TR-POL: Policy bundle checks (spec §3.1)."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from trace_tests.accounting import (
    BranchRule,
    ObligationSpec,
    ProducerRole,
    _checker_binding,
    _normative_text_sources,
    _observe,
    _structural_sources,
)
from trace_tests.result import Finding, Status

# Byte-equal to the schema pattern (test_digest_parity) and always applied with
# fullmatch: Python's $ also matches before a trailing newline, ECMA-262's does not.
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")
#: Digest algorithms this module can compute, keyed by the prefix a record uses.
#: Kept in step with `_DIGEST_RE`: a prefix the pattern admits and this map does
#: not would be accepted by TR-POL-001 and uncomputable by TR-POL-003.
_DIGEST_ALGOS: dict[str, Any] = {"sha256:": hashlib.sha256, "sha384:": hashlib.sha384}
#: RFC 3986 scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*$")
#: Mirrors `policy.enforcement_mode` in the packaged schema; `test_enum_parity` fails if
#: it drifts from that copy.
_VALID_ENFORCEMENT = frozenset({"enforce", "advisory", "silent", "declared"})

_ACCOUNTING_SPEC = ObligationSpec(
    "TR-POL-003",
    "TR-POL",
    _normative_text_sources(
        "5. Policy hash matches the policy bundle the verifier expects.",
    ),
    _checker_binding("TR-POL"),
    (
        BranchRule(
            "policy_missing",
            ProducerRole.PREREQUISITE,
            prerequisite_code="TR-POL-001",
            prerequisite_statuses=(Status.FAIL,),
            prerequisite_message_prefix="TR-POL-001: policy field is missing",
        ),
        BranchRule(
            "policy_not_object",
            ProducerRole.PREREQUISITE,
            prerequisite_code="TR-POL-001",
            prerequisite_statuses=(Status.FAIL,),
            prerequisite_message_prefix="TR-POL-001: policy field is missing",
        ),
        BranchRule("policy_uri_absent", ProducerRole.NOT_APPLICABLE, "TR-POL-003", (Status.SKIP,)),
        BranchRule(
            "policy_uri_explicit_null",
            ProducerRole.NOT_APPLICABLE,
            "TR-POL-003",
            (Status.SKIP,),
        ),
        BranchRule(
            "policy_uri_non_string", ProducerRole.TARGET_COMPLETED, "TR-POL-003", (Status.FAIL,)
        ),
        BranchRule(
            "policy_uri_malformed", ProducerRole.TARGET_COMPLETED, "TR-POL-003", (Status.FAIL,)
        ),
        BranchRule(
            "bundle_hash_malformed",
            ProducerRole.PREREQUISITE,
            "TR-POL-003",
            (Status.SKIP,),
            "TR-POL-001",
            (Status.FAIL,),
            "TR-POL-001: policy.bundle_hash must match ",
        ),
        BranchRule("no_resolver", ProducerRole.NOT_ATTEMPTED, "TR-POL-003", (Status.SKIP,)),
        BranchRule(
            "resolver_exception",
            ProducerRole.TARGET_ATTEMPTED_UNRESOLVED,
            "TR-POL-003",
            (Status.UNVERIFIED,),
        ),
        BranchRule(
            "resolver_non_bytes",
            ProducerRole.TARGET_ATTEMPTED_UNRESOLVED,
            "TR-POL-003",
            (Status.UNVERIFIED,),
        ),
        BranchRule("resolved_match", ProducerRole.TARGET_COMPLETED, "TR-POL-003", (Status.PASS,)),
        BranchRule(
            "resolved_mismatch", ProducerRole.TARGET_COMPLETED, "TR-POL-003", (Status.FAIL,)
        ),
    ),
    _structural_sources(
        "/required/5",
        "/properties/policy/type",
        "/properties/policy/required",
        "/properties/policy/properties/bundle_hash/pattern",
        "/properties/policy/properties/policy_uri",
    ),
)


def _not_absolute_uri(policy_uri: str) -> str | None:
    """Say why *policy_uri* is not an absolute URI, or None when it is one.

    Two rules, kept apart because they catch different mistakes. A reference
    with no scheme is a relative reference: the packaged schema asks for
    ``format: "uri"``, which is the absolute form, and a reader who writes the
    ``uri-reference`` form gets something no verifier can dereference on its
    own. A reference carrying whitespace or a control character is a
    transcription accident, and one that survives a diff unnoticed.
    """
    for ch in policy_uri:
        if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F:
            return f"contains whitespace or a control character ({ch!r})"
    try:
        scheme = urlsplit(policy_uri).scheme
    except ValueError as exc:  # pragma: no cover - urlsplit is total for str
        return f"cannot be parsed as a URI ({exc})"
    if not scheme:
        return "has no scheme, so it is a relative reference rather than an absolute URI"
    if not _SCHEME_RE.match(scheme):
        return f"has a scheme that RFC 3986 does not admit ({scheme!r})"
    return None


def _resolution_finding(
    policy: dict[str, Any], policy_resolver: Callable[[str], bytes] | None
) -> Finding:
    """Return the TR-POL-003 finding for *policy*.

    The order below is the whole of the check's meaning, so it is worth stating.
    A reference the record got wrong is a defect in the record, visible with no
    network and no resolver, exactly like the digest shape TR-POL-001 tests. A
    referent that could not be fetched is weather. The malformed check therefore
    runs before the resolver is consulted: running an offline verification must
    not mean being blind to a defect the record carries on its face.
    """
    if "policy_uri" not in policy:
        return _observe(
            "TR-POL",
            "policy_uri_absent",
            Finding(
                "TR-POL-003", Status.SKIP,
                "policy.policy_uri not present (optional); no bundle to resolve",
            ),
        )
    policy_uri = policy.get("policy_uri")
    if policy_uri is None:
        return _observe(
            "TR-POL",
            "policy_uri_explicit_null",
            Finding(
                "TR-POL-003", Status.SKIP,
                "policy.policy_uri not present (optional); no bundle to resolve",
            ),
        )
    if not isinstance(policy_uri, str):
        return _observe(
            "TR-POL",
            "policy_uri_non_string",
            Finding(
                "TR-POL-003", Status.FAIL,
                f"TR-POL-003: policy.policy_uri must be a string, got {type(policy_uri).__name__}",
            ),
        )

    malformed = _not_absolute_uri(policy_uri)
    if malformed is not None:
        return _observe(
            "TR-POL",
            "policy_uri_malformed",
            Finding(
                "TR-POL-003", Status.FAIL,
                f"TR-POL-003: policy.policy_uri {malformed}: {policy_uri!r}",
            ),
        )

    bundle_hash = str(policy.get("bundle_hash", ""))
    if not _DIGEST_RE.fullmatch(bundle_hash):
        return _observe(
            "TR-POL",
            "bundle_hash_malformed",
            Finding(
                "TR-POL-003", Status.SKIP,
                "policy.bundle_hash is not a well-formed digest, so there is nothing to "
                "compare the resolved bundle against; reported by TR-POL-001",
            ),
        )

    if policy_resolver is None:
        return _observe(
            "TR-POL",
            "no_resolver",
            Finding(
                "TR-POL-003", Status.SKIP,
                "policy.policy_uri not resolved; no resolver supplied",
            ),
        )

    try:
        resolved = policy_resolver(policy_uri)
    except Exception as exc:
        # The exception text is carried deliberately. The status says only that
        # the bundle could not be read, which is the same word for a withdrawn
        # referent and a mistyped path; without the reason the second is
        # indistinguishable from weather.
        return _observe(
            "TR-POL",
            "resolver_exception",
            Finding(
                "TR-POL-003", Status.UNVERIFIED,
                f"TR-POL-003: policy.policy_uri could not be resolved, so "
                f"policy.bundle_hash was not checked against it: {policy_uri!r} "
                f"({type(exc).__name__}: {exc})",
            ),
        )

    if not isinstance(resolved, bytes):
        return _observe(
            "TR-POL",
            "resolver_non_bytes",
            Finding(
                "TR-POL-003", Status.UNVERIFIED,
                "TR-POL-003: the policy resolver violated its contract by returning "
                f"{type(resolved).__name__} rather than bytes, so policy.bundle_hash "
                f"was not checked against policy.policy_uri {policy_uri!r}",
            ),
        )

    prefix, _, _ = bundle_hash.partition(":")
    algo = _DIGEST_ALGOS[f"{prefix}:"]
    actual = f"{prefix}:{algo(resolved).hexdigest().lower()}"
    if actual == bundle_hash.lower():
        return _observe(
            "TR-POL",
            "resolved_match",
            Finding(
                "TR-POL-003", Status.PASS,
                f"policy.policy_uri resolves to the bundle policy.bundle_hash declares "
                f"({len(resolved)} bytes, {prefix})",
            ),
        )
    return _observe(
        "TR-POL",
        "resolved_mismatch",
        Finding(
            "TR-POL-003", Status.FAIL,
            f"TR-POL-003: policy.bundle_hash does not describe what policy.policy_uri "
            f"resolves to; declared {bundle_hash}, resolved {actual}",
        ),
    )


def check(
    trace: dict[str, Any], *, policy_resolver: Callable[[str], bytes] | None = None
) -> list[Finding]:
    """Return TR-POL findings for the policy bundle claim.

    *policy_resolver* is supplied by the caller and never derived from the
    record: a record that could name its own resolver could name one that
    agrees with it. When it is None the resolution check skips, so offline
    verification stays a first-class use rather than a degraded one.
    """
    findings: list[Finding] = []
    policy = trace.get("policy")

    if policy is None:
        _observe("TR-POL", "policy_missing")
        return [Finding("TR-POL-001", Status.FAIL, "TR-POL-001: policy field is missing or not an object")]
    if not isinstance(policy, dict):
        _observe("TR-POL", "policy_not_object")
        return [
            Finding(
                "TR-POL-001", Status.FAIL,
                "TR-POL-001: policy field is missing or not an object",
            )
        ]

    bundle_hash = policy.get("bundle_hash", "")
    if _DIGEST_RE.fullmatch(str(bundle_hash)):
        findings.append(Finding("TR-POL-001", Status.PASS, "policy.bundle_hash has valid digest format"))
    else:
        findings.append(Finding(
            "TR-POL-001", Status.FAIL,
            f"TR-POL-001: policy.bundle_hash must match sha256:<64hex> or sha384:<96hex>, got {bundle_hash!r}",
        ))

    enforcement = policy.get("enforcement_mode")
    if isinstance(enforcement, str) and enforcement in _VALID_ENFORCEMENT:
        findings.append(Finding("TR-POL-002", Status.PASS, f"policy.enforcement_mode is valid ({enforcement!r})"))
    else:
        findings.append(Finding(
            "TR-POL-002", Status.FAIL,
            f"TR-POL-002: policy.enforcement_mode must be one of {sorted(_VALID_ENFORCEMENT)}, got {enforcement!r}",
        ))

    findings.append(_resolution_finding(policy, policy_resolver))

    return findings

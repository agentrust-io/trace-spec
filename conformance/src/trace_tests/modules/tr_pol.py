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
        BranchRule(
            "expected_policy_mismatch",
            ProducerRole.TARGET_COMPLETED,
            "TR-POL-003",
            (Status.FAIL,),
        ),
        BranchRule(
            "expected_policy_unevaluated_no_uri",
            ProducerRole.NOT_ATTEMPTED,
            "TR-POL-003",
            (Status.UNVERIFIED,),
        ),
        BranchRule(
            "expected_policy_unevaluated_no_resolver",
            ProducerRole.NOT_ATTEMPTED,
            "TR-POL-003",
            (Status.UNVERIFIED,),
        ),
        BranchRule(
            "expected_policy_unevaluated_unresolved",
            ProducerRole.TARGET_ATTEMPTED_UNRESOLVED,
            "TR-POL-003",
            (Status.UNVERIFIED,),
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


def validate_expected_policy_hash(expected_policy_hash: str | None) -> None:
    """Refuse an expected policy hash the comparison could not use.

    The value comes from the verifier, not the record, so a malformed one is a
    caller error and raises rather than becoming a finding about the record.
    """
    if expected_policy_hash is None:
        return
    if not isinstance(expected_policy_hash, str) or not _DIGEST_RE.fullmatch(
        expected_policy_hash
    ):
        raise ValueError(
            "expected_policy_hash must match sha256:<64 lowercase hex> or "
            f"sha384:<96 lowercase hex>, got {expected_policy_hash!r}"
        )


def _expected_mismatch(
    bundle_hash: str, expected_policy_hash: str | None
) -> Finding | None:
    """Return a failure when the record declares a policy other than the expected one.

    This compares the record's own declaration with verifier context, so like a
    malformed reference it needs no network and runs before any resolver. It
    decides only when both digests use the same algorithm; otherwise the
    comparison is made over the resolved bytes, in `_resolution_finding`.
    """
    if expected_policy_hash is None or not _DIGEST_RE.fullmatch(bundle_hash):
        return None
    if expected_policy_hash.partition(":")[0] != bundle_hash.partition(":")[0]:
        return None
    if expected_policy_hash == bundle_hash:
        return None
    return _observe(
        "TR-POL",
        "expected_policy_mismatch",
        Finding(
            "TR-POL-003", Status.FAIL,
            f"TR-POL-003: policy.bundle_hash declares {bundle_hash}, which is not the "
            f"policy the verifier expects ({expected_policy_hash})",
        ),
    )


def _needs_bytes(bundle_hash: str, expected_policy_hash: str | None) -> bool:
    """Return True when the expected policy can only be compared over the bundle bytes.

    That is the case when the verifier supplied an expectation in a different
    digest algorithm from the record's own declaration.
    """
    if expected_policy_hash is None or not _DIGEST_RE.fullmatch(bundle_hash):
        # A malformed declaration is TR-POL-001's failure; nothing is deferred.
        return False
    return expected_policy_hash.partition(":")[0] != bundle_hash.partition(":")[0]


def _unevaluated(branch: str, expected_policy_hash: str, reason: str) -> Finding:
    """Report an expected policy hash the verifier supplied that could not be compared.

    The record has not been shown to cite another policy, so this is not a
    failure of the record. But the verifier asked for the comparison, and a
    result that reads as conformant without it would answer a question the
    verifier did not ask. The finding is therefore unverified and fails the run
    at every level, whatever the threshold registered for TR-POL-003, which
    keeps governing callers that supplied no expectation.
    """
    return _observe(
        "TR-POL",
        branch,
        Finding(
            "TR-POL-003", Status.UNVERIFIED,
            f"TR-POL-003: the expected policy hash {expected_policy_hash} uses a "
            f"different algorithm from policy.bundle_hash and could only be compared "
            f"over the policy bundle, which {reason}; the expected policy was not "
            f"compared",
            unverified_fails_from_level=0,
        ),
    )


def _resolution_finding(
    policy: dict[str, Any],
    policy_resolver: Callable[[str], bytes] | None,
    expected_policy_hash: str | None = None,
) -> Finding:
    """Return the TR-POL-003 finding for *policy*.

    The order below is the whole of the check's meaning, so it is worth stating.
    A reference the record got wrong is a defect in the record, visible with no
    network and no resolver, exactly like the digest shape TR-POL-001 tests. A
    referent that could not be fetched is weather. The malformed check therefore
    runs before the resolver is consulted: running an offline verification must
    not mean being blind to a defect the record carries on its face.

    The expected policy hash follows the same rule. It is verifier context, never
    read from the record, and a record that declares a different policy is
    reported without a resolver, whether or not it carries a policy_uri.
    """
    bundle_hash = str(policy.get("bundle_hash", ""))
    if "policy_uri" not in policy:
        mismatch = _expected_mismatch(bundle_hash, expected_policy_hash)
        if mismatch is not None:
            return mismatch
        if expected_policy_hash is not None and _needs_bytes(bundle_hash, expected_policy_hash):
            return _unevaluated(
                "expected_policy_unevaluated_no_uri",
                expected_policy_hash,
                "the record does not reference (policy.policy_uri is absent)",
            )
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
        mismatch = _expected_mismatch(bundle_hash, expected_policy_hash)
        if mismatch is not None:
            return mismatch
        if expected_policy_hash is not None and _needs_bytes(bundle_hash, expected_policy_hash):
            return _unevaluated(
                "expected_policy_unevaluated_no_uri",
                expected_policy_hash,
                "the record does not reference (policy.policy_uri is null)",
            )
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

    mismatch = _expected_mismatch(bundle_hash, expected_policy_hash)
    if mismatch is not None:
        return mismatch

    if policy_resolver is None:
        if expected_policy_hash is not None and _needs_bytes(bundle_hash, expected_policy_hash):
            return _unevaluated(
                "expected_policy_unevaluated_no_resolver",
                expected_policy_hash,
                "was not resolved because no resolver was supplied",
            )
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
        if expected_policy_hash is not None and _needs_bytes(bundle_hash, expected_policy_hash):
            return _unevaluated(
                "expected_policy_unevaluated_unresolved",
                expected_policy_hash,
                f"could not be resolved from policy.policy_uri {policy_uri!r} "
                f"({type(exc).__name__}: {exc})",
            )
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
        if expected_policy_hash is not None and _needs_bytes(bundle_hash, expected_policy_hash):
            return _unevaluated(
                "expected_policy_unevaluated_unresolved",
                expected_policy_hash,
                f"the policy resolver did not return (it returned "
                f"{type(resolved).__name__} rather than bytes for {policy_uri!r})",
            )
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
        if expected_policy_hash is not None:
            # Same-algorithm expectations were settled before the resolver ran. One
            # in another algorithm can only be compared over the bytes just read.
            exp_prefix, _, _ = expected_policy_hash.partition(":")
            exp_algo = _DIGEST_ALGOS[f"{exp_prefix}:"]
            resolved_as_expected = f"{exp_prefix}:{exp_algo(resolved).hexdigest()}"
            if resolved_as_expected != expected_policy_hash:
                return _observe(
                    "TR-POL",
                    "expected_policy_mismatch",
                    Finding(
                        "TR-POL-003", Status.FAIL,
                        f"TR-POL-003: policy.policy_uri resolves to the bundle "
                        f"policy.bundle_hash declares, but that bundle is not the policy "
                        f"the verifier expects; resolved {resolved_as_expected}, "
                        f"expected {expected_policy_hash}",
                    ),
                )
        return _observe(
            "TR-POL",
            "resolved_match",
            Finding(
                "TR-POL-003", Status.PASS,
                f"policy.policy_uri resolves to the bundle policy.bundle_hash declares "
                f"({len(resolved)} bytes, {prefix})"
                + ("" if expected_policy_hash is None
                   else ", and it is the policy the verifier expects"),
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
    trace: dict[str, Any],
    *,
    policy_resolver: Callable[[str], bytes] | None = None,
    expected_policy_hash: str | None = None,
) -> list[Finding]:
    """Return TR-POL findings for the policy bundle claim.

    *policy_resolver* is supplied by the caller and never derived from the
    record: a record that could name its own resolver could name one that
    agrees with it. When it is None the resolution check skips, so offline
    verification stays a first-class use rather than a degraded one.

    *expected_policy_hash* is the digest of the policy the verifier expects,
    also supplied by the caller. A matching ``bundle_hash`` shows the resolved
    bytes are the ones the record cited, not that they are the expected policy,
    so TR-POL-003 fails a record that declares any other policy. When it is
    None, TR-POL-003 behaves exactly as before.
    """
    validate_expected_policy_hash(expected_policy_hash)
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

    findings.append(_resolution_finding(policy, policy_resolver, expected_policy_hash))

    return findings

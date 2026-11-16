"""TR-ENV: EAT envelope structure checks (spec §3.2)."""

from __future__ import annotations

import re
import time
from typing import Any

from trace_tests.result import Finding, Status

_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
# RFC 7517/7518 private key members. Mirrors _JWK_PRIVATE_PARAMS in the
# agentrust-trace reference model, which already refuses these.
_JWK_PRIVATE_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

# Applied with fullmatch: $ alone also matches before a trailing newline.
_SUBJECT_RE = re.compile(r'^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$')
_IAT_MIN = 1_700_000_000
#: The schema's unconditional required tree (spec 3.1: every field is required
#: unless marked OPTIONAL): each member reached through `required`, from the root
#: and into required objects, with its JSON type. Equal to schema/trace-claim.json;
#: test_required_tree_parity fails if the two drift.
_REQUIRED: tuple[tuple[str, str], ...] = (
    ("eat_profile", "string"),
    ("iat", "integer"),
    ("subject", "string"),
    ("model", "object"),
    ("model.provider", "string"),
    ("model.model_id", "string"),
    ("runtime", "object"),
    ("runtime.platform", "string"),
    ("runtime.measurement", "string"),
    ("policy", "object"),
    ("policy.bundle_hash", "string"),
    ("policy.enforcement_mode", "string"),
    ("data_class", "string"),
    ("build_provenance", "object"),
    ("build_provenance.slsa_level", "integer"),
    ("build_provenance.digest", "string"),
    ("appraisal", "object"),
    ("appraisal.status", "string"),
    ("appraisal.verifier", "string"),
    ("cnf", "object"),
    ("cnf.jwk", "object"),
    ("cnf.jwk.kty", "string"),
)


def _has_type(value: Any, json_type: str) -> bool:
    """JSON Schema's type test. An integer is any number with no fractional part,
    as TR-ENV-002 already reads `iat`; a bool is never a number."""
    if json_type == "object":
        return isinstance(value, dict)
    if json_type == "string":
        return isinstance(value, str)
    if json_type == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    raise ValueError(f"no type test for {json_type!r}")


def _required_tree_errors(trace: Any) -> list[str]:
    """One entry per required member that is absent, null or of the wrong type.

    A member under one that failed is not reported again. Formats and enums are
    the field modules' checks, and conditional rules are not read here.
    """
    if not isinstance(trace, dict):
        return ["the record is not an object"]
    errors: list[str] = []
    failed: set[str] = set()
    for path, json_type in _REQUIRED:
        *parents, name = path.split(".")
        if any(".".join(parents[: i + 1]) in failed for i in range(len(parents))):
            continue
        node: Any = trace
        for part in parents:
            node = node[part]
        if name not in node:
            errors.append(f"{path} is missing")
        elif node[name] is None:
            errors.append(f"{path} is null")
        elif not _has_type(node[name], json_type):
            errors.append(f"{path} is not {'an' if json_type[0] in 'aeiou' else 'a'} {json_type}")
        else:
            continue
        failed.add(path)
    return errors
_JCS_SAFE_INTEGER = 9007199254740991

#: Default maximum record age (seconds). Records older than this fail freshness.
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60


def check(trace: dict[str, Any], max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS) -> list[Finding]:
    """Return findings for the EAT envelope structure.

    *max_age_seconds* bounds how old ``iat`` may be; without an upper bound any
    historical record would pass freshness forever and be trivially replayable.
    """
    findings: list[Finding] = []

    profile = trace.get("eat_profile")
    if profile == _PROFILE:
        findings.append(Finding("TR-ENV-001", Status.PASS, "eat_profile sentinel matches"))
    else:
        findings.append(Finding("TR-ENV-001", Status.FAIL, f"eat_profile must be {_PROFILE!r}, got {profile!r}"))

    iat = trace.get("iat")
    # Integer-typed members are decided by mathematical value within the RFC 8785
    # safe-integer range (spec §3.2.2); bool is an int subclass in Python and is
    # excluded explicitly.
    if (
        isinstance(iat, (int, float))
        and not isinstance(iat, bool)
        and (isinstance(iat, int) or iat.is_integer())
        and _IAT_MIN <= int(iat) <= _JCS_SAFE_INTEGER
    ):
        iat = int(iat)
        now = int(time.time())
        if iat > now + 60:
            findings.append(Finding("TR-ENV-002", Status.FAIL, f"iat {iat} is in the future (now={now})"))
        elif now - iat > max_age_seconds:
            findings.append(Finding(
                "TR-ENV-002", Status.FAIL,
                f"TR-ENV-002: record is stale: iat {iat} is {now - iat}s old, "
                f"exceeding the maximum allowed age of {max_age_seconds}s",
            ))
        else:
            findings.append(Finding("TR-ENV-002", Status.PASS, f"iat is valid and fresh ({iat})"))
    else:
        findings.append(Finding(
            "TR-ENV-002", Status.FAIL,
            f"iat must be a Unix timestamp integer in "
            f"[{_IAT_MIN}, {_JCS_SAFE_INTEGER}], got {iat!r}",
        ))

    subject = trace.get("subject", "")
    if isinstance(subject, str) and _SUBJECT_RE.fullmatch(subject):
        findings.append(Finding("TR-ENV-003", Status.PASS, f"subject is a valid workload identity URI ({subject!r})"))
    else:
        findings.append(Finding("TR-ENV-003", Status.FAIL, f"subject must be a SPIFFE URI (spiffe://) or DID URI (did:), got {subject!r}"))

    cnf = trace.get("cnf")
    if isinstance(cnf, dict) and isinstance(cnf.get("jwk"), dict) and "kty" in cnf["jwk"]:
        findings.append(Finding("TR-ENV-004", Status.PASS, f"cnf.jwk.kty present ({cnf['jwk']['kty']!r})"))
    else:
        findings.append(Finding("TR-ENV-004", Status.FAIL, "cnf must contain jwk with kty"))

    # TR-ENV-005 (GHSA-vc4p-h84j-7qxj). RFC 8747 makes cnf a confirmation key:
    # the public half, so a verifier can bind the record to the key that signed
    # it. A private member here publishes the signing key inside a record that
    # is signed, self-authenticating and usually anchored, and the only remedy
    # afterwards is to revoke the identity. TR-ENV-004 checks kty is present,
    # so a record carrying `d` passed the whole suite.
    if isinstance(cnf, dict) and isinstance(cnf.get("jwk"), dict):
        private = sorted(_JWK_PRIVATE_PARAMS.intersection(cnf["jwk"]))
        if private:
            findings.append(Finding(
                "TR-ENV-005", Status.FAIL,
                "cnf.jwk carries private key material: "
                + ", ".join(private)
                + ". Publish the public half only; this key must be treated as compromised",
            ))
        else:
            findings.append(Finding(
                "TR-ENV-005", Status.PASS, "cnf.jwk carries no private key material"
            ))

    # TR-ENV-006. Spec 3.1: every field is required unless marked OPTIONAL.
    # The other Level 0 checks read single fields, so a record with no model,
    # runtime or build_provenance, or with `model: {}`, passed Level 0. This is
    # the schema's required tree, not full schema validation.
    errors = _required_tree_errors(trace)
    if errors:
        findings.append(Finding("TR-ENV-006", Status.FAIL, "; ".join(errors)))
    else:
        findings.append(Finding(
            "TR-ENV-006", Status.PASS, "every required member is present with its type"
        ))

    return findings

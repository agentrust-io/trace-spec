"""TR-ENV: EAT envelope structure checks (spec §3.2)."""

from __future__ import annotations

import re
import time
from typing import Any

from trace_tests.result import Finding, Status

_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
# RFC 7517/7518 private key members. Mirrors _JWK_PRIVATE_PARAMS in the
# agentrust-trace reference model, which already refuses these.
_JWK_PRIVATE_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})

# Applied with fullmatch: $ alone also matches before a trailing newline.
_SUBJECT_RE = re.compile(r'^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$')
_IAT_MIN = 1_700_000_000

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
    if isinstance(iat, int) and iat >= _IAT_MIN:
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
        findings.append(Finding("TR-ENV-002", Status.FAIL, f"iat must be a Unix timestamp >= {_IAT_MIN}, got {iat!r}"))

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

    return findings

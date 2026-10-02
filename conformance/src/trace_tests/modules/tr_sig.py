"""TR-SIG: Signature verification (spec §3.2.1).

Records are verified over their RFC 8785 (JCS) canonical bytes, excluding the
``signature`` field, with the key in ``trace.cnf.jwk``.

RFC 8785 and not an ad-hoc serializer, because §3.2.2 of the specification says so
in as many words: "Implementations MUST use an RFC 8785-conformant library. Using
``json.dumps(sort_keys=True)`` (Python) or equivalent ad-hoc sorting is
insufficient." This module used ``json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=True)`` until it was pointed at trace-spec's canonicalization corpus,
which rejected all four of its valid, correctly signed records. The two forms agree
on every ASCII record, which is every record this suite carried, so nothing here
failed while the suite told conformant implementations they were not.

A plain trace record carrying a ``signature`` field is verified against it. One
without a signature cannot be, so TR-SIG fails closed: at any level that requires
signatures (level >= 1) the result is FAIL; at level 0 it is an explicit UNVERIFIED
finding, so a record with nothing to check is never reported as verified.
"""

from __future__ import annotations

import base64
import re
from typing import Any

import rfc8785

from trace_tests.result import Finding, Status

_SUPPORTED_KTY = {"OKP", "EC"}
_ED25519_CRV = "Ed25519"


_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*\Z")


def _b64url_decode(s: str) -> bytes:
    """Decode unpadded base64url (RFC 7515 section 2), accepting one spelling only.

    ``base64.urlsafe_b64decode`` is lenient: it drops characters outside the
    alphabet, takes the standard ``+`` and ``/`` as well, accepts padding, and
    ignores the unused low bits of the last character. Each of those gives a
    different string for the same bytes. The signature sits outside the body it
    signs, so every such spelling was a different record that still verified.
    Anything but the canonical unpadded form is refused.
    """
    if not isinstance(s, str) or not _B64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("not unpadded base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != s:
        raise ValueError("not the canonical base64url encoding of its bytes")
    return raw


def _canonical_json(d: dict[str, Any]) -> bytes:
    """RFC 8785 canonical bytes, per specification §3.2.2.

    Not ``json.dumps`` with its options set carefully. The escaping of non-ASCII and
    the sort order of keys containing supplementary-plane characters both differ, and
    a verifier that gets either wrong computes different bytes and rejects a valid
    record. ``tests/test_canonicalization_boundary.py`` holds this to records where
    the difference is observable.
    """
    return rfc8785.dumps(d)


def _canonical_body(d: dict[str, Any]) -> tuple[bytes | None, str]:
    """Canonical bytes for *d*, or ``None`` and the reason there are none.

    Two contracts meet here and they disagree. ``_canonical_json`` raises by design: it
    is the RFC 8785 serializer, and a value JCS has no form for has no canonical bytes,
    so there is nothing for it to return. ``runner.run`` calls every module with no
    ``try``, so a module that lets that reach the caller ends the run and the record is
    neither passed nor failed.

    This is the boundary between them. ``_canonical_json`` keeps raising, because the
    canonicalization tests compare its bytes directly and a wrapper that swallowed the
    error would hide a real serializer defect. Callers that must return a verdict use
    this instead.

    ``IntegerDomainError`` and ``FloatDomainError`` both derive from
    ``CanonicalizationError``, so one clause covers all three: an integer outside the JCS
    safe range, a non-finite float, and a string carrying a lone surrogate. All three are
    ordinary JSON. ``json.loads`` accepts them, ``load_record`` has no reason to refuse
    them, and before this they reached the CLI as a traceback.
    """
    try:
        return _canonical_json(d), ""
    except rfc8785.CanonicalizationError as exc:
        return None, str(exc)
    except UnicodeError as exc:
        # A lone surrogate in an object *key* fails inside rfc8785's UTF-16 key
        # sort with UnicodeEncodeError, outside its own hierarchy. The same
        # character in a value is a CanonicalizationError. Same meaning either way.
        return None, f"lone surrogate in an object key ({exc})"


def _verify_ed25519(pub_x: str, sig_b64: str, body: bytes) -> tuple[bool, str]:
    """Verify *sig_b64* over *body*, returning ``(ok, message)``.

    The messages name no error code. Two callers attach them to findings, ``check``
    under TR-SIG-005 and ``check_cmcp_runtime`` under TR-SIG-001, so a code written
    here would contradict one of them and, before this, contradicted both: a
    malformed signature was published as a TR-SIG-005 finding whose text read
    "TR-SIG-003". The finding's ``code`` is the only place a code belongs.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return False, "cryptography library not installed; run: pip install cryptography"

    try:
        pub_bytes = _b64url_decode(pub_x)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as exc:
        return False, f"invalid public key in cnf.jwk.x: {exc}"

    try:
        sig_bytes = _b64url_decode(sig_b64)
    except Exception as exc:
        return False, f"invalid base64url signature: {exc}"

    try:
        pub_key.verify(sig_bytes, body)
        return True, "Ed25519 signature verified"
    except InvalidSignature:
        return False, "signature verification failed"


def _jwk_of(container: Any) -> dict[str, Any]:
    """The JWK under ``container["cnf"]["jwk"]``, or ``{}`` when it is not an object.

    A malformed record must produce a finding, not an exception. ``runner.run`` calls
    every module without a ``try``, so anything raised here ends the run rather than
    failing the record, and the caller sees a traceback where a verdict belongs.

    The outer ``isinstance`` is for ``check_cmcp_runtime``, which passes
    ``record["trace"]`` and so can hand this anything at all. ``check`` passes the
    ``trace`` it was given, which for the plain format is the record itself and is
    already a dict; that function reads ``trace`` directly elsewhere and is not
    hardened against a non-dict ``trace``. Whether one can reach it is a question
    about ``loader.extract_trace``, not about this helper.
    """
    if not isinstance(container, dict):
        return {}
    cnf = container.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    return jwk if isinstance(jwk, dict) else {}


def check_cmcp_runtime(record: dict[str, Any]) -> list[Finding]:
    """Verify the Ed25519 signature on a cmcp RuntimeClaim."""
    findings: list[Finding] = []

    sig = record.get("signature", "")
    if not sig:
        findings.append(Finding("TR-SIG-001", Status.FAIL, "TR-SIG-001: signature field is missing or empty"))
        return findings

    jwk = _jwk_of(record.get("trace"))
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    x = jwk.get("x")

    if kty != "OKP" or crv != _ED25519_CRV:
        findings.append(Finding("TR-SIG-002", Status.FAIL, f"TR-SIG-002: expected OKP/Ed25519 key, got kty={kty!r} crv={crv!r}"))
        return findings

    if not x:
        findings.append(Finding("TR-SIG-002", Status.FAIL, "TR-SIG-002: cnf.jwk.x is missing"))
        return findings

    body, why = _canonical_body({k: v for k, v in record.items() if k != "signature"})
    if body is None:
        # Not "verification failed". No signature over this claim could verify, because
        # the bytes a signature is taken over do not exist. A consumer acting on the
        # other reading would go looking for a key problem.
        findings.append(Finding(
            "TR-SIG-001", Status.FAIL,
            f"TR-SIG-001: claim has no RFC 8785 canonical form, so there are no bytes "
            f"to check the signature against ({why})",
        ))
        return findings

    ok, msg = _verify_ed25519(x, sig, body)
    status = Status.PASS if ok else Status.FAIL
    findings.append(Finding("TR-SIG-001", status, msg))
    return findings


def check(trace: dict[str, Any], record: dict[str, Any], fmt: str, level: int = 0) -> list[Finding]:
    """Return TR-SIG findings. *record* is the full raw dict, *trace* is the extracted TRACE fields.

    *level* is the conformance level being checked.

    Plain trace records with an embedded ``signature`` field are verified with Ed25519
    (agentrust-trace ``sign_record()`` output). Plain trace records without a signature
    field FAIL at level >= 1 and are UNVERIFIED at level 0.
    """
    if fmt == "cmcp-runtime":
        return check_cmcp_runtime(record)

    findings: list[Finding] = []
    jwk = _jwk_of(trace)
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    x = jwk.get("x")

    if "d" in jwk:
        findings.append(Finding(
            "TR-SIG-004", Status.FAIL,
            "TR-SIG-004: cnf.jwk must not contain private key material "
            "('d' member present in the JWK)",
        ))
        # The signature is not checked against a key the record should never have
        # carried. Say so rather than returning nothing: a consumer reading TR-SIG-005
        # to learn whether the signature was verified would otherwise find no finding
        # at all, which is the benign-omission reading UNVERIFIED exists to prevent.
        findings.append(Finding(
            "TR-SIG-005", Status.UNVERIFIED,
            "TR-SIG-005: signature not checked; cnf.jwk carries private key material",
        ))
        return findings

    if isinstance(kty, str) and kty in _SUPPORTED_KTY:
        label = f"kty={kty!r}" + (f", crv={crv!r}" if crv else "")
        findings.append(Finding("TR-SIG-004", Status.PASS, f"cnf.jwk key type is supported ({label})"))
    elif kty is None:
        findings.append(Finding("TR-SIG-004", Status.FAIL, "TR-SIG-004: cnf.jwk.kty is missing"))
    else:
        findings.append(Finding(
            "TR-SIG-004", Status.FAIL,
            f"TR-SIG-004: unsupported key type {kty!r}; expected one of {sorted(_SUPPORTED_KTY)}",
        ))

    sig = trace.get("signature", "")
    if sig and kty == "OKP" and crv == _ED25519_CRV and jwk.get("x"):
        body, why = _canonical_body({k: v for k, v in trace.items() if k != "signature"})
        if body is None:
            findings.append(Finding(
                "TR-SIG-005", Status.FAIL,
                f"TR-SIG-005: record has no RFC 8785 canonical form, so there are no "
                f"bytes to check the signature against ({why})",
            ))
        else:
            ok, msg = _verify_ed25519(jwk["x"], sig, body)
            status = Status.PASS if ok else Status.FAIL
            findings.append(Finding("TR-SIG-005", status, msg))
    elif sig:
        findings.append(Finding(
            "TR-SIG-005", Status.FAIL,
            "TR-SIG-005: signature field present but key type is not OKP/Ed25519 or cnf.jwk.x is missing",
        ))
    elif level >= 1:
        findings.append(Finding(
            "TR-SIG-005", Status.FAIL,
            f"TR-SIG-005: no signature present; Level {level} requires cryptographic verification",
        ))
    else:
        findings.append(Finding(
            "TR-SIG-005", Status.UNVERIFIED,
            "TR-SIG-005: no signature present; this record is NOT cryptographically verified",
        ))

    return findings

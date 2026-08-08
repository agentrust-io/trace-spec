"""Signing utilities for TRACE Trust Records.

Produces a signed record dict with an embedded ``signature`` field --
Ed25519 over the canonical JSON of the record with only the signature field absent.
This is the same convention used by cMCP RuntimeClaim and verified by
trace-tests TR-SIG at all conformance levels.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import warnings
from collections.abc import Callable, Container
from typing import Any, TypeAlias

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TRACE_PROFILE_V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
"""The profile URI this build implements — the only one ``verify_record`` accepts."""

_TRACE_PROFILE_V0_1 = "tag:agentrust.io,2026:trace-v0.1"
"""The superseded identifier, minted under a domain the project does not own.

Named only so its rejection can say why. Deliberately not exported: no caller
should be able to spell it without reading this file.
"""

RevocationStore: TypeAlias = Container[str] | Callable[[str], bool]
"""Caller-supplied source of key revocation status, consulted by ``verify_record``.

Either form is accepted:

- a container of revoked key identifiers (``set``, ``frozenset``, ``list``, or any
  object supporting ``in``), for a revocation list the caller already holds; or
- a callable taking one key identifier and returning ``True`` when that key is
  revoked, for a live CRL, OCSP-style status endpoint, or SCITT log lookup.

An identifier is either the RFC 7638 JWK Thumbprint of the trusted key (see
``jwk_thumbprint``) or its ``kid``; a match on either revokes the key.
"""


def generate_key() -> Ed25519PrivateKey:
    """Generate a new Ed25519 signing key."""
    return Ed25519PrivateKey.generate()


def load_key(pem: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM string."""
    return serialization.load_pem_private_key(pem.encode(), password=None)  # type: ignore[return-value]


def load_signing_key() -> Ed25519PrivateKey:
    """Load key from ``TRACE_PRIVATE_KEY_PEM`` env var, or generate an ephemeral one.

    Emits a warning when falling back to an ephemeral key so callers notice
    that the resulting records cannot be re-verified after the process exits.
    """
    pem = os.environ.get("TRACE_PRIVATE_KEY_PEM")
    if pem:
        return load_key(pem)
    warnings.warn(
        "TRACE_PRIVATE_KEY_PEM not set -- generating ephemeral Ed25519 key. "
        "The signed record cannot be re-verified after this process exits. "
        "Set TRACE_PRIVATE_KEY_PEM to a persistent PEM for production use.",
        stacklevel=2,
    )
    return generate_key()


def _okp_jwk(raw_public_bytes: bytes) -> dict[str, str]:
    """Return the OKP / Ed25519 public JWK for raw 32-byte public key material."""
    x = base64.urlsafe_b64encode(raw_public_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def key_to_jwk(key: Ed25519PrivateKey) -> dict[str, str]:
    """Return the public JWK dict for *key* (OKP / Ed25519)."""
    return _okp_jwk(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def _jwk_from_public_key(pub: Any) -> dict[str, str]:
    """Return the public JWK for an ``Ed25519PublicKey``.

    Needed only by the revocation check, which is keyed on the trusted key's
    identifiers. Callers may pass a key object rather than a JWK, so the JWK is
    reconstructed here rather than requiring one at the call site.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError(
            "revocation checking needs the trusted key as an Ed25519PublicKey or a JWK "
            f"dict, so its identifiers can be derived; got {type(pub).__name__}"
        )
    return _okp_jwk(
        pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


# RFC 7638 §3.2 (extended for OKP by RFC 8037 §2): the required members of each key
# type, which are the only ones hashed into a thumbprint. RFC 7638 also defines the
# member set for "oct"; it is omitted deliberately, because an oct JWK carries a
# symmetric secret and every key this module handles is a public confirmation key.
_THUMBPRINT_MEMBERS: dict[str, tuple[str, ...]] = {
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "RSA": ("e", "kty", "n"),
}


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Return the RFC 7638 JWK Thumbprint of *jwk*: base64url SHA-256, no padding.

    The thumbprint is computed over only the required members for the key type, in
    lexicographic order with no whitespace, so it is stable across JWKs that differ
    in optional members such as ``kid``, ``alg``, or ``use``. That makes it the
    identifier a revocation list can be keyed on when the issuer publishes no ``kid``.

    Member names are ASCII, so the RFC 8785 (JCS) serialization used here is
    byte-identical to the code-point ordering RFC 7638 §3.3 specifies.

    Raises ``ValueError`` for an unknown ``kty`` or a missing required member.
    """
    kty = jwk.get("kty")
    if not isinstance(kty, str) or kty not in _THUMBPRINT_MEMBERS:
        raise ValueError(
            f"cannot compute a JWK thumbprint for kty {kty!r}; "
            f"expected one of {sorted(_THUMBPRINT_MEMBERS)}"
        )

    members: dict[str, Any] = {}
    for name in _THUMBPRINT_MEMBERS[kty]:
        value = jwk.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"jwk with kty={kty!r} is missing required thumbprint member {name!r}"
            )
        members[name] = value

    return base64.urlsafe_b64encode(
        hashlib.sha256(_canonical_bytes(members)).digest()
    ).rstrip(b"=").decode()


def _key_identifiers(jwk: dict[str, Any]) -> list[str]:
    """Return the identifiers a revocation store may list this key under."""
    identifiers = [jwk_thumbprint(jwk)]
    kid = jwk.get("kid")
    if isinstance(kid, str) and kid and kid not in identifiers:
        identifiers.append(kid)
    return identifiers


def _check_not_revoked(jwk: dict[str, Any], revocation: RevocationStore) -> None:
    """Raise ``ValueError`` if *jwk* is revoked, or if its status cannot be determined.

    Both outcomes fail closed. An unreachable revocation source is not evidence
    that a key is unrevoked, so a store that raises is treated as a rejection
    rather than passed over.
    """
    for identifier in _key_identifiers(jwk):
        try:
            revoked = revocation(identifier) if callable(revocation) else identifier in revocation
        except Exception as exc:
            raise ValueError(
                f"revocation status for key {identifier!r} could not be determined: {exc}. "
                "Verification fails closed: an unavailable revocation source is not "
                "evidence that the key is unrevoked."
            ) from exc
        if revoked:
            raise ValueError(
                f"signing key is revoked (listed as {identifier!r}); the record is rejected. "
                "A signature made by a revoked key stays cryptographically valid, so the "
                "verifier is the only place this can be caught."
            )


def _canonical_bytes(d: dict[str, Any]) -> bytes:
    """Return the RFC 8785 (JCS) canonical UTF-8 byte sequence for *d*.

    This is the signature pre-image mandated by spec/trace-v0.2.md §3.2.2. JCS
    sorts object keys by UTF-16 code unit, serializes numbers per the
    ECMAScript Number-to-String / RFC 8785 §3.2.2.3 shortest round-trip form,
    escapes only the characters required by RFC 8259 §7, and emits non-ASCII
    characters as raw UTF-8 (not ``\\uXXXX`` escapes). A plain
    ``json.dumps(sort_keys=True)`` diverges from JCS for non-ASCII strings and
    for IEEE 754 number formatting, which would break cross-implementation
    verification, so a conformant library is used instead.
    """
    return rfc8785.dumps(d)


def _b64url_decode(value: str, *, field: str) -> bytes:
    """Decode an unpadded base64url string, raising ValueError on malformed input.

    Restores the padding the encoder stripped and surfaces ``binascii`` decode
    failures as ``ValueError`` so callers see one consistent failure type.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64url string")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} is not valid base64url: {exc}") from exc


def sign_record(record: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """Return a copy of *record* with ``cnf.jwk`` populated and a ``signature`` field added.

    The signature is Ed25519 over the canonical JSON (sorted keys, no whitespace)
    of the record with only the ``signature`` field absent. ``cnf.jwk`` is set to the
    public key derived from *key*.

    The returned dict is a plain JSON-serialisable object. Pass it to
    ``json.dumps()`` to get the wire form, or to ``TrustRecord.model_validate()``
    to confirm structural validity before writing.
    """
    jwk = key_to_jwk(key)
    payload: dict[str, Any] = {**record, "cnf": {"jwk": jwk}}
    body = _canonical_bytes({k: v for k, v in payload.items() if k != "signature"})
    sig_bytes = key.sign(body)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
    return {**payload, "signature": sig_b64}


def _pubkey_from_jwk(jwk: dict[str, Any]) -> Any:
    """Reconstruct an Ed25519 public key from a JWK, rejecting other key types.

    Asserts ``kty == "OKP"`` and ``crv == "Ed25519"`` before building the key so
    that, for example, an EC key is never silently treated as Ed25519.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    kty = jwk.get("kty")
    crv = jwk.get("crv")
    if kty != "OKP":
        raise ValueError(f"unsupported JWK kty {kty!r}; expected 'OKP' for Ed25519")
    if crv != "Ed25519":
        raise ValueError(f"unsupported JWK crv {crv!r}; expected 'Ed25519'")

    x_b64 = jwk.get("x")
    if not x_b64:
        raise ValueError("JWK missing 'x' field")
    x_bytes = _b64url_decode(x_b64, field="JWK 'x'")
    return Ed25519PublicKey.from_public_bytes(x_bytes)


def verify_record(
    record: dict[str, Any],
    public_key_or_jwk: Any = None,
    *,
    allow_embedded_key: bool = False,
    max_age_seconds: int | None = 86400,
    expected_nonce: str | None = None,
    revocation: RevocationStore | None = None,
) -> None:
    """Verify an Ed25519 signature on a signed TRACE Trust Record.

    A trusted key is REQUIRED. Pass an ``Ed25519PublicKey`` or a JWK dict via
    *public_key_or_jwk* to verify against a key the caller already trusts.

    Raises ``InvalidSignature`` if the signature does not verify, and ``ValueError``
    for every other rejection (wrong or missing profile, no signature, no trusted
    key, malformed input, unsupported JWK type, stale record, nonce mismatch, or
    revoked key). Returns ``None`` on success. All checks fail closed.

    Profile (fail closed):
        The record's ``eat_profile`` must be exactly ``TRACE_PROFILE_V0_2``.
        ``spec/trace-v0.2.md`` section 2 requires this of a v0.2 verifier: require
        the v0.2 identifier, reject the superseded v0.1 identifier, and never accept
        both. Any other profile is refused rather than verified on a best-effort
        basis, because "the signature checks out" says nothing about whether this
        code implements the semantics the record was written under. A missing
        profile is refused for the same reason: a verifier cannot supply it by
        assumption.

        The profile is read before any cryptographic work, which is safe because
        the only action taken on the unauthenticated value is refusal; a record
        that verifies has had its profile covered by the signature, since the
        signature spans the whole record.

    Trust anchoring (fail closed):
        Without a trusted key, the record cannot vouch for itself, so verification
        is refused. Set ``allow_embedded_key=True`` to opt in to verifying against
        ``record["cnf"]["jwk"]`` — this only proves internal consistency, not
        authenticity, and emits a loud ``UserWarning``.

    Freshness (fail closed):
        ``max_age_seconds`` (default 86400 = 24h) bounds how old ``record["iat"]``
        may be relative to now; pass ``None`` to disable the age check. If
        ``expected_nonce`` is given, it is compared in constant time against
        ``record["runtime"]["nonce"]``. A stale record or nonce mismatch raises
        ``ValueError``.

    Revocation (fail closed):
        ``spec/trace-v0.2.md`` §3.2.1 requires a verifier to consult current
        revocation status at verification time. Pass a ``revocation`` store, either
        a container of revoked key identifiers or a callable performing a live
        CRL/status/SCITT lookup. The trusted key is rejected if it is listed, or if
        the store cannot answer. Identifiers are the key's RFC 7638 thumbprint
        (``jwk_thumbprint``) and its ``kid``.

        ``revocation=None`` (the default) skips the check and keeps verification
        purely offline. Offline verification cannot prove non-revocation: a
        signature made by a compromised key stays cryptographically valid forever,
        and nothing inside the record can retract it. See ``LIMITATIONS.md``.
    """
    import time
    from hmac import compare_digest

    from cryptography.exceptions import InvalidSignature as _InvalidSignature  # noqa: F401

    # Profile first: refuse semantics this build does not implement before spending
    # any work on the record.
    profile = record.get("eat_profile")
    if not isinstance(profile, str) or not profile:
        raise ValueError(
            "record has no 'eat_profile': the profile URI states which semantics the "
            "record was written under, and a verifier cannot supply it by assumption"
        )
    if profile != TRACE_PROFILE_V0_2:
        if profile == _TRACE_PROFILE_V0_1:
            raise ValueError(
                f"record carries the superseded v0.1 profile {profile!r}. "
                "spec/trace-v0.2.md section 2: the cutover is cutover, not "
                "coexistence — a v0.2 verifier rejects the v0.1 identifier, which "
                "was minted under a domain the project does not own."
            )
        raise ValueError(
            f"record profile {profile!r} is not {TRACE_PROFILE_V0_2!r}. Verification "
            "is refused rather than attempted: a valid signature over semantics this "
            "build does not implement is not evidence."
        )

    sig_b64 = record.get("signature")
    if not sig_b64:
        raise ValueError("record has no 'signature' field")

    sig_bytes = _b64url_decode(sig_b64, field="signature")

    # Resolve the trusted public key. A trusted key is required: a record cannot
    # authenticate itself with the key it embeds.
    if public_key_or_jwk is None:
        if not allow_embedded_key:
            raise ValueError(
                "verify_record requires a trusted key. Pass an Ed25519PublicKey or "
                "JWK dict, or set allow_embedded_key=True to (insecurely) trust the "
                "key embedded in record.cnf.jwk."
            )
        jwk = record.get("cnf", {}).get("jwk", {})
        if not jwk:
            raise ValueError("record has no cnf.jwk and no public key was supplied")
        warnings.warn(
            "verify_record is trusting the key embedded in record.cnf.jwk "
            "(allow_embedded_key=True). This proves the record is internally "
            "consistent, NOT that it came from a trusted issuer. Verify against a "
            "pinned trusted key in production.",
            UserWarning,
            stacklevel=2,
        )
        public_key_or_jwk = jwk

    if isinstance(public_key_or_jwk, dict):
        pub = _pubkey_from_jwk(public_key_or_jwk)
    else:
        pub = public_key_or_jwk

    # Revocation: signature validity is permanent, trust is not. A key compromised
    # after issuance still produces records that verify, so the only place the
    # withdrawal of trust can be applied is here, at verification time.
    #
    # The check is keyed on the TRUSTED key, never on record["cnf"]["jwk"]: cnf.jwk
    # is attacker-controlled until the signature verifies, so keying on it would let
    # a revoked issuer present an unlisted thumbprint and pass. With
    # allow_embedded_key=True the two are the same object, and that path is already
    # documented as proving internal consistency only.
    if revocation is not None:
        trusted_jwk = (
            public_key_or_jwk
            if isinstance(public_key_or_jwk, dict)
            else _jwk_from_public_key(pub)
        )
        _check_not_revoked(trusted_jwk, revocation)

    # Freshness: bound the age of the record against its issued-at timestamp.
    if max_age_seconds is not None:
        iat = record.get("iat")
        if not isinstance(iat, int | float) or isinstance(iat, bool):
            raise ValueError("record has no valid integer 'iat' for freshness check")
        age = time.time() - iat
        if age > max_age_seconds:
            raise ValueError(
                f"record is stale: iat is {int(age)}s old, exceeds max_age_seconds="
                f"{max_age_seconds}"
            )

    # Freshness: bind to a caller-supplied nonce when provided.
    if expected_nonce is not None:
        actual_nonce = record.get("runtime", {}).get("nonce")
        if not isinstance(actual_nonce, str) or not compare_digest(actual_nonce, expected_nonce):
            raise ValueError("record runtime.nonce does not match expected_nonce")

    # Canonical bytes: record without "signature" key
    record_no_sig = {k: v for k, v in record.items() if k != "signature"}
    msg = _canonical_bytes(record_no_sig)

    pub.verify(sig_bytes, msg)  # raises InvalidSignature on failure

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
import json
import os
import warnings
from collections.abc import Callable, Container, Iterable
from typing import TYPE_CHECKING, Any, TypeAlias

if TYPE_CHECKING:
    from agentrust_trace.revocation import VerificationResult

import rfc8785
from jsonschema import ValidationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TRACE_PROFILE_V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
"""The profile URI this build implements: the only one ``verify_record`` accepts."""

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
    """Load an Ed25519 private key from a PEM string.

    Raises ``ValueError`` for anything that is not a PEM string this library can
    read. A PEM arrives from a file, an environment variable or a secret store,
    so its type is not something the caller has already established: reading
    ``.encode()`` off it first turned every non-string into an ``AttributeError``
    and a lone surrogate into a ``UnicodeEncodeError``, neither of which a caller
    written against this signature catches.
    """
    if not isinstance(pem, str):
        raise ValueError(
            f"pem must be a PEM string, got {type(pem).__name__}. A key read from a "
            "file, an environment variable or a secret store can be bytes or None "
            "before anyone has looked at it."
        )
    try:
        encoded = pem.encode()
    except UnicodeEncodeError as exc:
        raise ValueError(f"pem is not encodable as UTF-8: {exc}") from exc
    return serialization.load_pem_private_key(encoded, password=None)  # type: ignore[return-value]


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
    """Return the public JWK dict for *key* (OKP / Ed25519).

    Raises ``ValueError`` for anything that is not an ``Ed25519PrivateKey``. A
    public key is called out separately because it is the plausible mistake here:
    the name reads as "turn a key into a JWK", the result is the *public* JWK, and
    a caller holding only the public half will reach for this. It is not a widening
    this function can make on its own, since ``sign_record`` depends on being handed
    something that can sign; ``_jwk_from_public_key`` is the path for that half.
    """
    if not isinstance(key, Ed25519PrivateKey):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if isinstance(key, Ed25519PublicKey):
            raise ValueError(
                "key_to_jwk needs the private key, not the public one. It derives the "
                "public JWK from it, and its callers go on to sign with the same object."
            )
        raise ValueError(
            f"key must be an Ed25519PrivateKey, got {type(key).__name__}"
        )
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
    if not isinstance(jwk, dict):
        raise ValueError(
            f"jwk must be a JSON object, got {type(jwk).__name__}. A JWK reaches this "
            "function from a peer, a key document or a record's own `cnf`, so its shape "
            "is not something the caller has already established."
        )
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

    A callable that returns a non-bool has also not determined anything, and is
    treated the same way. Reading its answer by truthiness would decide the one
    check here that exists to catch a compromised key, on a value whose truthiness
    means nothing about revocation. The membership branch needs no such guard:
    ``in`` yields a real bool whatever ``__contains__`` returns.
    """
    for identifier in _key_identifiers(jwk):
        try:
            if callable(revocation):
                revoked = revocation(identifier)
                if not isinstance(revoked, bool):
                    # `RevocationStore` is `Callable[[str], bool]`, and a store that
                    # answers with anything else has not answered. Truthiness would
                    # decide it here, and truthiness is unrelated to revocation
                    # status: `None`, `""`, `0` and `[]` would all read as "not
                    # revoked", which is the direction that lets a compromised key
                    # through, while the string "no" would read as revoked. The
                    # `None` case is not hypothetical. It is what a lookup returns
                    # when its author handled the 200 and forgot the rest, which is
                    # exactly the outage this check exists to survive.
                    raise TypeError(
                        f"returned {type(revoked).__name__}, not bool"
                    )
            else:
                revoked = identifier in revocation
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


# The JCS safe-integer range, RFC 8785 Appendix B note 1, which spec section 3.2.2
# raises to a MUST for anything canonicalized under it.
JCS_SAFE_INTEGER = 9007199254740991


class UnanchorableValue(ValueError):
    """A value the registry-anchor profile excludes, found before it was hashed."""


def _reject_unanchorable(value: Any, path: str = "$") -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise UnanchorableValue(
            f"{path} is a non-integer number ({value!r}). registry-anchor-v1 section 1 "
            "puts these outside the profile: cross-language float serialization is not "
            "canonical, so the digest would depend on which language computed it."
        )
    if isinstance(value, int) and abs(value) > JCS_SAFE_INTEGER:
        raise UnanchorableValue(
            f"{path} is {value}, outside -{JCS_SAFE_INTEGER} to {JCS_SAFE_INTEGER}. "
            "registry-anchor-v1 section 1 puts these outside the profile: an "
            "implementation of the same four rules in a language whose only number "
            "type is the IEEE 754 double writes one value for two distinct integers, "
            "so two different claims would share a leaf. Carry the value as a JSON "
            "string. Nanosecond timestamps and 64-bit identifiers land here, and a "
            "digest over one is not reproducible by a peer, which is what anchoring "
            "is for."
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_unanchorable(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_unanchorable(item, f"{path}[{index}]")


def anchor_bytes(value: Any) -> bytes:
    """Sorted-key JSON per registry-anchor-v1 section 1. Deliberately not JCS.

    Section 0 of that document exists because these two canonicalizations are
    easy to confuse, so the one that is not JCS lives next to the one that is.
    They differ on non-ASCII strings, on non-integer numbers, on integers outside
    the safe-integer range, and on key order above the Basic Multilingual Plane.

    Section 1 puts the first two of those outside the profile. Nothing enforced
    that, and the failure it produces is the one section 0 calls out as giving no
    useful diagnostic: a peer in another language recomputes a different digest
    and the only symptom is that a proof does not verify. Refusing the value here,
    by name, is that diagnostic.
    """
    _reject_unanchorable(value)
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except TypeError as exc:
        # `_reject_unanchorable` names the two cases section 1 puts outside the
        # profile. A type JSON cannot serialize at all is a third, and it reached
        # `json.dumps` and came back as "Object of type bytes is not JSON
        # serializable": a message about a serializer, from a function whose stated
        # purpose is to refuse the value by name.
        raise UnanchorableValue(
            f"$ holds a {type(value).__name__}, which is not JSON at all, so it has "
            f"no anchor form: {exc}"
        ) from exc


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

    Raises ``ValueError`` for a *record* that is not a JSON object. ``{**record}``
    reads it before anything establishes its shape, so a non-mapping raised a bare
    ``TypeError`` naming a dict-unpacking failure, which is not the module's
    documented refusal and tells the caller nothing about which argument was wrong.
    """
    if not isinstance(record, dict):
        raise ValueError(
            f"record must be a JSON object, got {type(record).__name__}"
        )
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
    max_future_skew_seconds: int = 300,
    expected_nonce: str | None = None,
    revocation: RevocationStore | None = None,
    revocation_bundle: dict[str, Any] | None = None,
    trusted_bundle_keys: Iterable[dict[str, Any]] | None = None,
    max_bundle_age_seconds: int = 86400,
    now: int | None = None,
) -> VerificationResult:
    """Verify an Ed25519 signature on a signed TRACE Trust Record.

    A trusted key is REQUIRED. Pass an ``Ed25519PublicKey`` or a JWK dict via
    *public_key_or_jwk* to verify against a key the caller already trusts.

    Raises ``InvalidSignature`` if the signature does not verify, and ``ValueError``
    for every other rejection (wrong or missing profile, no signature, no trusted
    key, malformed input, unsupported JWK type, stale record, nonce mismatch, or
    revoked key). Returns a ``VerificationResult`` on success, carrying what the
    revocation check reported; see below. All checks fail closed.

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
        ``record["cnf"]["jwk"]``: this only proves internal consistency, not
        authenticity, and emits a loud ``UserWarning``.

    Freshness (fail closed):
        ``max_age_seconds`` (default 86400 = 24h) bounds how old ``record["iat"]``
        may be relative to now; pass ``None`` to disable the age check.
        ``max_future_skew_seconds`` (default 300 = 5m) bounds tolerated clock skew;
        a record dated further in the future is rejected. If
        ``expected_nonce`` is given, it is compared in constant time against
        ``record["runtime"]["nonce"]``. A stale record or nonce mismatch raises
        ``ValueError``. ``now`` pins the verification moment (Unix epoch seconds)
        for both the record-age check and the bundle-age check below; it defaults
        to the clock, and a conformance vector supplies it so the outcome
        reproduces from retained facts rather than from when the test ran.

    Revocation (reported, never implied):
        ``spec/trace-v0.2.md`` section 3.2.3 separates three states and forbids
        reporting any of them as an affirming appraisal: verified against a
        revocation bundle valid at T; unverified for revocation, because the newest
        bundle is past the profile's maximum age; and no revocation check performed,
        because there was no bundle. The result's ``revocation`` field carries which
        one applied and the facts a second verifier needs to reach it again.

        Pass ``revocation_bundle``, a dict validated here against
        ``schema/trace-revocation-bundle.json``, together with
        ``trusted_bundle_keys``, the JWKs whose signatures the caller accepts on a
        bundle. The bundle is evidence only while both age bounds hold: the
        issuer's ``valid_until`` and the caller's ``max_bundle_age_seconds``,
        measured from ``issued_at``. The tighter bound governs. 86400 is section
        3.2.2's default maximum age, applied to bundles by 3.2.3's "same
        maximum-age model" sentence; 3.2.3 names no bundle default of its own and
        defers the value to the deployment profile. A bundle that is malformed,
        signed by a key not in ``trusted_bundle_keys``, signed with an algorithm
        this build cannot verify, dated in the future, or expired under either
        bound yields ``unverified_for_revocation`` with the cause named; it does
        not raise, because inability to check is not evidence of a defect. A
        statement on the bundle's log naming the trusted key raises ``ValueError``:
        no inclusion entry ID reaches this function, so 3.2.3's fallback applies
        and every record the key signed is rejected.

        ``revocation`` is the older store interface and still works: a container
        of revoked key identifiers or a callable performing a live lookup. The
        trusted key is rejected if it is listed, or if the store cannot answer.
        A store that answers "not listed" is a check performed; the result reports
        ``verified`` with ``source: "store"`` and no horizon, because a store has
        none. Identifiers are the key's RFC 7638 thumbprint (``jwk_thumbprint``)
        and its ``kid``, and the check reads the trusted key, never
        ``record["cnf"]["jwk"]``.

        With neither a bundle nor a store the result reports
        ``no_check_performed``. That is the honest offline default, and it is
        what the old ``None`` return withheld: verification that proves the record
        was validly signed by this key, and nothing about whether the key is still
        trusted. See ``LIMITATIONS.md``.

        The outcome is a value in the result rather than an exception or a
        separate entry point, so a caller has to handle it to know it. A caller
        who discards the return has the fail-open behaviour the old signature
        had; the alternatives were worse, and the reasoning is on issue #190.
    """
    import time
    from hmac import compare_digest

    from agentrust_trace.revocation import (
        NO_CHECK,
        RevocationCheck,
        VerificationResult,
        check_bundle,
    )

    if now is None:
        verification_time = int(time.time())
    elif isinstance(now, bool) or not isinstance(now, int):
        raise ValueError("now must be an integer Unix timestamp in seconds, or None")
    else:
        verification_time = now
    if max_bundle_age_seconds < 0:
        raise ValueError("max_bundle_age_seconds must be non-negative")
    if max_future_skew_seconds < 0:
        raise ValueError("max_future_skew_seconds must be non-negative")

    from cryptography.exceptions import InvalidSignature as _InvalidSignature  # noqa: F401

    # Profile first: refuse semantics this build does not implement before spending
    # any work on the record.
    if not isinstance(record, dict):
        raise ValueError(
            f"record must be a JSON object, got {type(record).__name__}. A Trust Record "
            "is always an object, and what a verifier is handed is by definition not yet "
            "established to be one."
        )
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
                "coexistence: a v0.2 verifier rejects the v0.1 identifier, which "
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

    # Signature validity is not schema validity. Enforce the canonical profile
    # shape here so callers cannot accidentally treat a signed object carrying
    # unknown fields, missing required claims, or invalid nested values as a
    # verified TRACE Trust Record. Signature presence and encoding are checked
    # first so the public API preserves its specific envelope errors.
    from agentrust_trace.validate import validate_json

    try:
        validate_json(record)
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "<record>"
        raise ValueError(
            f"record does not conform to the TRACE v0.2 schema at {location}: {exc.message}"
        ) from exc

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
        trusted_jwk = public_key_or_jwk
    else:
        pub = public_key_or_jwk
        trusted_jwk = _jwk_from_public_key(pub)

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
        _check_not_revoked(trusted_jwk, revocation)

    # What the revocation check reports. The bundle governs when present; a store
    # consulted beside it is recorded as consulted. Neither present: say so.
    revocation_check: RevocationCheck
    if revocation_bundle is not None:
        revocation_check = check_bundle(
            revocation_bundle,
            trusted_key_identifiers=_key_identifiers(trusted_jwk),
            trusted_bundle_keys=trusted_bundle_keys or (),
            now=verification_time,
            max_bundle_age_seconds=max_bundle_age_seconds,
            max_future_skew_seconds=max_future_skew_seconds,
        )
        if revocation is not None:
            revocation_check = RevocationCheck(
                outcome=revocation_check.outcome,
                cause=revocation_check.cause,
                evidence={**revocation_check.evidence, "store": "consulted"},
            )
    elif revocation is not None:
        revocation_check = RevocationCheck(outcome="verified", evidence={"source": "store"})
    else:
        revocation_check = NO_CHECK

    # The signature binding is defined as a signature made by the key in cnf.
    # Verifying with a caller-pinned key is necessary for authenticity, but it
    # must not permit a trusted signer to authenticate a record that names a
    # different confirmation key for downstream proof-of-possession checks.
    cnf = record.get("cnf")
    embedded_jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(embedded_jwk, dict):
        raise ValueError("record has no valid cnf.jwk confirmation key")
    _pubkey_from_jwk(embedded_jwk)
    if not compare_digest(jwk_thumbprint(embedded_jwk), jwk_thumbprint(trusted_jwk)):
        raise ValueError(
            "record cnf.jwk does not identify the trusted key that verifies its signature"
        )

    # Freshness: bound the age of the record against its issued-at timestamp.
    iat = record.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise ValueError("record has no valid integer 'iat' for freshness check")
    age = verification_time - iat
    if age < -max_future_skew_seconds:
        raise ValueError(
            f"record is dated {int(-age)}s in the future, exceeds "
            f"max_future_skew_seconds={max_future_skew_seconds}"
        )
    if max_age_seconds is not None:
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

    return VerificationResult(
        revocation=revocation_check,
        trusted_key_thumbprint=jwk_thumbprint(trusted_jwk),
    )

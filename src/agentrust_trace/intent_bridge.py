"""Verify the optional PIC-CJSON/1.0 to TRACE authorization bridge."""

from __future__ import annotations

import base64
import hashlib
import time
from hmac import compare_digest
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.sign import _b64url_decode, _canonical_bytes, _pubkey_from_jwk

BRIDGE_PROFILE = "tag:agentrust-io.com,2026:pic-trace-bridge-v1"
PIC_PROFILE = "PIC-CJSON/1.0"

__all__ = [
    "BRIDGE_PROFILE", "PIC_PROFILE", "IntentBridgeError", "AuthorizationDenied",
    "AuthorizationMismatch", "digest_jcs", "sign_bridge", "verify_bridge",
]


class IntentBridgeError(ValueError):
    """The bridge is malformed, untrusted, stale, or cannot be evaluated."""


class AuthorizationDenied(IntentBridgeError):
    """The signed decision is not an authorization to execute."""


class AuthorizationMismatch(IntentBridgeError):
    """Execution evidence does not match the signed authorization."""


def _jcs(value: dict[str, Any], what: str) -> bytes:
    """Canonical bytes for *value*, as ``IntentBridgeError`` when there are none.

    ``_canonical_bytes`` is ``rfc8785.dumps`` and raises by design: a value JCS has
    no form for has no canonical bytes to return. Its errors are ``ValueError``
    subclasses, which satisfies ``sign``'s documented contract but not this
    module's: ``rfc8785.CanonicalizationError`` is not an ``IntentBridgeError``, so
    a caller written against this module's own exception does not catch it.

    Four of the five values that trip it are ordinary JSON that ``json.loads``
    accepts, an integer outside the JCS safe range, a non-finite float, and a lone
    surrogate among them, so an authorization assembled from a parsed document
    reaches this.
    """
    try:
        return _canonical_bytes(value)
    except rfc8785.CanonicalizationError as exc:
        raise IntentBridgeError(
            f"{what} has no RFC 8785 canonical form, so it cannot be digested or "
            f"signed: {exc}"
        ) from exc


def digest_jcs(value: dict[str, Any]) -> str:
    """Return the SHA-256 digest of an RFC 8785 canonical JSON object."""
    if not isinstance(value, dict):
        raise IntentBridgeError("a digest input must be a JSON object")
    return f"sha256:{hashlib.sha256(_jcs(value, 'the digest input')).hexdigest()}"


def sign_bridge(authorization: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """Sign the complete authorization; key material is deliberately not embedded."""
    artifact = {"profile": BRIDGE_PROFILE, "authorization": authorization}
    signature = base64.urlsafe_b64encode(key.sign(_jcs(artifact, "the authorization"))).rstrip(b"=")
    return {**artifact, "signature": signature.decode("ascii")}


def _object(value: Any, field: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IntentBridgeError(f"{field} must be an object")
    unknown = set(value) - keys
    if unknown:
        raise IntentBridgeError(f"{field} contains unknown fields: {sorted(unknown)}")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise IntentBridgeError(f"{field} must be a sha256 digest")
    tail = value[7:]
    if len(tail) != 64 or any(c not in "0123456789abcdef" for c in tail):
        raise IntentBridgeError(f"{field} must contain 64 lowercase hexadecimal characters")
    return value


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise IntentBridgeError(f"{field} must be a non-empty string")
    return value


def _unique_nonempty_strings(value: Any, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise IntentBridgeError(f"{field} must be a non-empty array of non-empty strings")
    if len(value) != len(set(value)):
        raise IntentBridgeError(f"{field} must not contain duplicates")
    return value


def verify_bridge(
    bridge: dict[str, Any], trusted_authorizer_jwk: dict[str, Any], *,
    declaration: dict[str, Any], pic_intent_digest: str, pic_args_digest: str,
    tool_call: dict[str, Any], transcript: dict[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify the decision, trusted signature, scope, freshness, and execution binding.

    PIC digests are compared as PIC-defined values and never recomputed here.
    Bridge-specific declaration and tool-call digests use RFC 8785 JCS.  When a
    transcript is required, both its before and after halves must be supplied.
    """
    root = _object(bridge, "bridge", {"profile", "authorization", "signature"})
    if root.get("profile") != BRIDGE_PROFILE:
        raise IntentBridgeError("unknown bridge profile; best-effort parsing is refused")
    signature_value = root.get("signature")
    if not isinstance(signature_value, str):
        raise IntentBridgeError("signature must be a base64url string")
    signature = _b64url_decode(signature_value, field="signature")
    fields = {
        "authorization_id", "decision", "authorizer", "authorizer_key_id",
        "authorized_at", "expires_at", "scope", "pic", "declaration_digest",
        "tool_call_digest", "transcript_required",
    }
    authorization = _object(root.get("authorization"), "authorization", fields)
    missing = fields - set(authorization)
    if missing:
        raise IntentBridgeError(f"authorization is missing fields: {sorted(missing)}")
    for field in ("authorization_id", "authorizer", "authorizer_key_id"):
        _nonempty_string(authorization[field], f"authorization.{field}")

    # Hoisted out of the try below. Inside it, an authorization JCS cannot serialize
    # was reported as "the signature is invalid", which is a different fact and sends
    # the reader to look at a key. There are no bytes for a signature to be checked
    # against, so nothing has been learned about the signature at all.
    body = _jcs({"profile": BRIDGE_PROFILE, "authorization": authorization},
                "the authorization")
    try:
        _pubkey_from_jwk(trusted_authorizer_jwk).verify(signature, body)
    except Exception as exc:
        raise IntentBridgeError("authorization signature is invalid") from exc
    trusted_kid = trusted_authorizer_jwk.get("kid")
    if not isinstance(trusted_kid, str) or trusted_kid != authorization["authorizer_key_id"]:
        raise IntentBridgeError("authorizer_key_id does not identify the trusted key")
    if authorization["decision"] != "allow":
        raise AuthorizationDenied("the signed decision is not allow")
    for field in ("authorized_at", "expires_at"):
        if (
            not isinstance(authorization[field], int)
            or isinstance(authorization[field], bool)
            or authorization[field] < 0
        ):
            raise IntentBridgeError(f"{field} must be a non-negative integer Unix timestamp")
    invalid_now_type = not isinstance(now, (int, type(None))) or isinstance(now, bool)
    if invalid_now_type or (now is not None and now < 0):
        raise IntentBridgeError("now must be a non-negative integer Unix timestamp")
    instant = int(time.time()) if now is None else now
    if instant < authorization["authorized_at"]:
        raise IntentBridgeError("authorization is not yet valid")
    if authorization["expires_at"] <= authorization["authorized_at"]:
        raise IntentBridgeError("expires_at must be after authorized_at")
    if instant >= authorization["expires_at"]:
        raise IntentBridgeError("authorization has expired")

    scope = _object(authorization["scope"], "authorization.scope", {"tools", "impacts"})
    tools = _unique_nonempty_strings(scope.get("tools"), "authorization.scope.tools")
    impacts = _unique_nonempty_strings(scope.get("impacts"), "authorization.scope.impacts")
    if not isinstance(tool_call, dict):
        raise IntentBridgeError("tool_call must be an object")
    if tool_call.get("name") not in tools:
        raise AuthorizationMismatch("executed tool is outside the authorized tool scope")
    if not isinstance(declaration, dict):
        raise IntentBridgeError("declaration must be an object")
    if declaration.get("impact") not in impacts:
        raise AuthorizationMismatch("declaration impact is outside the authorized impact scope")

    pic = _object(
        authorization["pic"], "authorization.pic", {"profile", "intent_digest", "args_digest"}
    )
    if pic.get("profile") != PIC_PROFILE:
        raise IntentBridgeError("authorization.pic.profile is not PIC-CJSON/1.0")
    for name, actual in (("intent_digest", pic_intent_digest), ("args_digest", pic_args_digest)):
        expected = _digest(pic.get(name), f"authorization.pic.{name}")
        _digest(actual, name)
        if not compare_digest(expected, actual):
            raise AuthorizationMismatch(f"PIC {name} does not match the signed authorization")

    digest_pairs = (
        ("declaration_digest", digest_jcs(declaration)),
        ("tool_call_digest", digest_jcs(tool_call)),
    )
    for name, actual in digest_pairs:
        expected = _digest(authorization[name], f"authorization.{name}")
        if not compare_digest(expected, actual):
            raise AuthorizationMismatch(f"{name} does not match the signed authorization")

    if not isinstance(authorization["transcript_required"], bool):
        raise IntentBridgeError("transcript_required must be boolean")
    if authorization["transcript_required"]:
        if not isinstance(transcript, dict) or set(transcript) != {"before", "after"}:
            raise AuthorizationMismatch("a full before/after transcript is required")
        before = transcript.get("before")
        if not isinstance(before, dict) or before.get("tool_call") != tool_call:
            raise AuthorizationMismatch("transcript.before.tool_call does not match execution")
        if not isinstance(transcript.get("after"), dict):
            raise AuthorizationMismatch("transcript.after must contain the execution result")
    return authorization

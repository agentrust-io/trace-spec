"""Independent verifier for the PIC/TRACE bridge conformance corpus.

This module deliberately does not import ``agentrust_trace`` or the fixture
generator. It implements the published bridge contract with RFC 8785 and
Ed25519 primitives so the fixture producer and reference implementation do not
vouch for themselves.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from hmac import compare_digest
from typing import Any
from collections.abc import Collection

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BRIDGE_PROFILE = "tag:agentrust-io.com,2026:pic-trace-bridge-v1"
PIC_PROFILE = "PIC-CJSON/1.0"
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class Rule:
    """One public result code in first-failure evaluation order."""

    code: str
    classification: str
    description: str


# This literal registry is the public rule inventory used by mutation checks.
RULES: tuple[Rule, ...] = (
    Rule("bridge_not_object", "invalid", "bridge root is not an object"),
    Rule("bridge_unknown_fields", "invalid", "bridge root has unknown fields"),
    Rule("bridge_profile_invalid", "invalid", "bridge profile is absent or unsupported"),
    Rule(
        "signature_representation_invalid",
        "invalid",
        "signature is not strict unpadded 86-character base64url",
    ),
    Rule("authorization_not_object", "invalid", "authorization is not an object"),
    Rule("authorization_unknown_fields", "invalid", "authorization has unknown fields"),
    Rule("authorization_fields_missing", "invalid", "authorization lacks required fields"),
    Rule("authorization_id_invalid", "invalid", "authorization_id is not a nonempty string"),
    Rule("authorizer_invalid", "invalid", "authorizer is not a nonempty string"),
    Rule(
        "authorizer_key_id_invalid",
        "invalid",
        "authorizer_key_id is not a nonempty string",
    ),
    Rule("authorization_unverifiable", "invalid", "authorization signature cannot verify"),
    Rule(
        "authorizer_key_id_mismatch",
        "invalid",
        "signed key identifier does not identify the trusted key",
    ),
    Rule("decision_not_allow", "denied", "signed decision is not exact allow"),
    Rule("authorized_at_invalid", "invalid", "authorized_at is not a nonnegative integer"),
    Rule("expires_at_invalid", "invalid", "expires_at is not a nonnegative integer"),
    Rule(
        "verification_time_invalid",
        "invalid",
        "verification time is not a nonnegative integer",
    ),
    Rule("authorization_not_yet_valid", "invalid", "authorization begins after now"),
    Rule("authorization_window_invalid", "invalid", "authorization window is not ordered"),
    Rule("authorization_expired", "invalid", "authorization is expired at now"),
    Rule("scope_not_object", "invalid", "signed scope is not an object"),
    Rule("scope_unknown_fields", "invalid", "signed scope has unknown fields"),
    Rule("scope_tools_invalid", "invalid", "tool scope is not a nonempty string array"),
    Rule("scope_tools_duplicate", "invalid", "tool scope has duplicates"),
    Rule("scope_impacts_invalid", "invalid", "impact scope is not a nonempty string array"),
    Rule("scope_impacts_duplicate", "invalid", "impact scope has duplicates"),
    Rule("tool_call_not_object", "invalid", "runtime tool call is not an object"),
    Rule("tool_outside_scope", "mismatch", "runtime tool is outside signed scope"),
    Rule("declaration_not_object", "invalid", "runtime declaration is not an object"),
    Rule("impact_outside_scope", "mismatch", "runtime impact is outside signed scope"),
    Rule("pic_not_object", "invalid", "signed PIC block is not an object"),
    Rule("pic_unknown_fields", "invalid", "signed PIC block has unknown fields"),
    Rule("pic_profile_invalid", "invalid", "signed PIC profile is unsupported"),
    Rule("pic_intent_digest_invalid", "invalid", "signed or supplied intent digest is invalid"),
    Rule("pic_intent_digest_mismatch", "mismatch", "PIC intent digests differ"),
    Rule("pic_args_digest_invalid", "invalid", "signed or supplied args digest is invalid"),
    Rule("pic_args_digest_mismatch", "mismatch", "PIC args digests differ"),
    Rule(
        "execution_input_not_jcs",
        "invalid",
        "declaration or tool call is outside the RFC 8785 domain",
    ),
    Rule("declaration_digest_invalid", "invalid", "signed declaration digest is invalid"),
    Rule("declaration_digest_mismatch", "mismatch", "declaration digest differs"),
    Rule("tool_call_digest_invalid", "invalid", "signed tool-call digest is invalid"),
    Rule("tool_call_digest_mismatch", "mismatch", "tool-call digest differs"),
    Rule(
        "transcript_requirement_invalid",
        "invalid",
        "signed transcript requirement is not boolean",
    ),
    Rule("transcript_incomplete", "mismatch", "required transcript is not exact before/after"),
    Rule("transcript_before_mismatch", "mismatch", "transcript before half differs"),
    Rule("transcript_after_invalid", "mismatch", "transcript after half is not an object"),
)
RULE_CODES = tuple(rule.code for rule in RULES)
RULE_BY_CODE = {rule.code: rule for rule in RULES}

_BRIDGE_FIELDS = {"profile", "authorization", "signature"}
_AUTHORIZATION_FIELDS = {
    "authorization_id",
    "decision",
    "authorizer",
    "authorizer_key_id",
    "authorized_at",
    "expires_at",
    "scope",
    "pic",
    "declaration_digest",
    "tool_call_digest",
    "transcript_required",
}


def _result(
    classification: str,
    codes: list[str],
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {"classification": classification, "codes": codes, "result": result}


def _failure(code: str, disabled: frozenset[str]) -> dict[str, Any] | None:
    if code in disabled:
        return None
    rule = RULE_BY_CODE[code]
    return _result(rule.classification, [rule.code])


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _string_array(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item) for item in value)
    )


def _timestamp(value: Any) -> bool:
    """Apply JSON integer semantics, including an exact-valued float such as 100.0."""

    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and (not isinstance(value, float) or value.is_integer())
        and value >= 0
    )


def _strict_b64url(value: str) -> bytes:
    if not value or _B64URL_RE.fullmatch(value) is None:
        raise ValueError("not unpadded base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785 bytes without using the reference implementation."""

    return rfc8785.dumps(value)


def digest_jcs(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _verify_signature(
    signature: bytes,
    authorization: dict[str, Any],
    trusted_authorizer_jwk: Any,
) -> bool:
    try:
        if not isinstance(trusted_authorizer_jwk, dict):
            return False
        if trusted_authorizer_jwk.get("kty") != "OKP":
            return False
        if trusted_authorizer_jwk.get("crv") != "Ed25519":
            return False
        x = trusted_authorizer_jwk.get("x")
        if not isinstance(x, str):
            return False
        raw_key = _strict_b64url(x)
        if len(raw_key) != 32:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(raw_key)
        preimage = canonical_bytes({"profile": BRIDGE_PROFILE, "authorization": authorization})
        public_key.verify(signature, preimage)
    except Exception:
        return False
    return True


def verify_bridge_independent(
    bridge: Any,
    trusted_authorizer_jwk: Any,
    *,
    declaration: Any,
    pic_intent_digest: Any,
    pic_args_digest: Any,
    tool_call: Any,
    transcript: Any = None,
    now: Any,
    disabled_codes: Collection[str] = (),
    case003: bool = False,
) -> dict[str, Any]:
    """Return an exact normalized bridge outcome.

    ``disabled_codes`` exists only for rule-deletion mutation measurements. An
    unknown code is rejected so a stale mutation target cannot pass silently.
    """

    disabled = frozenset(disabled_codes)
    unknown_disabled = disabled - set(RULE_CODES)
    if unknown_disabled:
        raise ValueError(f"unknown disabled rule codes: {sorted(unknown_disabled)}")

    if not isinstance(bridge, dict):
        if (outcome := _failure("bridge_not_object", disabled)) is not None:
            return outcome
        root: dict[str, Any] = {}
    else:
        root = bridge

    if set(root) - _BRIDGE_FIELDS:
        if (outcome := _failure("bridge_unknown_fields", disabled)) is not None:
            return outcome
    if root.get("profile") != BRIDGE_PROFILE:
        if (outcome := _failure("bridge_profile_invalid", disabled)) is not None:
            return outcome

    signature_value = root.get("signature")
    signature_valid = (
        isinstance(signature_value, str) and _SIGNATURE_RE.fullmatch(signature_value) is not None
    )
    if not signature_valid:
        if (outcome := _failure("signature_representation_invalid", disabled)) is not None:
            return outcome
    try:
        signature = _strict_b64url(signature_value) if isinstance(signature_value, str) else b""
    except ValueError:
        signature = b""

    authorization_value = root.get("authorization")
    if not isinstance(authorization_value, dict):
        if (outcome := _failure("authorization_not_object", disabled)) is not None:
            return outcome
        authorization: dict[str, Any] = {}
    else:
        authorization = authorization_value

    allowed_fields = _AUTHORIZATION_FIELDS | (
        {"successor_observation_digest"} if case003 else set()
    )
    if set(authorization) - allowed_fields:
        if (outcome := _failure("authorization_unknown_fields", disabled)) is not None:
            return outcome
    if _AUTHORIZATION_FIELDS - set(authorization):
        if (outcome := _failure("authorization_fields_missing", disabled)) is not None:
            return outcome

    for field, code in (
        ("authorization_id", "authorization_id_invalid"),
        ("authorizer", "authorizer_invalid"),
        ("authorizer_key_id", "authorizer_key_id_invalid"),
    ):
        if not _nonempty_string(authorization.get(field)):
            if (outcome := _failure(code, disabled)) is not None:
                return outcome

    signature_verified = _verify_signature(signature, authorization, trusted_authorizer_jwk)
    if not signature_verified:
        if (outcome := _failure("authorization_unverifiable", disabled)) is not None:
            return outcome

    trusted_kid = (
        trusted_authorizer_jwk.get("kid") if isinstance(trusted_authorizer_jwk, dict) else None
    )
    if not isinstance(trusted_kid, str) or trusted_kid != authorization.get("authorizer_key_id"):
        if (outcome := _failure("authorizer_key_id_mismatch", disabled)) is not None:
            return outcome

    if authorization.get("decision") != "allow":
        if (outcome := _failure("decision_not_allow", disabled)) is not None:
            return outcome

    authorized_at_value = authorization.get("authorized_at")
    expires_at_value = authorization.get("expires_at")
    if not _timestamp(authorized_at_value):
        if (outcome := _failure("authorized_at_invalid", disabled)) is not None:
            return outcome
    if not _timestamp(expires_at_value):
        if (outcome := _failure("expires_at_invalid", disabled)) is not None:
            return outcome
    if not (isinstance(now, int) and not isinstance(now, bool) and now >= 0):
        if (outcome := _failure("verification_time_invalid", disabled)) is not None:
            return outcome

    authorized_at = authorized_at_value if _timestamp(authorized_at_value) else 0
    expires_at = expires_at_value if _timestamp(expires_at_value) else 0
    instant = now if isinstance(now, int) and not isinstance(now, bool) else 0
    if instant < authorized_at:
        if (outcome := _failure("authorization_not_yet_valid", disabled)) is not None:
            return outcome
    if expires_at <= authorized_at:
        if (outcome := _failure("authorization_window_invalid", disabled)) is not None:
            return outcome
    if instant >= expires_at:
        if (outcome := _failure("authorization_expired", disabled)) is not None:
            return outcome

    scope_value = authorization.get("scope")
    if not isinstance(scope_value, dict):
        if (outcome := _failure("scope_not_object", disabled)) is not None:
            return outcome
        scope: dict[str, Any] = {}
    else:
        scope = scope_value
    if set(scope) - {"tools", "impacts"}:
        if (outcome := _failure("scope_unknown_fields", disabled)) is not None:
            return outcome

    tools_value = scope.get("tools")
    if not _string_array(tools_value):
        if (outcome := _failure("scope_tools_invalid", disabled)) is not None:
            return outcome
    tools = tools_value if _string_array(tools_value) else []
    if len(tools) != len(set(tools)):
        if (outcome := _failure("scope_tools_duplicate", disabled)) is not None:
            return outcome

    impacts_value = scope.get("impacts")
    if not _string_array(impacts_value):
        if (outcome := _failure("scope_impacts_invalid", disabled)) is not None:
            return outcome
    impacts = impacts_value if _string_array(impacts_value) else []
    if len(impacts) != len(set(impacts)):
        if (outcome := _failure("scope_impacts_duplicate", disabled)) is not None:
            return outcome

    if not isinstance(tool_call, dict):
        if (outcome := _failure("tool_call_not_object", disabled)) is not None:
            return outcome
        tool_call_object: dict[str, Any] = {}
    else:
        tool_call_object = tool_call
    selected_tool = tool_call_object.get("name")
    if selected_tool not in tools:
        if (outcome := _failure("tool_outside_scope", disabled)) is not None:
            return outcome

    if not isinstance(declaration, dict):
        if (outcome := _failure("declaration_not_object", disabled)) is not None:
            return outcome
        declaration_object: dict[str, Any] = {}
    else:
        declaration_object = declaration
    selected_impact = declaration_object.get("impact")
    if selected_impact not in impacts:
        if (outcome := _failure("impact_outside_scope", disabled)) is not None:
            return outcome

    pic_value = authorization.get("pic")
    if not isinstance(pic_value, dict):
        if (outcome := _failure("pic_not_object", disabled)) is not None:
            return outcome
        pic: dict[str, Any] = {}
    else:
        pic = pic_value
    if set(pic) - {"profile", "intent_digest", "args_digest"}:
        if (outcome := _failure("pic_unknown_fields", disabled)) is not None:
            return outcome
    if pic.get("profile") != PIC_PROFILE:
        if (outcome := _failure("pic_profile_invalid", disabled)) is not None:
            return outcome

    for name, supplied, invalid_code, mismatch_code in (
        (
            "intent_digest",
            pic_intent_digest,
            "pic_intent_digest_invalid",
            "pic_intent_digest_mismatch",
        ),
        (
            "args_digest",
            pic_args_digest,
            "pic_args_digest_invalid",
            "pic_args_digest_mismatch",
        ),
    ):
        signed = pic.get(name)
        if not isinstance(signed, str) or _DIGEST_RE.fullmatch(signed) is None:
            if (outcome := _failure(invalid_code, disabled)) is not None:
                return outcome
        if not isinstance(supplied, str) or _DIGEST_RE.fullmatch(supplied) is None:
            if (outcome := _failure(invalid_code, disabled)) is not None:
                return outcome
        signed_text = signed if isinstance(signed, str) else ""
        supplied_text = supplied if isinstance(supplied, str) else ""
        if not compare_digest(signed_text, supplied_text):
            if (outcome := _failure(mismatch_code, disabled)) is not None:
                return outcome

    try:
        computed_declaration_digest = digest_jcs(declaration_object)
        computed_tool_call_digest = digest_jcs(tool_call_object)
    except Exception:
        if (outcome := _failure("execution_input_not_jcs", disabled)) is not None:
            return outcome
        computed_declaration_digest = ""
        computed_tool_call_digest = ""

    for field, computed, invalid_code, mismatch_code in (
        (
            "declaration_digest",
            computed_declaration_digest,
            "declaration_digest_invalid",
            "declaration_digest_mismatch",
        ),
        (
            "tool_call_digest",
            computed_tool_call_digest,
            "tool_call_digest_invalid",
            "tool_call_digest_mismatch",
        ),
    ):
        signed = authorization.get(field)
        if not isinstance(signed, str) or _DIGEST_RE.fullmatch(signed) is None:
            if (outcome := _failure(invalid_code, disabled)) is not None:
                return outcome
        signed_text = signed if isinstance(signed, str) else ""
        if not compare_digest(signed_text, computed):
            if (outcome := _failure(mismatch_code, disabled)) is not None:
                return outcome

    transcript_required = authorization.get("transcript_required")
    if not isinstance(transcript_required, bool):
        if (outcome := _failure("transcript_requirement_invalid", disabled)) is not None:
            return outcome
    if case003 and (
        transcript_required is not True or "successor_observation_digest" not in authorization
    ):
        raise ValueError("case-003 requires a transcript and signed successor digest")
    if transcript_required is True:
        if not isinstance(transcript, dict) or set(transcript) != {"before", "after"}:
            if (outcome := _failure("transcript_incomplete", disabled)) is not None:
                return outcome
            transcript_object: dict[str, Any] = {}
        else:
            transcript_object = transcript
        before = transcript_object.get("before")
        before_matches = isinstance(before, dict) and before.get("tool_call") == tool_call_object
        if case003 and isinstance(before, dict):
            before_matches = (
                canonical_bytes(before.get("tool_call")) == canonical_bytes(tool_call_object)
            )
        if not before_matches:
            if (outcome := _failure("transcript_before_mismatch", disabled)) is not None:
                return outcome
        if not isinstance(transcript_object.get("after"), dict):
            if (outcome := _failure("transcript_after_invalid", disabled)) is not None:
                return outcome

    if case003:
        from case003_independent import binding

        code = binding(transcript["after"], authorization["successor_observation_digest"])
        if code is not None:
            return _result("mismatch", [code])

    accepted = {
        "authorization_id": authorization.get("authorization_id"),
        "tool": selected_tool,
        "impact": selected_impact,
        "transcript_bound": transcript_required is True,
    }
    return _result("accepted", [], accepted)


def verify_bridge(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Compatibility alias with the same normalized return contract."""

    return verify_bridge_independent(*args, **kwargs)


def verify_case(case: dict[str, Any], *, disabled_codes: Collection[str] = ()) -> dict[str, Any]:
    """Evaluate one corpus case without reading its expected result."""

    inputs = case["inputs"]
    reconciled = case.get("profile") == "trace.pic-trace-bridge.case003.v1"
    runtime = verify_bridge_independent(
        inputs["bridge"],
        inputs["trusted_authorizer_jwk"],
        declaration=inputs["declaration"],
        pic_intent_digest=inputs["pic_intent_digest"],
        pic_args_digest=inputs["pic_args_digest"],
        tool_call=inputs["tool_call"],
        transcript=inputs.get("transcript"),
        now=inputs["now"],
        disabled_codes=disabled_codes,
        case003=reconciled,
    )
    if reconciled:
        from case003_independent import finish

        return finish(runtime, inputs, case["successor_policy"])
    return runtime


__all__ = [
    "BRIDGE_PROFILE",
    "PIC_PROFILE",
    "RULES",
    "RULE_CODES",
    "Rule",
    "canonical_bytes",
    "digest_jcs",
    "verify_bridge",
    "verify_bridge_independent",
    "verify_case",
]

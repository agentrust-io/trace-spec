"""Generate the portable PIC/TRACE bridge conformance corpus.

The generator is deliberately independent of agentrust_trace.  It uses only
rfc8785 and cryptography for canonicalization, digesting, key derivation, and
signing so the fixtures do not vouch for themselves through the implementation
under test.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any
from collections.abc import Callable

import rfc8785
import sys

import case003_vectors
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


OUT = Path(__file__).resolve().parent
PROFILE = "trace.pic-trace-bridge.conformance.v1"
BRIDGE_PROFILE = "tag:agentrust-io.com,2026:pic-trace-bridge-v1"
PIC_PROFILE = "PIC-CJSON/1.0"
BASELINE_COMMIT = "3c2f96375afaea6c615c49dea21d83a7969862e3"
TRACKER_247 = "https://github.com/agentrust-io/trace-spec/issues/247"
NOW = 150
SAFE_INTEGER_PLUS_ONE = 9007199254740992

# Published deterministic test-key seeds.  These role-labelled keys have no
# production standing and exist only so every fixture regenerates byte-for-byte.
AUTHORIZER_TEST_SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
OTHER_TEST_SEED_HEX = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
AUTHORIZER_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(AUTHORIZER_TEST_SEED_HEX))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(OTHER_TEST_SEED_HEX))


INVALID_CODES = (
    "bridge_not_object",
    "bridge_unknown_fields",
    "bridge_profile_invalid",
    "signature_representation_invalid",
    "authorization_not_object",
    "authorization_unknown_fields",
    "authorization_fields_missing",
    "authorization_id_invalid",
    "authorizer_invalid",
    "authorizer_key_id_invalid",
    "authorization_unverifiable",
    "authorizer_key_id_mismatch",
    "authorized_at_invalid",
    "expires_at_invalid",
    "verification_time_invalid",
    "authorization_not_yet_valid",
    "authorization_window_invalid",
    "authorization_expired",
    "scope_not_object",
    "scope_unknown_fields",
    "scope_tools_invalid",
    "scope_tools_duplicate",
    "scope_impacts_invalid",
    "scope_impacts_duplicate",
    "tool_call_not_object",
    "declaration_not_object",
    "pic_not_object",
    "pic_unknown_fields",
    "pic_profile_invalid",
    "pic_intent_digest_invalid",
    "pic_args_digest_invalid",
    "execution_input_not_jcs",
    "declaration_digest_invalid",
    "tool_call_digest_invalid",
    "transcript_requirement_invalid",
)
DENIED_CODES = ("decision_not_allow",)
MISMATCH_CODES = (
    "tool_outside_scope",
    "impact_outside_scope",
    "pic_intent_digest_mismatch",
    "pic_args_digest_mismatch",
    "declaration_digest_mismatch",
    "tool_call_digest_mismatch",
    "transcript_incomplete",
    "transcript_before_mismatch",
    "transcript_after_invalid",
)
APPROVED_CODES = INVALID_CODES + DENIED_CODES + MISMATCH_CODES


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jcs(value: Any) -> bytes:
    return rfc8785.dumps(value)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest(value: dict[str, Any]) -> str:
    return _sha256(_jcs(value))


def _jwk(key: Ed25519PrivateKey, *, kid: str | None = "key-206") -> dict[str, Any]:
    public = key.public_key().public_bytes_raw()
    value: dict[str, Any] = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(public)}
    if kid is not None:
        value["kid"] = kid
    return value


def _sign_authorization(authorization: dict[str, Any]) -> str:
    preimage = _jcs({"profile": BRIDGE_PROFILE, "authorization": authorization})
    return _b64url(AUTHORIZER_KEY.sign(preimage))


def _signed_bridge(authorization: dict[str, Any]) -> dict[str, Any]:
    authorization = copy.deepcopy(authorization)
    return {
        "profile": BRIDGE_PROFILE,
        "authorization": authorization,
        "signature": _sign_authorization(authorization),
    }


def _base_inputs() -> dict[str, Any]:
    declaration = {
        "impact": "external-side-effect",
        "purpose": "send invoice",
        "metadata": {"channel": "email", "reference": "INV-7"},
    }
    tool_call = {
        "name": "send_invoice",
        "arguments": {"invoice_id": "INV-7", "options": {"notify": True}},
    }
    intent_digest = "sha256:" + "1" * 64
    args_digest = "sha256:" + "2" * 64
    authorization = {
        "authorization_id": "auth-206",
        "decision": "allow",
        "authorizer": "policy-engine",
        "authorizer_key_id": "key-206",
        "authorized_at": 100,
        "expires_at": 200,
        "scope": {
            "tools": ["send_invoice", "archive_invoice"],
            "impacts": ["external-side-effect", "internal-side-effect"],
        },
        "pic": {
            "profile": PIC_PROFILE,
            "intent_digest": intent_digest,
            "args_digest": args_digest,
        },
        "declaration_digest": _digest(declaration),
        "tool_call_digest": _digest(tool_call),
        "transcript_required": True,
    }
    return {
        "bridge": _signed_bridge(authorization),
        "trusted_authorizer_jwk": _jwk(AUTHORIZER_KEY),
        "declaration": declaration,
        "pic_intent_digest": intent_digest,
        "pic_args_digest": args_digest,
        "tool_call": tool_call,
        "transcript": {
            "before": {"tool_call": copy.deepcopy(tool_call)},
            "after": {"status": "accepted", "receipt_id": "receipt-206"},
        },
        "now": NOW,
    }


def _resign(inputs: dict[str, Any]) -> None:
    bridge = inputs["bridge"]
    authorization = bridge["authorization"]
    bridge["signature"] = _sign_authorization(authorization)


def _bind_declaration(inputs: dict[str, Any]) -> None:
    inputs["bridge"]["authorization"]["declaration_digest"] = _digest(inputs["declaration"])
    _resign(inputs)


def _bind_tool_call(inputs: dict[str, Any]) -> None:
    inputs["bridge"]["authorization"]["tool_call_digest"] = _digest(inputs["tool_call"])
    transcript = inputs.get("transcript")
    if isinstance(transcript, dict) and isinstance(transcript.get("before"), dict):
        transcript["before"]["tool_call"] = copy.deepcopy(inputs["tool_call"])
    _resign(inputs)


def _auth_mutation(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    inputs = _base_inputs()
    change(inputs["bridge"]["authorization"])
    _resign(inputs)
    return inputs


def _input_mutation(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    inputs = _base_inputs()
    change(inputs)
    return inputs


def _material(value: Any, *, not_object: str, not_jcs: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"applicable": False, "reason": not_object}
    try:
        preimage = _jcs(value)
    except Exception:
        return {"applicable": False, "reason": not_jcs}
    return {
        "applicable": True,
        "canonical_preimage_base64url": _b64url(preimage),
        "canonical_preimage_sha256": _sha256(preimage),
    }


def _reproducibility(inputs: dict[str, Any]) -> dict[str, Any]:
    bridge = inputs.get("bridge")
    if not isinstance(bridge, dict):
        authorization_signature = {"applicable": False, "reason": "bridge_not_object"}
    elif bridge.get("profile") != BRIDGE_PROFILE:
        authorization_signature = {
            "applicable": False,
            "reason": "bridge_profile_invalid",
        }
    elif not isinstance(bridge.get("authorization"), dict):
        authorization_signature = {
            "applicable": False,
            "reason": "authorization_not_object",
        }
    else:
        authorization_signature = _material(
            {"profile": BRIDGE_PROFILE, "authorization": bridge["authorization"]},
            not_object="authorization_not_object",
            not_jcs="authorization_preimage_not_jcs",
        )
    return {
        "authorization_signature": authorization_signature,
        "declaration_digest": _material(
            inputs.get("declaration"),
            not_object="declaration_not_object",
            not_jcs="declaration_preimage_not_jcs",
        ),
        "tool_call_digest": _material(
            inputs.get("tool_call"),
            not_object="tool_call_not_object",
            not_jcs="tool_call_preimage_not_jcs",
        ),
    }


def _accepted_runtime(inputs: dict[str, Any]) -> dict[str, Any]:
    authorization = inputs["bridge"]["authorization"]
    return {
        "classification": "accepted",
        "codes": [],
        "result": {
            "authorization_id": authorization["authorization_id"],
            "tool": inputs["tool_call"]["name"],
            "impact": inputs["declaration"]["impact"],
            "transcript_bound": authorization["transcript_required"],
        },
    }


def _negative_runtime(classification: str, code: str) -> dict[str, Any]:
    return {"classification": classification, "codes": [code], "result": None}


def _case(
    *,
    slug: str,
    description: str,
    inputs: dict[str, Any],
    bridge_schema_valid: bool,
    runtime: dict[str, Any],
    rule: str | None,
    variant: str,
    declared_defect: str | None,
    known_defect_reference: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if known_defect_reference is None:
        conformance: dict[str, Any] = {"status": "conformant"}
    else:
        conformance = {
            "status": "known_defect",
            "tracker": TRACKER_247,
            "counted_as_conformance": False,
            "reference": {
                "implementation": "agentrust_trace.intent_bridge.verify_bridge",
                "baseline_commit": BASELINE_COMMIT,
                "runtime": known_defect_reference,
            },
        }
    return {
        "name": slug,
        "description": description,
        "profile": PROFILE,
        "conformance": conformance,
        "inputs": inputs,
        "reproducibility": _reproducibility(inputs),
        "coverage": {
            "rule": rule,
            "variant": variant,
            "declared_defect": declared_defect,
        },
        "expected": {
            "case_schema": "valid",
            "bridge_schema": "valid" if bridge_schema_valid else "invalid",
            "conformant_runtime": runtime,
        },
    }


def _negative_case(
    cases: list[dict[str, Any]],
    *,
    slug: str,
    rule: str,
    variant: str,
    declared_defect: str,
    inputs: dict[str, Any],
    bridge_schema_valid: bool,
    classification: str = "invalid",
) -> None:
    cases.append(
        _case(
            slug=slug,
            description=(
                f"{variant.replace('_', ' ')} exercises {rule} and must produce "
                f"the exact {classification} classification and code."
            ),
            inputs=inputs,
            bridge_schema_valid=bridge_schema_valid,
            runtime=_negative_runtime(classification, rule),
            rule=rule,
            variant=variant,
            declared_defect=declared_defect,
        )
    )


def _changed_hex_digest(value: str, index: int, replacement: str = "3") -> str:
    chars = list(value)
    position = 7 + index
    assert chars[position] != replacement
    chars[position] = replacement
    return "".join(chars)


def build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    # Accepted controls; only case 003 uses the reconciled successor contract.
    inputs = _base_inputs()
    cases.append(
        _case(
            slug="accepted-baseline",
            description="A fully bound, correctly signed authorization is accepted.",
            inputs=inputs,
            bridge_schema_valid=True,
            runtime=_accepted_runtime(inputs),
            rule=None,
            variant="accepted_baseline",
            declared_defect=None,
        )
    )

    inputs = _auth_mutation(lambda a: a.__setitem__("transcript_required", False))
    inputs["transcript"] = None
    cases.append(
        _case(
            slug="accepted-transcript-not-required",
            description="No transcript is required when the signed requirement is false.",
            inputs=inputs,
            bridge_schema_valid=True,
            runtime=_accepted_runtime(inputs),
            rule=None,
            variant="transcript_not_required",
            declared_defect="requires_transcript_unconditionally",
        )
    )

    cases.append(case003_vectors.build(sys.modules[__name__]))

    inputs = _auth_mutation(lambda a: a.__setitem__("authorizer", "política-机密"))
    cases.append(
        _case(
            slug="accepted-jcs-non-ascii-values",
            description="BMP non-ASCII values remain literal UTF-8 under RFC 8785.",
            inputs=inputs,
            bridge_schema_valid=True,
            runtime=_accepted_runtime(inputs),
            rule=None,
            variant="jcs_non_ascii_values",
            declared_defect="ascii_escaping_canonicalizer",
        )
    )

    inputs = _auth_mutation(lambda a: a.__setitem__("authorization_id", "auth-206-🤖"))
    cases.append(
        _case(
            slug="accepted-jcs-non-bmp-values",
            description="Supplementary-plane values remain literal UTF-8 under RFC 8785.",
            inputs=inputs,
            bridge_schema_valid=True,
            runtime=_accepted_runtime(inputs),
            rule=None,
            variant="jcs_non_bmp_values",
            declared_defect="surrogate_escape_canonicalizer",
        )
    )

    inputs = _base_inputs()
    inputs["declaration"]["zk😀"] = "sorts-first-under-rfc-8785"
    inputs["declaration"]["zk�"] = "sorts-second-under-rfc-8785"
    _bind_declaration(inputs)
    cases.append(
        _case(
            slug="accepted-jcs-utf16-key-order",
            description="Declaration digesting uses UTF-16 code-unit key order.",
            inputs=inputs,
            bridge_schema_valid=True,
            runtime=_accepted_runtime(inputs),
            rule=None,
            variant="jcs_utf16_key_order",
            declared_defect="code_point_key_sort",
        )
    )

    inputs = _base_inputs()
    inputs["tool_call"]["arguments"]["zmeta"] = {
        "zk😀": "sorts-first-under-rfc-8785",
        "zk�": "sorts-second-under-rfc-8785",
    }
    _bind_tool_call(inputs)
    cases.append(
        _case(
            slug="accepted-jcs-utf16-key-order-nested",
            description=(
                "Nested tool-call digesting preserves UTF-16 code-unit key order "
                "recursively."
            ),
            inputs=inputs,
            bridge_schema_valid=True,
            runtime=_accepted_runtime(inputs),
            rule=None,
            variant="jcs_utf16_key_order_nested",
            declared_defect="shallow_utf16_key_sort",
        )
    )

    # Invalid classification.
    for slug, value, variant in (
        ("bridge-null", None, "null_bridge"),
        ("bridge-array", [], "array_bridge"),
    ):
        inputs = _base_inputs()
        inputs["bridge"] = value
        _negative_case(
            cases,
            slug=slug,
            rule="bridge_not_object",
            variant=variant,
            declared_defect="reject_null_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    for field in ("nonce", "version"):
        inputs = _base_inputs()
        inputs["bridge"][field] = "unexpected"
        _negative_case(
            cases,
            slug=f"bridge-unknown-{field}",
            rule="bridge_unknown_fields",
            variant=f"unknown_{field}",
            declared_defect="reject_nonce_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    inputs = _base_inputs()
    inputs["bridge"].pop("profile")
    _negative_case(
        cases,
        slug="bridge-profile-missing",
        rule="bridge_profile_invalid",
        variant="profile_missing",
        declared_defect="default_missing_profile_to_v1",
        inputs=inputs,
        bridge_schema_valid=False,
    )
    inputs = _base_inputs()
    inputs["bridge"]["profile"] = "tag:example.invalid,2026:bridge"
    _negative_case(
        cases,
        slug="bridge-profile-wrong",
        rule="bridge_profile_invalid",
        variant="profile_wrong",
        declared_defect="default_missing_profile_to_v1",
        inputs=inputs,
        bridge_schema_valid=False,
    )

    inputs = _base_inputs()
    inputs["bridge"].pop("signature")
    _negative_case(
        cases,
        slug="signature-missing",
        rule="signature_representation_invalid",
        variant="signature_missing",
        declared_defect="string_type_only",
        inputs=inputs,
        bridge_schema_valid=False,
    )
    inputs = _base_inputs()
    inputs["bridge"]["signature"] = 7
    _negative_case(
        cases,
        slug="signature-non-string",
        rule="signature_representation_invalid",
        variant="signature_non_string",
        declared_defect="string_type_only",
        inputs=inputs,
        bridge_schema_valid=False,
    )
    inputs = _base_inputs()
    inputs["bridge"]["signature"] = "A"
    _negative_case(
        cases,
        slug="signature-decoder-rejected",
        rule="signature_representation_invalid",
        variant="signature_decoder_rejected",
        declared_defect="string_type_only",
        inputs=inputs,
        bridge_schema_valid=False,
    )

    inputs = _base_inputs()
    inputs["bridge"].pop("authorization")
    _negative_case(
        cases,
        slug="authorization-missing",
        rule="authorization_not_object",
        variant="authorization_missing",
        declared_defect="reject_missing_only",
        inputs=inputs,
        bridge_schema_valid=False,
    )
    inputs = _base_inputs()
    inputs["bridge"]["authorization"] = []
    _negative_case(
        cases,
        slug="authorization-array",
        rule="authorization_not_object",
        variant="authorization_array",
        declared_defect="reject_missing_only",
        inputs=inputs,
        bridge_schema_valid=False,
    )

    for field in ("nonce", "conditions"):
        inputs = _auth_mutation(lambda a, f=field: a.__setitem__(f, "unexpected"))
        _negative_case(
            cases,
            slug=f"authorization-unknown-{field}",
            rule="authorization_unknown_fields",
            variant=f"unknown_{field}",
            declared_defect="reject_nonce_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    for field in ("decision", "scope"):
        inputs = _auth_mutation(lambda a, f=field: a.pop(f))
        _negative_case(
            cases,
            slug=f"authorization-missing-{field}",
            rule="authorization_fields_missing",
            variant=f"missing_{field}",
            declared_defect="checks_decision_presence_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    for rule, field in (
        ("authorization_id_invalid", "authorization_id"),
        ("authorizer_invalid", "authorizer"),
        ("authorizer_key_id_invalid", "authorizer_key_id"),
    ):
        for suffix, value in (("empty", ""), ("non-string", 7)):
            inputs = _auth_mutation(lambda a, f=field, v=value: a.__setitem__(f, v))
            _negative_case(
                cases,
                slug=f"{field.replace('_', '-')}-{suffix}",
                rule=rule,
                variant=f"{field}_{suffix.replace('-', '_')}",
                declared_defect="empty_string_only",
                inputs=inputs,
                bridge_schema_valid=False,
            )

    # Broad post-decode signal: all signatures retain a schema-valid representation.
    inputs = _base_inputs()
    signature = inputs["bridge"]["signature"]
    inputs["bridge"]["signature"] = ("B" if signature[0] == "A" else "A") + signature[1:]
    _negative_case(
        cases,
        slug="authorization-signature-tampered",
        rule="authorization_unverifiable",
        variant="valid_length_signature_tamper",
        declared_defect="key_shape_only_without_crypto",
        inputs=inputs,
        bridge_schema_valid=True,
    )
    inputs = _base_inputs()
    inputs["trusted_authorizer_jwk"] = _jwk(OTHER_KEY)
    _negative_case(
        cases,
        slug="authorization-wrong-trusted-key",
        rule="authorization_unverifiable",
        variant="wrong_trusted_public_key",
        declared_defect="key_shape_only_without_crypto",
        inputs=inputs,
        bridge_schema_valid=True,
    )
    inputs = _base_inputs()
    inputs["trusted_authorizer_jwk"] = {
        "kty": "EC",
        "crv": "Ed25519",
        "x": inputs["trusted_authorizer_jwk"]["x"],
        "kid": "key-206",
    }
    _negative_case(
        cases,
        slug="authorization-malformed-trusted-jwk",
        rule="authorization_unverifiable",
        variant="malformed_trusted_jwk",
        declared_defect="key_shape_only_without_crypto",
        inputs=inputs,
        bridge_schema_valid=True,
    )
    inputs = _base_inputs()
    inputs["bridge"]["authorization"]["expires_at"] = SAFE_INTEGER_PLUS_ONE
    _negative_case(
        cases,
        slug="authorization-timestamp-outside-jcs-domain",
        rule="authorization_unverifiable",
        variant="safe_integer_timestamp_collapse",
        declared_defect="key_shape_only_without_crypto",
        inputs=inputs,
        bridge_schema_valid=False,
    )

    inputs = _base_inputs()
    inputs["trusted_authorizer_jwk"].pop("kid")
    _negative_case(
        cases,
        slug="trusted-kid-missing",
        rule="authorizer_key_id_mismatch",
        variant="trusted_kid_missing",
        declared_defect="compare_only_when_kid_present",
        inputs=inputs,
        bridge_schema_valid=True,
    )
    inputs = _base_inputs()
    inputs["trusted_authorizer_jwk"]["kid"] = "other-key"
    _negative_case(
        cases,
        slug="trusted-kid-different",
        rule="authorizer_key_id_mismatch",
        variant="trusted_kid_different",
        declared_defect="compare_only_when_kid_present",
        inputs=inputs,
        bridge_schema_valid=True,
    )

    for rule, field, good in (
        ("authorized_at_invalid", "authorized_at", 100),
        ("expires_at_invalid", "expires_at", 200),
    ):
        for suffix, value in (("negative", -1), ("string", str(good))):
            inputs = _auth_mutation(lambda a, f=field, v=value: a.__setitem__(f, v))
            _negative_case(
                cases,
                slug=f"{field.replace('_', '-')}-{suffix}",
                rule=rule,
                variant=f"{field}_{suffix}",
                declared_defect="minimum_only",
                inputs=inputs,
                bridge_schema_valid=False,
            )

    for suffix, value in (("negative", -1), ("string", "150")):
        inputs = _base_inputs()
        inputs["now"] = value
        _negative_case(
            cases,
            slug=f"verification-time-{suffix}",
            rule="verification_time_invalid",
            variant=f"verification_time_{suffix}",
            declared_defect="minimum_only",
            inputs=inputs,
            bridge_schema_valid=True,
        )

    for suffix, value in (("boundary", 99), ("far", 0)):
        inputs = _base_inputs()
        inputs["now"] = value
        _negative_case(
            cases,
            slug=f"authorization-not-yet-valid-{suffix}",
            rule="authorization_not_yet_valid",
            variant=f"not_yet_valid_{suffix}",
            declared_defect="one_second_clock_tolerance",
            inputs=inputs,
            bridge_schema_valid=True,
        )

    inputs = _auth_mutation(lambda a: a.__setitem__("expires_at", 100))
    inputs["now"] = 100
    _negative_case(
        cases,
        slug="authorization-window-equal",
        rule="authorization_window_invalid",
        variant="window_equal_endpoints",
        declared_defect="strict_less_only",
        inputs=inputs,
        bridge_schema_valid=True,
    )
    inputs = _auth_mutation(lambda a: a.__setitem__("expires_at", 99))
    inputs["now"] = 100
    _negative_case(
        cases,
        slug="authorization-window-reversed",
        rule="authorization_window_invalid",
        variant="window_reversed",
        declared_defect="strict_less_only",
        inputs=inputs,
        bridge_schema_valid=True,
    )

    for suffix, value in (("boundary", 200), ("after", 201)):
        inputs = _base_inputs()
        inputs["now"] = value
        _negative_case(
            cases,
            slug=f"authorization-expired-{suffix}",
            rule="authorization_expired",
            variant=f"expired_{suffix}",
            declared_defect="strict_greater_only",
            inputs=inputs,
            bridge_schema_valid=True,
        )

    for suffix, value in (("null", None), ("array", [])):
        inputs = _auth_mutation(lambda a, v=value: a.__setitem__("scope", v))
        _negative_case(
            cases,
            slug=f"scope-{suffix}",
            rule="scope_not_object",
            variant=f"scope_{suffix}",
            declared_defect="reject_null_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    for field in ("regions", "principals"):
        inputs = _auth_mutation(lambda a, f=field: a["scope"].__setitem__(f, ["unexpected"]))
        _negative_case(
            cases,
            slug=f"scope-unknown-{field}",
            rule="scope_unknown_fields",
            variant=f"scope_unknown_{field}",
            declared_defect="reject_regions_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    for rule, field in (("scope_tools_invalid", "tools"), ("scope_impacts_invalid", "impacts")):
        for suffix, value in (("empty-array", []), ("empty-item", [""])):
            inputs = _auth_mutation(lambda a, f=field, v=value: a["scope"].__setitem__(f, v))
            _negative_case(
                cases,
                slug=f"scope-{field.replace('_', '-')}-{suffix}",
                rule=rule,
                variant=f"{field}_{suffix.replace('-', '_')}",
                declared_defect="min_items_only",
                inputs=inputs,
                bridge_schema_valid=False,
            )

    for rule, field, first, middle in (
        ("scope_tools_duplicate", "tools", "send_invoice", "archive_invoice"),
        ("scope_impacts_duplicate", "impacts", "external-side-effect", "internal-side-effect"),
    ):
        for suffix, value in (
            ("adjacent", [first, first]),
            ("separated", [first, middle, first]),
        ):
            inputs = _auth_mutation(lambda a, f=field, v=value: a["scope"].__setitem__(f, v))
            _negative_case(
                cases,
                slug=f"scope-{field}-{suffix}-duplicate",
                rule=rule,
                variant=f"{field}_{suffix}_duplicate",
                declared_defect="adjacent_duplicates_only",
                inputs=inputs,
                bridge_schema_valid=False,
            )

    for rule, field in (
        ("tool_call_not_object", "tool_call"),
        ("declaration_not_object", "declaration"),
    ):
        for suffix, value in (("null", None), ("array", [])):
            inputs = _base_inputs()
            inputs[field] = value
            _negative_case(
                cases,
                slug=f"{field.replace('_', '-')}-{suffix}",
                rule=rule,
                variant=f"{field}_{suffix}",
                declared_defect="reject_null_only",
                inputs=inputs,
                bridge_schema_valid=True,
            )

    for suffix, value in (("null", None), ("array", [])):
        inputs = _auth_mutation(lambda a, v=value: a.__setitem__("pic", v))
        _negative_case(
            cases,
            slug=f"pic-{suffix}",
            rule="pic_not_object",
            variant=f"pic_{suffix}",
            declared_defect="reject_null_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    for field in ("algorithm", "version"):
        inputs = _auth_mutation(lambda a, f=field: a["pic"].__setitem__(f, "unexpected"))
        _negative_case(
            cases,
            slug=f"pic-unknown-{field}",
            rule="pic_unknown_fields",
            variant=f"pic_unknown_{field}",
            declared_defect="reject_algorithm_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    inputs = _auth_mutation(lambda a: a["pic"].pop("profile"))
    _negative_case(
        cases,
        slug="pic-profile-missing",
        rule="pic_profile_invalid",
        variant="pic_profile_missing",
        declared_defect="default_missing_pic_profile",
        inputs=inputs,
        bridge_schema_valid=False,
    )
    inputs = _auth_mutation(lambda a: a["pic"].__setitem__("profile", "PIC-OTHER/1.0"))
    _negative_case(
        cases,
        slug="pic-profile-wrong",
        rule="pic_profile_invalid",
        variant="pic_profile_wrong",
        declared_defect="default_missing_pic_profile",
        inputs=inputs,
        bridge_schema_valid=False,
    )

    for rule, field, supplied in (
        ("pic_intent_digest_invalid", "intent_digest", "pic_intent_digest"),
        ("pic_args_digest_invalid", "args_digest", "pic_args_digest"),
    ):
        malformed = "sha256:" + "A" * 64
        inputs = _auth_mutation(
            lambda a, f=field, value=malformed: a["pic"].__setitem__(f, value)
        )
        _negative_case(
            cases,
            slug=f"pic-{field.replace('_', '-')}-signed-syntax",
            rule=rule,
            variant=f"signed_{field}_syntax",
            declared_defect="validate_signed_digest_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )
        inputs = _base_inputs()
        inputs[supplied] = malformed
        _negative_case(
            cases,
            slug=f"pic-{field.replace('_', '-')}-supplied-syntax",
            rule=rule,
            variant=f"supplied_{field}_syntax",
            declared_defect="validate_signed_digest_only",
            inputs=inputs,
            bridge_schema_valid=True,
        )

    inputs = _base_inputs()
    inputs["declaration"]["unsafe_integer"] = SAFE_INTEGER_PLUS_ONE
    _negative_case(
        cases,
        slug="declaration-not-jcs",
        rule="execution_input_not_jcs",
        variant="declaration_outside_jcs_domain",
        declared_defect="check_declaration_jcs_only",
        inputs=inputs,
        bridge_schema_valid=True,
    )
    inputs = _base_inputs()
    inputs["tool_call"]["arguments"]["unsafe_integer"] = SAFE_INTEGER_PLUS_ONE
    _negative_case(
        cases,
        slug="tool-call-not-jcs",
        rule="execution_input_not_jcs",
        variant="tool_call_outside_jcs_domain",
        declared_defect="check_declaration_jcs_only",
        inputs=inputs,
        bridge_schema_valid=True,
    )

    for rule, field in (
        ("declaration_digest_invalid", "declaration_digest"),
        ("tool_call_digest_invalid", "tool_call_digest"),
    ):
        for suffix, value in (
            ("wrong-prefix", "sha512:" + "a" * 64),
            ("short-tail", "sha256:" + "a" * 63),
        ):
            inputs = _auth_mutation(lambda a, f=field, v=value: a.__setitem__(f, v))
            _negative_case(
                cases,
                slug=f"{field.replace('_', '-')}-{suffix}",
                rule=rule,
                variant=f"{field}_{suffix.replace('-', '_')}",
                declared_defect="prefix_only",
                inputs=inputs,
                bridge_schema_valid=False,
            )

    for suffix, value in (("integer", 1), ("string", "true")):
        inputs = _auth_mutation(lambda a, v=value: a.__setitem__("transcript_required", v))
        _negative_case(
            cases,
            slug=f"transcript-requirement-{suffix}",
            rule="transcript_requirement_invalid",
            variant=f"transcript_requirement_{suffix}",
            declared_defect="reject_string_only",
            inputs=inputs,
            bridge_schema_valid=False,
        )

    # Denied classification.
    for suffix, value, schema_valid in (("deny", "deny", True), ("unknown", "review", False)):
        inputs = _auth_mutation(lambda a, v=value: a.__setitem__("decision", v))
        _negative_case(
            cases,
            slug=f"decision-{suffix}",
            rule="decision_not_allow",
            variant=f"decision_{suffix}",
            declared_defect="deny_literal_only",
            inputs=inputs,
            bridge_schema_valid=schema_valid,
            classification="denied",
        )

    # Mismatch classification.  Rebind execution digests where scope alone is tested.
    inputs = _base_inputs()
    inputs["tool_call"] = {"arguments": {"invoice_id": "INV-7"}}
    _bind_tool_call(inputs)
    _negative_case(
        cases,
        slug="tool-scope-name-missing",
        rule="tool_outside_scope",
        variant="tool_name_missing",
        declared_defect="name_presence_only",
        inputs=inputs,
        bridge_schema_valid=True,
        classification="mismatch",
    )
    inputs = _base_inputs()
    inputs["tool_call"]["name"] = "delete_invoice"
    _bind_tool_call(inputs)
    _negative_case(
        cases,
        slug="tool-scope-unlisted",
        rule="tool_outside_scope",
        variant="tool_name_unlisted",
        declared_defect="name_presence_only",
        inputs=inputs,
        bridge_schema_valid=True,
        classification="mismatch",
    )

    inputs = _base_inputs()
    inputs["declaration"].pop("impact")
    _bind_declaration(inputs)
    _negative_case(
        cases,
        slug="impact-scope-missing",
        rule="impact_outside_scope",
        variant="impact_missing",
        declared_defect="impact_presence_only",
        inputs=inputs,
        bridge_schema_valid=True,
        classification="mismatch",
    )
    inputs = _base_inputs()
    inputs["declaration"]["impact"] = "public-side-effect"
    _bind_declaration(inputs)
    _negative_case(
        cases,
        slug="impact-scope-unlisted",
        rule="impact_outside_scope",
        variant="impact_unlisted",
        declared_defect="impact_presence_only",
        inputs=inputs,
        bridge_schema_valid=True,
        classification="mismatch",
    )

    for rule, supplied in (
        ("pic_intent_digest_mismatch", "pic_intent_digest"),
        ("pic_args_digest_mismatch", "pic_args_digest"),
    ):
        for suffix, index in (("first", 0), ("last", 63)):
            inputs = _base_inputs()
            inputs[supplied] = _changed_hex_digest(inputs[supplied], index)
            _negative_case(
                cases,
                slug=f"{supplied.replace('_', '-')}-mismatch-{suffix}",
                rule=rule,
                variant=f"{supplied}_mismatch_{suffix}",
                declared_defect="digest_prefix_compare",
                inputs=inputs,
                bridge_schema_valid=True,
                classification="mismatch",
            )

    for rule, field in (
        ("declaration_digest_mismatch", "declaration_digest"),
        ("tool_call_digest_mismatch", "tool_call_digest"),
    ):
        for suffix, index in (("first", 0), ("last", 63)):
            inputs = _base_inputs()
            authorization = inputs["bridge"]["authorization"]
            authorization[field] = _changed_hex_digest(authorization[field], index)
            _resign(inputs)
            _negative_case(
                cases,
                slug=f"{field.replace('_', '-')}-mismatch-{suffix}",
                rule=rule,
                variant=f"{field}_mismatch_{suffix}",
                declared_defect="digest_prefix_compare",
                inputs=inputs,
                bridge_schema_valid=True,
                classification="mismatch",
            )

    inputs = _base_inputs()
    inputs["transcript"] = None
    _negative_case(
        cases,
        slug="transcript-incomplete-absent",
        rule="transcript_incomplete",
        variant="transcript_absent",
        declared_defect="truthiness_only",
        inputs=inputs,
        bridge_schema_valid=True,
        classification="mismatch",
    )
    inputs = _base_inputs()
    inputs["transcript"]["extra"] = {}
    _negative_case(
        cases,
        slug="transcript-incomplete-extra-key",
        rule="transcript_incomplete",
        variant="transcript_extra_key",
        declared_defect="truthiness_only",
        inputs=inputs,
        bridge_schema_valid=True,
        classification="mismatch",
    )

    inputs = _base_inputs()
    inputs["transcript"]["before"] = None
    _negative_case(
        cases,
        slug="transcript-before-null",
        rule="transcript_before_mismatch",
        variant="transcript_before_null",
        declared_defect="before_object_shape_only",
        inputs=inputs,
        bridge_schema_valid=True,
        classification="mismatch",
    )
    inputs = _base_inputs()
    inputs["transcript"]["before"]["tool_call"] = {"name": "other", "arguments": {}}
    _negative_case(
        cases,
        slug="transcript-before-different-call",
        rule="transcript_before_mismatch",
        variant="transcript_before_different_call",
        declared_defect="before_object_shape_only",
        inputs=inputs,
        bridge_schema_valid=True,
        classification="mismatch",
    )

    for suffix, value in (("null", None), ("array", [])):
        inputs = _base_inputs()
        inputs["transcript"]["after"] = value
        _negative_case(
            cases,
            slug=f"transcript-after-{suffix}",
            rule="transcript_after_invalid",
            variant=f"transcript_after_{suffix}",
            declared_defect="reject_null_only",
            inputs=inputs,
            bridge_schema_valid=True,
            classification="mismatch",
        )

    # Exactly two machine-readable known defects, both tracking #247.
    inputs = _base_inputs()
    inputs["bridge"]["signature"] += "=="
    cases.append(
        _case(
            slug="known-defect-padded-signature-accepted",
            description=(
                "A padded schema-invalid signature should be rejected but the pinned "
                "reference accepts it."
            ),
            inputs=inputs,
            bridge_schema_valid=False,
            runtime=_negative_runtime("invalid", "signature_representation_invalid"),
            rule="signature_representation_invalid",
            variant="padded_signature_known_defect",
            declared_defect="permissive_padding_decoder",
            known_defect_reference=_accepted_runtime(inputs),
        )
    )

    inputs = _base_inputs()
    inputs["bridge"]["authorization"]["authorized_at"] = 100.0
    _resign(inputs)
    cases.append(
        _case(
            slug="known-defect-integer-valued-float-rejected",
            description=(
                "JSON 100.0 is integer-valued under the schema and should be accepted, "
                "but the pinned Python reference rejects it."
            ),
            inputs=inputs,
            bridge_schema_valid=True,
            runtime=_accepted_runtime(inputs),
            rule="authorized_at_invalid",
            variant="integer_valued_float_known_defect",
            declared_defect="python_int_type_check",
            known_defect_reference=_negative_runtime("invalid", "authorized_at_invalid"),
        )
    )

    return cases


def _validate_inventory(cases: list[dict[str, Any]]) -> None:
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names)), "duplicate case names"
    known = [case for case in cases if case["conformance"]["status"] == "known_defect"]
    assert len(known) == 2, f"expected exactly two known defects, found {len(known)}"
    conformant = [case for case in cases if case["conformance"]["status"] == "conformant"]
    counts = Counter(
        case["coverage"]["rule"] for case in conformant if case["coverage"]["rule"] is not None
    )
    assert set(counts) == set(APPROVED_CODES), (
        "coverage inventory differs from the approved codes: "
        f"missing={sorted(set(APPROVED_CODES) - set(counts))}, "
        f"extra={sorted(set(counts) - set(APPROVED_CODES))}"
    )
    thin = {code: counts[code] for code in APPROVED_CODES if counts[code] < 2}
    assert not thin, f"approved codes below the two-vector floor: {thin}"
    reached = {case["expected"]["conformant_runtime"]["classification"] for case in conformant}
    assert reached == {"accepted", "invalid", "denied", "mismatch"}


def main() -> None:
    cases = build_cases()
    _validate_inventory(cases)

    for stale in OUT.glob("[0-9][0-9][0-9]-*.json"):
        stale.unlink()

    for number, case in enumerate(cases, start=1):
        document = {"id": f"TRACE-PIC-BRIDGE-{number:03d}", **case}
        path = OUT / f"{number:03d}-{case['name']}.json"
        rendered = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered)

    for document in case003_vectors.companions(sys.modules[__name__]):
        suffix = document["id"].removeprefix("TRACE-PIC-BRIDGE-")
        path = OUT / f"{suffix}-{document['name']}.json"
        path.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8", newline="\n",
        )

    print(f"wrote {len(cases)} base vectors and 3 case-003 companions; certification held")


if __name__ == "__main__":
    main()

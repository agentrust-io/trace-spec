from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.intent_bridge import (
    AuthorizationDenied,
    AuthorizationMismatch,
    IntentBridgeError,
    digest_jcs,
    sign_bridge,
    verify_bridge,
)
from agentrust_trace.sign import key_to_jwk


def _fixture() -> tuple[dict, Ed25519PrivateKey, dict, str, str, dict, dict]:
    key = Ed25519PrivateKey.generate()
    declaration = {"impact": "external-side-effect", "purpose": "send invoice"}
    tool_call = {"name": "send_invoice", "arguments": {"invoice_id": "INV-7"}}
    authorization = {
        "authorization_id": "auth-7",
        "decision": "allow",
        "authorizer": "finance-policy",
        "authorizer_key_id": "key-7",
        "authorized_at": 100,
        "expires_at": 200,
        "scope": {"tools": ["send_invoice"], "impacts": ["external-side-effect"]},
        "pic": {
            "profile": "PIC-CJSON/1.0",
            "intent_digest": "sha256:" + "1" * 64,
            "args_digest": "sha256:" + "2" * 64,
        },
        "declaration_digest": digest_jcs(declaration),
        "tool_call_digest": digest_jcs(tool_call),
        "transcript_required": True,
    }
    bridge = sign_bridge(authorization, key)
    transcript = {"before": {"tool_call": tool_call}, "after": {"status": "accepted"}}
    return (
        bridge, key, declaration, authorization["pic"]["intent_digest"],
        authorization["pic"]["args_digest"], tool_call, transcript,
    )


def test_verify_bridge_accepts_authorized_bound_execution() -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    result = verify_bridge(
        bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
        pic_intent_digest=intent,
        pic_args_digest=args, tool_call=tool_call, transcript=transcript, now=150,
    )
    assert result["authorization_id"] == "auth-7"


@pytest.mark.parametrize("field", ["authorization", "signature"])
def test_tampering_is_rejected(field: str) -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    tampered = copy.deepcopy(bridge)
    if field == "authorization":
        tampered["authorization"]["decision"] = "deny"
    else:
        # Substitute a character the signature does not already start with. A fixed
        # "A" is a no-op whenever it is already the first character, which is one
        # signature in 64: the "tampered" bridge then verifies and the test fails
        # having never tampered with anything.
        head = tampered["signature"][0]
        tampered["signature"] = ("B" if head == "A" else "A") + tampered["signature"][1:]
    with pytest.raises(IntentBridgeError):
        verify_bridge(
            tampered, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent,
            pic_args_digest=args, tool_call=tool_call, transcript=transcript, now=150,
        )


def test_deny_and_scope_fail_closed() -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    denied = copy.deepcopy(bridge)
    denied["authorization"]["decision"] = "deny"
    denied = sign_bridge(denied["authorization"], key)
    with pytest.raises(AuthorizationDenied):
        verify_bridge(
            denied, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=transcript, now=150,
        )
    outside = {"name": "delete_invoice", "arguments": {}}
    with pytest.raises(AuthorizationMismatch):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=outside, transcript=transcript, now=150,
        )


def test_expiry_and_required_transcript_are_enforced() -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    with pytest.raises(IntentBridgeError, match="expired"):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=transcript, now=200,
        )
    with pytest.raises(AuthorizationMismatch, match="before/after"):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=None, now=150,
        )


def test_invalid_expiry_order_and_unknown_fields_are_rejected() -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    malformed = copy.deepcopy(bridge)
    malformed["authorization"]["expires_at"] = 100
    malformed = sign_bridge(malformed["authorization"], key)
    with pytest.raises(IntentBridgeError, match="after"):
        verify_bridge(
            malformed, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=transcript, now=100,
        )
    unknown = copy.deepcopy(bridge)
    unknown["authorization"]["unexpected"] = True
    with pytest.raises(IntentBridgeError, match="unknown fields"):
        verify_bridge(
            unknown, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=transcript, now=150,
        )

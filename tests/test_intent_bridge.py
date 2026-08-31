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


def _fixture(
    scope: dict | None = None,
    tool_call: dict | None = None,
    declaration: dict | None = None,
) -> tuple[dict, Ed25519PrivateKey, dict, str, str, dict, dict]:
    key = Ed25519PrivateKey.generate()
    declaration = declaration or {"impact": "external-side-effect", "purpose": "send invoice"}
    tool_call = tool_call or {"name": "send_invoice", "arguments": {"invoice_id": "INV-7"}}
    authorization = {
        "authorization_id": "auth-7",
        "decision": "allow",
        "authorizer": "finance-policy",
        "authorizer_key_id": "key-7",
        "authorized_at": 100,
        "expires_at": 200,
        "scope": scope or {"tools": ["send_invoice"], "impacts": ["external-side-effect"]},
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


def _verify(
    bridge: dict, key: Ed25519PrivateKey, declaration: dict,
    intent: str, args: str, tool_call: dict, transcript: dict,
) -> None:
    verify_bridge(
        bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
        pic_intent_digest=intent, pic_args_digest=args,
        tool_call=tool_call, transcript=transcript, now=150,
    )


def test_the_baseline_scope_verifies_so_the_two_below_refuse_on_scope_alone() -> None:
    """The control for the pair that follows. Without it they show only that something failed."""
    _verify(*_fixture({"tools": ["send_invoice"], "impacts": ["external-side-effect"]}))


def test_a_tool_outside_the_authorized_scope_is_refused_on_that_ground() -> None:
    """This line is the only validation of `tool_call["name"]` in the module.

    It reads as a policy comparison against `scope.tools` and it is one, but there is no
    `_object` and no `_nonempty_string` on the field anywhere, so it is also the only shape
    guard on a caller-supplied input. Delete it and a `tool_call` carrying no `name` key at
    all, digested and signed honestly by the issuer, verifies: every digest matches, the
    transcript matches, the window is open, and nothing else looks at the field.

    `test_deny_and_scope_fail_closed` cannot stand in for this and should not try. Its
    record violates three rules at once, so which fires first is not this suite's business,
    and its input changes the executed call, which changes `tool_call_digest` by
    construction and so can only ever reach the family the digest already refuses.
    """
    with pytest.raises(AuthorizationMismatch, match="outside the authorized tool scope"):
        _verify(*_fixture({"tools": ["read_invoice"], "impacts": ["external-side-effect"]}))


def test_an_impact_outside_the_authorized_scope_is_refused_on_that_ground() -> None:
    """The same, for `declaration["impact"]`, which is guarded in exactly one place too."""
    with pytest.raises(AuthorizationMismatch, match="outside the authorized impact scope"):
        _verify(*_fixture({"tools": ["send_invoice"], "impacts": ["read-only"]}))


def test_a_tool_call_with_no_name_at_all_is_refused() -> None:
    """The shape case, which is what makes this line the only guard on the field.

    Everything here is internally consistent: the issuer digested and signed exactly the
    call that executed. Nothing else in the module looks at `tool_call["name"]`, so an
    implementation that skipped the comparison when the key is absent would verify this.
    """
    with pytest.raises(AuthorizationMismatch, match="outside the authorized tool scope"):
        _verify(*_fixture(tool_call={"arguments": {"invoice_id": "INV-7"}}))


def test_a_declaration_with_no_impact_at_all_is_refused() -> None:
    """The same for `declaration["impact"]`."""
    with pytest.raises(AuthorizationMismatch, match="outside the authorized impact scope"):
        _verify(*_fixture(declaration={"purpose": "send invoice"}))


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


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("authorization_id", "", "authorization_id must be a non-empty string"),
        ("authorizer", "", "authorizer must be a non-empty string"),
        ("authorizer_key_id", "", "authorizer_key_id must be a non-empty string"),
        ("authorized_at", -1, "authorized_at must be a non-negative integer"),
        ("expires_at", -1, "expires_at must be a non-negative integer"),
    ],
)
def test_runtime_verifier_enforces_schema_scalar_constraints(
    field: str, value: object, message: str
) -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    bridge["authorization"][field] = value
    bridge = sign_bridge(bridge["authorization"], key)
    trusted = {**key_to_jwk(key), "kid": "" if field == "authorizer_key_id" else "key-7"}
    with pytest.raises(IntentBridgeError, match=message):
        verify_bridge(
            bridge, trusted, declaration=declaration, pic_intent_digest=intent,
            pic_args_digest=args, tool_call=tool_call, transcript=transcript, now=150,
        )


_DUPLICATES = "must not contain duplicates"
_NONEMPTY = "must be a non-empty array of non-empty strings"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("tools", ["send_invoice", "send_invoice"], _DUPLICATES),
        ("tools", [""], _NONEMPTY),
        ("tools", [], _NONEMPTY),
        ("impacts", ["external-side-effect", "external-side-effect"], _DUPLICATES),
        ("impacts", [""], _NONEMPTY),
        ("impacts", [], _NONEMPTY),
    ],
)
def test_runtime_verifier_enforces_schema_scope_constraints(
    field: str, value: list[str], message: str
) -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    bridge["authorization"]["scope"][field] = value
    bridge = sign_bridge(bridge["authorization"], key)
    with pytest.raises(IntentBridgeError, match=message):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args, tool_call=tool_call,
            transcript=transcript, now=150,
        )


@pytest.mark.parametrize("bad_now", [-1, True, 150.0, "150"])
def test_verifier_time_override_must_be_a_non_negative_integer(bad_now: object) -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    with pytest.raises(IntentBridgeError, match="now"):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args, tool_call=tool_call,
            transcript=transcript, now=bad_now,  # type: ignore[arg-type]
        )

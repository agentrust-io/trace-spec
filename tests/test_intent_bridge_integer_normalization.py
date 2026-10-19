"""Normalized integer outputs and JCS safe-integer bounds in the PIC-TRACE bridge."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.intent_bridge import (
    IntentBridgeError,
    digest_jcs,
    sign_bridge,
    sign_successor_artifact,
    verify_bridge,
    verify_successor_artifact,
)
from agentrust_trace.sign import JCS_SAFE_INTEGER, key_to_jwk


def _after(observed_at: int | float = 150) -> dict[str, Any]:
    return {
        "observation": {"status": "accepted"},
        "observer": "observer-1",
        "observed_at": observed_at,
    }


def _fixture(
    *,
    authorized_at: int | float = 100,
    expires_at: int | float = 200,
) -> tuple[
    dict[str, Any],
    Ed25519PrivateKey,
    dict[str, Any],
    str,
    str,
    dict[str, Any],
    dict[str, Any],
]:
    key = Ed25519PrivateKey.generate()
    declaration = {"impact": "external-side-effect", "purpose": "send invoice"}
    tool_call = {"name": "send_invoice", "arguments": {"invoice_id": "INV-7"}}
    authorization: dict[str, Any] = {
        "authorization_id": "auth-7",
        "decision": "allow",
        "authorizer": "finance-policy",
        "authorizer_key_id": "key-7",
        "authorized_at": authorized_at,
        "expires_at": expires_at,
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
    transcript = {"before": {"tool_call": tool_call}}
    return (
        bridge,
        key,
        declaration,
        authorization["pic"]["intent_digest"],
        authorization["pic"]["args_digest"],
        tool_call,
        transcript,
    )


@pytest.mark.parametrize(
    ("authorized_at", "expires_at"),
    [(100.0, 200.0), (1e2, 2e2)],
)
def test_verify_bridge_normalizes_whole_float_timestamps_to_int_without_mutating_input(
    authorized_at: float,
    expires_at: float,
) -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture(
        authorized_at=authorized_at,
        expires_at=expires_at,
    )
    assert type(bridge["authorization"]["authorized_at"]) is float
    assert type(bridge["authorization"]["expires_at"]) is float

    result = verify_bridge(
        bridge,
        {**key_to_jwk(key), "kid": "key-7"},
        declaration=declaration,
        pic_intent_digest=intent,
        pic_args_digest=args,
        tool_call=tool_call,
        transcript=transcript,
        now=150,
    )

    assert result["authorized_at"] == 100
    assert result["expires_at"] == 200
    assert type(result["authorized_at"]) is int
    assert type(result["expires_at"]) is int
    assert type(bridge["authorization"]["authorized_at"]) is float
    assert type(bridge["authorization"]["expires_at"]) is float


def test_sign_successor_artifact_normalizes_whole_float_observed_at_to_int() -> None:
    observer_key = Ed25519PrivateKey.generate()
    after = _after(150.0)
    assert type(after["observed_at"]) is float

    artifact = sign_successor_artifact("auth-7", after, "observer-key-1", observer_key)

    assert artifact["observed_at"] == 150
    assert type(artifact["observed_at"]) is int
    assert type(after["observed_at"]) is float


@pytest.mark.parametrize(
    ("artifact_observed_at", "envelope_observed_at"),
    [(150, 150.0), (150.0, 150.0)],
)
def test_verify_successor_artifact_normalizes_whole_float_observed_at_to_int(
    artifact_observed_at: int | float,
    envelope_observed_at: float,
) -> None:
    observer_key = Ed25519PrivateKey.generate()
    baseline = sign_successor_artifact("auth-7", _after(150), "observer-key-1", observer_key)
    artifact = {**copy.deepcopy(baseline), "observed_at": artifact_observed_at}
    after = _after(envelope_observed_at)
    assert type(after["observed_at"]) is float

    bound = verify_successor_artifact(
        artifact,
        {**key_to_jwk(observer_key), "kid": "observer-key-1"},
        trusted_observer="observer-1",
        authorization_id="auth-7",
        after=after,
    )

    assert bound["observed_at"] == 150
    assert type(bound["observed_at"]) is int
    assert type(after["observed_at"]) is float


@pytest.mark.parametrize("out_of_range_now", [JCS_SAFE_INTEGER + 1, 10**20])
def test_verify_bridge_bounds_now_by_jcs_safe_integer(out_of_range_now: int) -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture(
        authorized_at=JCS_SAFE_INTEGER - 10,
        expires_at=JCS_SAFE_INTEGER,
    )
    trusted = {**key_to_jwk(key), "kid": "key-7"}
    valid = verify_bridge(
        bridge,
        trusted,
        declaration=declaration,
        pic_intent_digest=intent,
        pic_args_digest=args,
        tool_call=tool_call,
        transcript=transcript,
        now=JCS_SAFE_INTEGER - 1,
    )
    assert valid["authorization_id"] == "auth-7"
    with pytest.raises(IntentBridgeError, match="^authorization has expired$"):
        verify_bridge(
            bridge,
            trusted,
            declaration=declaration,
            pic_intent_digest=intent,
            pic_args_digest=args,
            tool_call=tool_call,
            transcript=transcript,
            now=JCS_SAFE_INTEGER,
        )

    with pytest.raises(
        IntentBridgeError,
        match="now must be a non-negative integer Unix timestamp within the JCS safe-integer range",
    ):
        verify_bridge(
            bridge,
            trusted,
            declaration=declaration,
            pic_intent_digest=intent,
            pic_args_digest=args,
            tool_call=tool_call,
            transcript=transcript,
            now=out_of_range_now,
        )

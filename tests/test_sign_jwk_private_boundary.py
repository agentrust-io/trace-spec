"""Public verification and thumbprint surfaces refuse JWK private key material.

A confirmation or verification JWK is the public half of a key pair. While the
Trust Record schema and Pydantic model already forbid private parameters inside
``record["cnf"]["jwk"]``, callers also pass JWKs directly to ``jwk_thumbprint``,
``_pubkey_from_jwk``, ``verify_record``, ``check_bundle``, ``verify_bridge``, and
``verify_successor_artifact``. If a caller accidentally passes an unredacted
private JWK from a key store, silently ignoring the private parameters and
extracting the public ``x`` coordinate hides the key-handling defect.

Every JWK thumbprint or public-key reconstruction entry point therefore refuses
any JWK containing RFC 7517, RFC 7518, or RFC 8037 private or symmetric key
parameters (``d``, ``p``, ``q``, ``dp``, ``dq``, ``qi``, ``oth``, ``k``), naming
only the parameter keys and never echoing the secret material in the error text.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from agentrust_trace import (
    generate_key,
    intent_bridge,
    jwk_thumbprint,
    key_to_jwk,
    revocation,
    sign,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTOR_DOC = json.loads(
    (
        ROOT
        / "examples"
        / "revocation-bundle"
        / "01-fresh-well-inside-both-bounds.json"
    ).read_text(encoding="utf-8")
)

PRIVATE_JWK_PARAMS: tuple[str, ...] = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
SECRET_SENTINEL = "super-secret-private-material-999"


def _bridge_fixture() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    str,
    str,
    dict[str, Any],
    dict[str, Any],
]:
    key = generate_key()
    jwk = {**key_to_jwk(key), "kid": "authorizer-key-1"}
    declaration = {"impact": "external-side-effect", "purpose": "send invoice"}
    tool_call = {"name": "send_invoice", "arguments": {"invoice_id": "INV-7"}}
    intent_digest = "sha256:" + "1" * 64
    args_digest = "sha256:" + "2" * 64
    authorization = {
        "authorization_id": "auth-7",
        "decision": "allow",
        "authorizer": "finance-policy",
        "authorizer_key_id": "authorizer-key-1",
        "authorized_at": 100,
        "expires_at": 200,
        "scope": {"tools": ["send_invoice"], "impacts": ["external-side-effect"]},
        "pic": {
            "profile": "PIC-CJSON/1.0",
            "intent_digest": intent_digest,
            "args_digest": args_digest,
        },
        "declaration_digest": intent_bridge.digest_jcs(declaration),
        "tool_call_digest": intent_bridge.digest_jcs(tool_call),
        "transcript_required": True,
    }
    bridge = intent_bridge.sign_bridge(authorization, key)
    transcript = {"before": {"tool_call": tool_call}}
    return bridge, jwk, declaration, intent_digest, args_digest, tool_call, transcript


def _successor_fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    observer_key = generate_key()
    observer_jwk = {**key_to_jwk(observer_key), "kid": "observer-key-1"}
    after = {
        "observation": {"status": "accepted"},
        "observer": "observer-1",
        "observed_at": 150,
    }
    artifact = intent_bridge.sign_successor_artifact(
        "auth-7",
        after,
        "observer-key-1",
        observer_key,
    )
    return artifact, observer_jwk, after


def test_clean_public_jwk_succeeds_across_all_surfaces() -> None:
    ctx = VECTOR_DOC["context"]
    record = VECTOR_DOC["records"][0]
    trusted_key = ctx["trusted_key"]

    thumb = jwk_thumbprint(trusted_key)
    assert isinstance(thumb, str) and len(thumb) == 43
    assert sign._pubkey_from_jwk(trusted_key) is not None

    verified = sign.verify_record(record, trusted_key, now=ctx["now"])
    assert verified.trusted_key_thumbprint == thumb

    bundle_check = revocation.check_bundle(
        ctx["bundle"],
        trusted_key_identifiers=[thumb],
        trusted_bundle_keys=ctx["trusted_bundle_keys"],
        now=ctx["now"],
        max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
        max_future_skew_seconds=ctx["max_future_skew_seconds"],
    )
    assert bundle_check.outcome == "verified"

    bridge, auth_jwk, declaration, intent_digest, args_digest, tool_call, transcript = (
        _bridge_fixture()
    )
    bridge_out = intent_bridge.verify_bridge(
        bridge,
        auth_jwk,
        declaration=declaration,
        pic_intent_digest=intent_digest,
        pic_args_digest=args_digest,
        tool_call=tool_call,
        transcript=transcript,
        now=150,
    )
    assert bridge_out["authorization_id"] == "auth-7"

    successor_artifact, observer_jwk, after = _successor_fixture()
    successor_out = intent_bridge.verify_successor_artifact(
        successor_artifact,
        observer_jwk,
        trusted_observer="observer-1",
        authorization_id="auth-7",
        after=after,
    )
    assert successor_out == after


@pytest.mark.parametrize("param", PRIVATE_JWK_PARAMS)
def test_jwk_thumbprint_rejects_private_key_material_without_echoing_secret(
    param: str,
) -> None:
    public_jwk = key_to_jwk(generate_key())
    leaked_jwk = {**public_jwk, param: SECRET_SENTINEL}

    with pytest.raises(ValueError, match="private key material") as exc_info:
        jwk_thumbprint(leaked_jwk)

    message = str(exc_info.value)
    assert repr(param) in message
    assert SECRET_SENTINEL not in message


@pytest.mark.parametrize("param", PRIVATE_JWK_PARAMS)
def test_pubkey_from_jwk_rejects_private_key_material_without_echoing_secret(
    param: str,
) -> None:
    public_jwk = key_to_jwk(generate_key())
    leaked_jwk = {**public_jwk, param: SECRET_SENTINEL}

    with pytest.raises(ValueError, match="private key material") as exc_info:
        sign._pubkey_from_jwk(leaked_jwk)

    message = str(exc_info.value)
    assert repr(param) in message
    assert SECRET_SENTINEL not in message


@pytest.mark.parametrize("param", PRIVATE_JWK_PARAMS)
def test_verify_record_rejects_trusted_jwk_carrying_private_material(
    param: str,
) -> None:
    ctx = VECTOR_DOC["context"]
    record = VECTOR_DOC["records"][0]
    leaked_jwk = {**ctx["trusted_key"], param: SECRET_SENTINEL}

    with pytest.raises(ValueError, match="private key material") as exc_info:
        sign.verify_record(record, leaked_jwk, now=ctx["now"])

    message = str(exc_info.value)
    assert repr(param) in message
    assert SECRET_SENTINEL not in message


@pytest.mark.parametrize("param", PRIVATE_JWK_PARAMS)
def test_check_bundle_rejects_trusted_bundle_key_carrying_private_material(
    param: str,
) -> None:
    ctx = VECTOR_DOC["context"]
    leaked_bundle_key = {**ctx["trusted_bundle_keys"][0], param: SECRET_SENTINEL}

    with pytest.raises(ValueError, match="private key material") as exc_info:
        revocation.check_bundle(
            ctx["bundle"],
            trusted_key_identifiers=[jwk_thumbprint(ctx["trusted_key"])],
            trusted_bundle_keys=[leaked_bundle_key],
            now=ctx["now"],
            max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
            max_future_skew_seconds=ctx["max_future_skew_seconds"],
        )

    message = str(exc_info.value)
    assert repr(param) in message
    assert SECRET_SENTINEL not in message


@pytest.mark.parametrize("param", PRIVATE_JWK_PARAMS)
def test_verify_bridge_rejects_trusted_authorizer_jwk_carrying_private_material(
    param: str,
) -> None:
    bridge, auth_jwk, declaration, intent_digest, args_digest, tool_call, transcript = (
        _bridge_fixture()
    )
    leaked_jwk = {**auth_jwk, param: SECRET_SENTINEL}

    with pytest.raises(
        intent_bridge.IntentBridgeError, match="private key material"
    ) as exc_info:
        intent_bridge.verify_bridge(
            bridge,
            leaked_jwk,
            declaration=declaration,
            pic_intent_digest=intent_digest,
            pic_args_digest=args_digest,
            tool_call=tool_call,
            transcript=transcript,
            now=150,
        )

    message = str(exc_info.value)
    assert repr(param) in message
    assert SECRET_SENTINEL not in message


@pytest.mark.parametrize("param", PRIVATE_JWK_PARAMS)
def test_verify_successor_artifact_rejects_trusted_observer_jwk_carrying_private_material(
    param: str,
) -> None:
    successor_artifact, observer_jwk, after = _successor_fixture()
    leaked_jwk = {**observer_jwk, param: SECRET_SENTINEL}

    with pytest.raises(
        intent_bridge.IntentBridgeError, match="private key material"
    ) as exc_info:
        intent_bridge.verify_successor_artifact(
            successor_artifact,
            leaked_jwk,
            trusted_observer="observer-1",
            authorization_id="auth-7",
            after=after,
        )

    message = str(exc_info.value)
    assert repr(param) in message
    assert SECRET_SENTINEL not in message


def test_multiple_private_jwk_members_are_listed_in_sorted_order() -> None:
    public_jwk = key_to_jwk(generate_key())
    leaked_jwk = {**public_jwk, "q": SECRET_SENTINEL, "d": SECRET_SENTINEL}

    with pytest.raises(ValueError, match=r"\('d', 'q'\)") as thumb_exc:
        jwk_thumbprint(leaked_jwk)
    assert SECRET_SENTINEL not in str(thumb_exc.value)

    with pytest.raises(ValueError, match=r"\('d', 'q'\)") as pub_exc:
        sign._pubkey_from_jwk(leaked_jwk)
    assert SECRET_SENTINEL not in str(pub_exc.value)

from __future__ import annotations

import base64
import copy
import inspect

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.intent_bridge import (
    AuthorizationDenied,
    AuthorizationMismatch,
    IntentBridgeError,
    digest_jcs,
    sign_bridge,
    sign_successor_artifact,
    verify_bridge,
    verify_successor_artifact,
)
from agentrust_trace.sign import key_to_jwk


def _after(
    observation: dict | None = None,
    *,
    observer: str = "observer-1",
    observed_at: int = 150,
) -> dict:
    return {
        "observation": observation if observation is not None else {"status": "accepted"},
        "observer": observer,
        "observed_at": observed_at,
    }


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
    # The pre-execution authorization is signed before any successor observation exists.
    bridge = sign_bridge(authorization, key)
    transcript = {"before": {"tool_call": tool_call}}
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


def test_successor_is_a_separate_post_execution_artifact() -> None:
    bridge, _, _, _, _, _, _ = _fixture()
    assert "successor_observation_digest" not in bridge["authorization"]

    observer_key = Ed25519PrivateKey.generate()
    after = _after()
    successor = sign_successor_artifact(
        bridge["authorization"]["authorization_id"],
        after,
        "observer-key-1",
        observer_key,
    )
    verified = verify_successor_artifact(
        successor,
        {**key_to_jwk(observer_key), "kid": "observer-key-1"},
        trusted_observer="observer-1",
        authorization_id=bridge["authorization"]["authorization_id"],
        after=after,
    )
    assert verified == after


def test_successor_artifact_with_wrong_authorization_id_is_rejected() -> None:
    bridge, _, _, _, _, _, _ = _fixture()
    observer_key = Ed25519PrivateKey.generate()
    successor = sign_successor_artifact(
        "auth-other",
        _after(),
        "observer-key-1",
        observer_key,
    )
    with pytest.raises(AuthorizationMismatch, match="does not name the authorization"):
        verify_successor_artifact(
            successor,
            {**key_to_jwk(observer_key), "kid": "observer-key-1"},
            trusted_observer="observer-1",
            authorization_id=bridge["authorization"]["authorization_id"],
            after=_after(),
        )


def test_successor_substitution_after_observer_signature_is_rejected() -> None:
    observer_key = Ed25519PrivateKey.generate()
    after = _after()
    successor = sign_successor_artifact(
        "auth-7",
        after,
        "observer-key-1",
        observer_key,
    )
    substituted = copy.deepcopy(after)
    substituted["observation"]["status"] = "different"
    with pytest.raises(AuthorizationMismatch, match="expected digest binding"):
        verify_successor_artifact(
            successor,
            {**key_to_jwk(observer_key), "kid": "observer-key-1"},
            trusted_observer="observer-1",
            authorization_id="auth-7",
            after=substituted,
        )


def _sign_successor_body(body: dict, key: Ed25519PrivateKey) -> dict:
    """Sign an arbitrary successor body, for cases the signer itself refuses to produce."""
    signature = base64.urlsafe_b64encode(key.sign(rfc8785.dumps(body))).rstrip(b"=")
    return {**body, "signature": signature.decode("ascii")}


@pytest.mark.parametrize("claimed", ["independent-auditor", "Executor", "executor-2", "exec"])
def test_successor_signed_under_another_observers_name_is_rejected(claimed: str) -> None:
    # The executor holds a key the verifier accepts for its own observations. Signed
    # under its own name the successor verifies, and the evaluator can then see that
    # observer and executor are the same principal. Signed under another observer's
    # name it must not verify, or the evaluator reads a name the key does not own.
    executor_key = Ed25519PrivateKey.generate()
    executor_jwk = {**key_to_jwk(executor_key), "kid": "executor-key"}
    honest = _after(observer="executor")
    verified = verify_successor_artifact(
        sign_successor_artifact("auth-7", honest, "executor-key", executor_key),
        executor_jwk,
        trusted_observer="executor",
        authorization_id="auth-7",
        after=honest,
    )
    assert verified["observer"] == "executor"

    # A different name, a different case, a longer name with the same prefix and a
    # shorter one: the identity must match exactly, not loosely.
    relabelled = _after(observer=claimed)
    successor = sign_successor_artifact("auth-7", relabelled, "executor-key", executor_key)
    with pytest.raises(IntentBridgeError, match="not the identity the trusted observer key"):
        verify_successor_artifact(
            successor,
            executor_jwk,
            trusted_observer="executor",
            authorization_id="auth-7",
            after=relabelled,
        )


def test_the_observer_identity_is_a_required_argument() -> None:
    # An optional `trusted_observer` would pass every test above, which always supply it,
    # and leave a caller who omits it where #451 started: the name chosen by the signer.
    parameter = inspect.signature(verify_successor_artifact).parameters["trusted_observer"]
    assert parameter.default is inspect.Parameter.empty
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


def test_successor_signed_by_a_key_other_than_the_trusted_one_is_rejected() -> None:
    after = _after()
    successor = sign_successor_artifact(
        "auth-7", after, "observer-key-1", Ed25519PrivateKey.generate()
    )
    with pytest.raises(IntentBridgeError, match="successor signature is invalid"):
        verify_successor_artifact(
            successor,
            {**key_to_jwk(Ed25519PrivateKey.generate()), "kid": "observer-key-1"},
            trusted_observer="observer-1",
            authorization_id="auth-7",
            after=after,
        )


def test_successor_naming_another_observer_key_id_is_rejected() -> None:
    observer_key = Ed25519PrivateKey.generate()
    after = _after()
    successor = sign_successor_artifact("auth-7", after, "observer-key-2", observer_key)
    with pytest.raises(IntentBridgeError, match="does not identify the trusted observer key"):
        verify_successor_artifact(
            successor,
            {**key_to_jwk(observer_key), "kid": "observer-key-1"},
            trusted_observer="observer-1",
            authorization_id="auth-7",
            after=after,
        )


@pytest.mark.parametrize(
    ("field", "signed_value"), [("observer", "observer-2"), ("observed_at", 151)]
)
def test_successor_metadata_that_differs_from_the_envelope_is_rejected(
    field: str, signed_value: object
) -> None:
    # The signer always copies observer and observed_at from the envelope, so this
    # artifact is signed by hand: the digest binds the envelope, the signed field does not.
    observer_key = Ed25519PrivateKey.generate()
    after = _after()
    body = {
        "profile": "tag:agentrust-io.com,2026:pic-trace-successor-v1",
        "authorization_id": "auth-7",
        "observer": after["observer"],
        "observer_key_id": "observer-key-1",
        "observed_at": after["observed_at"],
        "successor_observation_digest": digest_jcs(after),
    }
    body[field] = signed_value
    successor = _sign_successor_body(body, observer_key)
    with pytest.raises(AuthorizationMismatch, match="metadata does not match"):
        verify_successor_artifact(
            successor,
            {**key_to_jwk(observer_key), "kid": "observer-key-1"},
            trusted_observer=body["observer"],
            authorization_id="auth-7",
            after=after,
        )


def test_successor_with_another_profile_is_rejected() -> None:
    # Changed without re-signing. The signature is checked over the constant profile,
    # so an artifact re-signed over another profile would be refused by the signature
    # whether or not the profile check exists, and could not show that check is needed.
    observer_key = Ed25519PrivateKey.generate()
    after = _after()
    successor = sign_successor_artifact("auth-7", after, "observer-key-1", observer_key)
    successor["profile"] = "tag:example.com,2026:another-profile"
    with pytest.raises(IntentBridgeError, match="unknown successor profile"):
        verify_successor_artifact(
            successor,
            {**key_to_jwk(observer_key), "kid": "observer-key-1"},
            trusted_observer="observer-1",
            authorization_id="auth-7",
            after=after,
        )


def test_sign_bridge_refuses_a_surrogate_in_a_key_with_its_own_error() -> None:
    # Found by the intent-bridge fuzz target: the key sort inside rfc8785 raised
    # UnicodeEncodeError, which reached the caller instead of IntentBridgeError.
    with pytest.raises(IntentBridgeError, match="no RFC 8785 canonical form"):
        sign_bridge({"a\udeff": 1, "b": 2}, Ed25519PrivateKey.generate())


def test_verify_bridge_refuses_a_surrogate_in_a_tool_call_key_with_its_own_error() -> None:
    # The verifier side of the same escape: the tool call is the caller's untrusted input.
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    with pytest.raises(IntentBridgeError, match="no RFC 8785 canonical form"):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call={**tool_call, "arguments": {"x\udeff": 1, "b": 2}},
            transcript=transcript, now=150,
        )


def test_successor_envelope_rejects_unknown_fields_before_signing() -> None:
    observer_key = Ed25519PrivateKey.generate()
    after = _after()
    after["extra"] = "not-part-of-profile"
    with pytest.raises(AuthorizationMismatch, match="unknown successor fields"):
        sign_successor_artifact("auth-7", after, "observer-key-1", observer_key)


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


@pytest.mark.parametrize("bad_signature", ["a", "你好", "!!!not-base64!!!padding???"])
def test_a_malformed_base64_signature_raises_intentbridgeerror_not_valueerror(
    bad_signature: str,
) -> None:
    """`_b64url_decode` is `sign`'s own helper and raises the bare `ValueError`
    that module documents for itself. Called here unwrapped, a correctly-typed
    but undecodable signature -- too short to pad to a whole byte, or carrying a
    non-ASCII character -- escaped as that raw `ValueError`, which is not an
    instance of `IntentBridgeError` and is not caught by a caller written
    against this module's own exception (the same failure this module's `_jcs`
    docstring calls out for `rfc8785.CanonicalizationError`, at a call site the
    docstring does not cover).
    """
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    tampered = copy.deepcopy(bridge)
    tampered["signature"] = bad_signature
    with pytest.raises(IntentBridgeError, match="not valid base64url"):
        verify_bridge(
            tampered, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=transcript, now=150,
        )



@pytest.mark.parametrize("bad_decision", [True, 1, None, "", "reject"])
def test_malformed_signed_decision_is_not_classified_as_denial(bad_decision) -> None:
    """Only literal `deny` is AuthorizationDenied.

    Malformed values are producer errors, not policy decisions.
    """
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    malformed = copy.deepcopy(bridge)
    malformed["authorization"]["decision"] = bad_decision
    malformed = sign_bridge(malformed["authorization"], key)

    with pytest.raises(IntentBridgeError, match="decision must be") as excinfo:
        verify_bridge(
            malformed, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=transcript, now=150,
        )
    assert not isinstance(excinfo.value, AuthorizationDenied)


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


def test_pre_execution_authorization_rejects_future_successor_binding() -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    contradictory = copy.deepcopy(bridge["authorization"])
    contradictory["successor_observation_digest"] = digest_jcs(_after())
    contradictory_bridge = sign_bridge(contradictory, key)
    with pytest.raises(IntentBridgeError, match="unknown fields"):
        verify_bridge(
            contradictory_bridge, {**key_to_jwk(key), "kid": "key-7"},
            declaration=declaration, pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=transcript, now=150,
        )


def test_transcript_requirement_is_pre_execution_only() -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()

    result = verify_bridge(
        bridge, {**key_to_jwk(key), "kid": "key-7"},
        declaration=declaration, pic_intent_digest=intent, pic_args_digest=args,
        tool_call=tool_call, transcript=transcript, now=150,
    )
    assert result["transcript_required"] is True

    with_after = {**transcript, "after": _after()}
    with pytest.raises(AuthorizationMismatch, match="successor evidence is a separate"):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"},
            declaration=declaration, pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=with_after, now=150,
        )

    no_transcript = copy.deepcopy(bridge["authorization"])
    no_transcript["transcript_required"] = False
    no_transcript_bridge = sign_bridge(no_transcript, key)
    result = verify_bridge(
        no_transcript_bridge, {**key_to_jwk(key), "kid": "key-7"},
        declaration=declaration, pic_intent_digest=intent, pic_args_digest=args,
        tool_call=tool_call, transcript=None, now=150,
    )
    assert result["transcript_required"] is False


def test_expiry_and_required_transcript_are_enforced() -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    with pytest.raises(IntentBridgeError, match="expired"):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args,
            tool_call=tool_call, transcript=transcript, now=200,
        )
    with pytest.raises(AuthorizationMismatch, match="pre-execution/dispatch transcript"):
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


@pytest.mark.parametrize(
    ("executed", "transcribed"),
    [
        ({"approved": 1}, {"approved": True}),
        ({"approved": True}, {"approved": 1}),
        ({"approved": 0}, {"approved": False}),
        ({"approved": False}, {"approved": 0}),
    ],
)
def test_transcript_call_is_compared_over_canonical_bytes_not_python_equality(
    executed: dict, transcribed: dict
) -> None:
    """#317: `True == 1` in Python, so `!=` accepted a JSON-distinct transcript call."""
    call = {"name": "send_invoice", "arguments": executed}
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture(tool_call=call)
    substituted = {"name": "send_invoice", "arguments": transcribed}
    assert substituted == tool_call, "the substitution must be Python-equal to be a regression"
    assert digest_jcs(substituted) != digest_jcs(tool_call)
    with pytest.raises(AuthorizationMismatch, match="transcript.before.tool_call"):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args, tool_call=tool_call,
            transcript={"before": {"tool_call": substituted}},
            now=150,
        )


def test_transcript_call_identical_to_the_execution_still_verifies() -> None:
    """The control for the case above: canonical-byte equality still accepts a match."""
    call = {"name": "send_invoice", "arguments": {"approved": 1}}
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture(tool_call=call)
    result = verify_bridge(
        bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
        pic_intent_digest=intent, pic_args_digest=args, tool_call=tool_call,
        transcript=transcript, now=150,
    )
    assert result["authorization_id"] == "auth-7"


@pytest.mark.parametrize("bad", [None, "send_invoice", ["send_invoice"], 7])
def test_transcript_call_that_is_not_an_object_stays_an_authorization_mismatch(
    bad: object,
) -> None:
    """Comparing digests must not turn a malformed transcript into a different class."""
    bridge, key, declaration, intent, args, tool_call, transcript = _fixture()
    with pytest.raises(AuthorizationMismatch, match="transcript.before.tool_call"):
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args, tool_call=tool_call,
            transcript={"before": {"tool_call": bad}},
            now=150,
        )

@pytest.mark.parametrize("bad", [{"approved": 2**60}, {"approved": float("nan")}])
def test_uncanonicalizable_transcript_call_is_intentbridgeerror_not_mismatch(
    bad: dict,
) -> None:
    """An unrepresentable transcript call cannot be evaluated; it is not a mismatch."""
    bridge, key, declaration, intent, args, tool_call, _ = _fixture()
    transcript_call = {"name": "send_invoice", "arguments": bad}
    with pytest.raises(IntentBridgeError, match="transcript.before.tool_call") as excinfo:
        verify_bridge(
            bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
            pic_intent_digest=intent, pic_args_digest=args, tool_call=tool_call,
            transcript={"before": {"tool_call": transcript_call}},
            now=150,
        )
    assert not isinstance(excinfo.value, AuthorizationMismatch)

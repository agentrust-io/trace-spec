"""Discover all reference functions; vary every argument from a valid baseline.

Acceptance is not asserted for arbitrary helper values. Any refusal must be a
ProfileError. This sweep covers function parameters, not arbitrary object graphs.
"""

import inspect
from dataclasses import replace

import pytest
import rfc8785

from prototype import verifier_token as v
from tests.test_verifier_token_profile import context, fixture, g, proof, unb64

__all__ = ["fixture"]
JUNK = [
    None,
    True,
    False,
    0,
    1.5,
    "",
    "text",
    b"bytes",
    {},
    [],
    [1],
    10**30,
    float("nan"),
    float("inf"),
    "\ud800",
    {"nested": [None]},
]


def baselines(f):
    raw = unb64(f["envelope_b64"])
    token = v.Token.model_validate(f["token"])
    ctx = context(f)
    proof_body, signed_proof = proof(f)
    return {
        "digest": {"data": b"valid"},
        "canonical_digest": {"value": {"valid": 1}},
        "public_bytes": {"key": g.ISSUER},
        "key_id": {"key": g.ISSUER},
        "holder_key": {"key": g.HOLDER},
        "holder_public": {"cnf": token.cnf},
        "sign_payload": {"payload": token, "key": g.ISSUER},
        "unpack": {"envelope": raw, "profile": v.PROFILE},
        "read_payload": {"raw": rfc8785.dumps(f["token"]), "model": v.Token},
        "authenticate": {
            "envelope": raw,
            "profile": v.PROFILE,
            "key": g.ISSUER.public_key(),
            "model": v.Token,
        },
        "binding_digest": {
            "source": token.components[0],
            "target": token.components[1],
            "method": "same-instance-v1",
        },
        "derive_composite": {
            "token": token,
            "requirements": ctx.requirements,
            "policy": ctx.policy,
            "now": g.NOW,
            "trusted_appraisers": {},
        },
        "verify_token": {"envelope": raw, "context": ctx, "now": g.NOW},
        "verify_proof": {
            "proof_bytes": signed_proof,
            "token_bytes": raw,
            "token": token,
            "nonce": proof_body["nonce"],
            "audience": ctx.audience,
            "session_id": "session-1",
            "action_digest": proof_body["action_digest"],
            "challenge_issued_at": g.NOW,
            "challenge_expires_at": g.NOW + 30,
            "now": g.NOW,
        },
    }


def test_function_and_parameter_inventory_is_complete(fixture):
    functions = {
        name: fn
        for name, fn in vars(v).items()
        if not name.startswith("_") and inspect.isfunction(fn) and fn.__module__ == v.__name__
    }
    baseline = baselines(fixture)
    assert set(functions) == set(baseline)
    for name, fn in functions.items():
        assert set(inspect.signature(fn).parameters) == set(baseline[name])
        fn(**baseline[name])


@pytest.mark.parametrize(
    "name",
    [
        "digest",
        "canonical_digest",
        "public_bytes",
        "key_id",
        "holder_key",
        "holder_public",
        "sign_payload",
        "unpack",
        "read_payload",
        "authenticate",
        "binding_digest",
        "derive_composite",
        "verify_token",
        "verify_proof",
    ],
)
def test_every_parameter_has_a_stable_refusal_contract(fixture, name):
    fn = getattr(v, name)
    base = baselines(fixture)[name]
    fn(**base)
    leaks = []
    for parameter in base:
        for value in JUNK:
            kwargs = dict(base, **{parameter: value})
            try:
                fn(**kwargs)
            except v.ProfileError:
                pass
            except Exception as exc:
                leaks.append((parameter, type(value).__name__, type(exc).__name__))
    assert not leaks


def test_status_callback_cannot_rewrite_authenticated_claims(fixture):
    def callback(token, now):
        token.components.clear()
        return True

    ctx = replace(context(fixture), status_check=callback)
    token = v.verify_token(unb64(fixture["envelope_b64"]), ctx, g.NOW)
    assert len(token.components) == 2
    assert token.model_dump() == fixture["token"]


def test_context_fields_have_a_stable_refusal_contract(fixture):
    ctx = context(fixture)
    leaks = []
    for field in vars(ctx):
        for value in JUNK:
            try:
                replace(ctx, **{field: value})
            except v.ProfileError:
                pass
            except Exception as exc:
                leaks.append((field, type(value).__name__, type(exc).__name__))
    assert not leaks


@pytest.mark.parametrize("lifetime", [True, 1.5, float("nan"), -1, 0, 86401])
def test_context_lifetime_is_bounded_integer(fixture, lifetime):
    with pytest.raises(v.ProfileError, match="context_configuration_invalid"):
        replace(context(fixture), maximum_lifetime=lifetime)


@pytest.mark.parametrize("field", ["valid_from", "valid_until", "key", "issuer"])
def test_issuer_configuration_refuses_malformed_fields(fixture, field):
    issuer = next(iter(context(fixture).trusted_issuers.values()))
    for value in [None, {}, [], True]:
        with pytest.raises(v.ProfileError, match="issuer_configuration_invalid"):
            replace(issuer, **{field: value})


def test_canonical_32_byte_nonce_enforced_in_proof_and_relying_party(fixture):
    proof_body, signed_proof = proof(fixture)
    ctx = context(fixture)
    rp = v.RelyingParty(ctx)
    # Valid 32-byte canonical base64url nonce succeeds
    rp.challenge(
        nonce="A" * 43,
        session_id="session-1",
        action_digest=proof_body["action_digest"],
        issued_at=g.NOW,
        expires_at=g.NOW + 30,
    )
    # 43-char string with non-zero unused pad bits ("A"*42 + "B") is rejected
    with pytest.raises(v.ProfileError, match="nonce_shape"):
        rp.challenge(
            nonce="A" * 42 + "B",
            session_id="session-1",
            action_digest=proof_body["action_digest"],
            issued_at=g.NOW,
            expires_at=g.NOW + 30,
        )
    bad_proof = dict(proof_body, nonce="A" * 42 + "B")
    with pytest.raises(ValueError):
        v.Proof.model_validate(bad_proof)


def test_relying_party_challenge_and_verify_proof_reject_boolean_or_invalid_inputs(fixture):
    raw = unb64(fixture["envelope_b64"])
    token = v.Token.model_validate(fixture["token"])
    ctx = context(fixture)
    proof_body, signed_proof = proof(fixture)
    rp = v.RelyingParty(ctx)

    for idx, bad_session in enumerate(("", 123, None)):
        with pytest.raises(v.ProfileError, match="input_invalid"):
            rp.challenge(
                nonce=f"{idx}A" + "A" * 41,
                session_id=bad_session,  # type: ignore[arg-type]
                action_digest=proof_body["action_digest"],
                issued_at=g.NOW,
                expires_at=g.NOW + 30,
            )

    with pytest.raises(v.ProfileError, match="input_invalid"):
        rp.challenge(
            nonce="Q" * 43,
            session_id="session-1",
            action_digest="not-a-digest",
            issued_at=g.NOW,
            expires_at=g.NOW + 30,
        )

    for idx, (bad_issued, bad_expires) in enumerate(
        ((False, True), (-10, -5), (g.NOW, True), (g.NOW, 2**53))
    ):
        with pytest.raises(v.ProfileError, match="challenge_interval"):
            rp.challenge(
                nonce=f"{idx}Q" + "A" * 41,
                session_id="session-1",
                action_digest=proof_body["action_digest"],
                issued_at=bad_issued,
                expires_at=bad_expires,
            )

    for kw, bad_val in (
        ("now", True),
        ("challenge_issued_at", False),
        ("challenge_expires_at", True),
        ("now", 2**53),
        ("nonce", "A" * 42 + "B"),
    ):
        kwargs = {
            "proof_bytes": signed_proof,
            "token_bytes": raw,
            "token": token,
            "nonce": proof_body["nonce"],
            "audience": ctx.audience,
            "session_id": "session-1",
            "action_digest": proof_body["action_digest"],
            "challenge_issued_at": 1,
            "challenge_expires_at": 2,
            "now": 1,
        }
        kwargs[kw] = bad_val
        with pytest.raises(v.ProfileError, match="verification_inputs_invalid"):
            v.verify_proof(**kwargs)  # type: ignore[arg-type]


def test_execution_appraisal_rejects_nonfinite_jwt_json_and_unsafe_integer_times():
    import base64
    from prototype.execution_appraisal import (
        ExecutionDenied,
        LaunchPolicy,
        appraise_launch,
        authenticate_token,
    )

    def _b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    bad_header = _b64u(b'{"alg":"RS256","kid":"k1","x":NaN}') + "." + _b64u(b"{}") + ".AAAA"
    with pytest.raises(ExecutionDenied, match="jwt_framing"):
        authenticate_token(bad_header, {"keys": []})

    policy = LaunchPolicy(
        audience="aud-1",
        image_digest="sha256:" + "a" * 64,
        args=("run",),
        subject="https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/i1",
        instance_id="12345",
    )
    with pytest.raises(ExecutionDenied, match="clock_or_policy"):
        appraise_launch(
            {},
            {"keys": []},
            policy,
            expected_challenge="a" * 64,
            now=2**53,
        )

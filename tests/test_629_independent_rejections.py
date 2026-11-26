"""Supplemental independent controls for the three review gaps in #634."""

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prototype import execution_appraisal as appraisal
from prototype import verifier_token as v
from prototype.cmcp_gate import CMCPTraceGate
from tests.test_execution_appraisal import CHALLENGE, NOW, case
from tests.test_verifier_token_profile import context, fixture, g, proof, unb64

__all__ = ["case", "fixture"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_authenticated_claims_body_rejects_nonfinite_json(case, value):
    claims, keys, _, packet, _ = case
    assert appraisal.authenticate_token(packet()["token"], keys)["iat"] == NOW
    bad = dict(claims, extra={"nested": [value]})
    signed = packet(bad)
    with pytest.raises(appraisal.ExecutionDenied, match="jwt_framing"):
        appraisal.authenticate_token(signed["token"], keys)


@pytest.mark.parametrize(
    ("field", "value"), [("iat", -1), ("nbf", -1), ("exp", 2**53)]
)
def test_signed_claim_time_bounds_are_reached_independently(case, field, value):
    claims, keys, policy, packet, _ = case
    policy = replace(policy, max_age=2000)
    assert appraisal.appraise_launch(
        packet(), keys, policy, expected_challenge=CHALLENGE, now=NOW
    )["observed_digest"] == policy.image_digest
    with pytest.raises(appraisal.ExecutionDenied, match="time_bounds"):
        appraisal.appraise_launch(
            packet(dict(claims, **{field: value})),
            keys, policy, expected_challenge=CHALLENGE, now=NOW,
        )


def test_gate_refuses_nonce_alias_before_store_consumption(fixture, tmp_path, monkeypatch):
    monkeypatch.setattr("prototype.cmcp_gate.secrets.token_urlsafe", lambda _n: "A" * 43)
    raw = unb64(fixture["envelope_b64"])
    gate = CMCPTraceGate(
        context(fixture),
        database=tmp_path / "gate.sqlite",
        gateway_key=Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128))),
        gateway_issuer="spiffe://example.test/gateway",
        gateway_policy_digest="sha256:" + "a" * 64,
        clock=lambda: g.NOW,
    )
    action = {"domain": "cmcp:trace-admission:experimental-v1", "session_id": "session-1"}
    challenge = gate.challenge(raw, session_id="session-1", action=action)
    payload = {
        "profile": v.PROOF_PROFILE, "nonce": challenge["nonce"],
        "token_digest": v.digest(raw), "token_id": challenge["token_id"],
        "audience": challenge["audience"], "session_id": challenge["session_id"],
        "action_digest": challenge["action_digest"], "issued_at": challenge["issued_at"],
        "expires_at": challenge["expires_at"],
    }
    credentials = {
        "nonce": challenge["nonce"],
        "proof": CMCPTraceGate._encode(g.envelope(payload, g.HOLDER)),
    }
    calls = []
    original = gate._store.consume_challenge

    def observe(nonce):
        calls.append(nonce)
        return original(nonce)

    monkeypatch.setattr(gate._store, "consume_challenge", observe)
    with pytest.raises(v.ProfileError, match="nonce_shape"):
        gate.admit(raw, dict(credentials, nonce="A" * 42 + "B"), session_id="session-1")
    assert calls == []
    assert gate.admit(raw, credentials, session_id="session-1")["generation"] == 1
    assert calls == ["A" * 43]


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"nonce": 123}, "nonce_shape"),
        ({"issued_at": False, "expires_at": 1}, "challenge_interval"),
        ({"issued_at": 0, "expires_at": True}, "challenge_interval"),
        ({"issued_at": 2**53 - 10, "expires_at": 2**53 + 5}, "challenge_interval"),
    ],
)
def test_challenge_refuses_each_new_input(fixture, change, code):
    body, _ = proof(fixture)
    kwargs = {
        "nonce": "A" * 43,
        "session_id": "session-1",
        "action_digest": body["action_digest"],
        "issued_at": g.NOW,
        "expires_at": g.NOW + 30,
    }
    v.RelyingParty(context(fixture)).challenge(**kwargs)
    with pytest.raises(v.ProfileError, match=f"^{code}$"):
        v.RelyingParty(context(fixture)).challenge(**{**kwargs, **change})


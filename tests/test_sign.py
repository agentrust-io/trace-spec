"""Tests for agentrust_trace.sign."""

import base64
import hmac
import json
import time

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace import (
    DEFAULT_ACCEPTED_PROFILES,
    TRACE_PROFILE_V0_2,
    TrustRecord,
    VerificationResult,
    generate_key,
    jwk_thumbprint,
    key_to_jwk,
    sign_record,
    verify_record,
)
from agentrust_trace.sign import _TRACE_PROFILE_V0_1
from agentrust_trace.sign import _canonical_bytes


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _minimal_record() -> dict:
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": 1750000000,
        "subject": "did:mesh:spiffe://factory.example/agent/payments/prod",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + "0" * 64,
        },
        "policy": {
            "bundle_hash": "sha256:" + "a" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "confidential",
        "build_provenance": {
            "slsa_level": 0,
            "digest": "sha256:" + "b" * 64,
        },
        "appraisal": {
            "status": "affirming",
            "verifier": "https://agt.example.org/verifier",
        },
        "transparency": "https://rekor.sigstore.dev/api/v1/log/entries/example",
        "tool_transcript": {
            "hash": "sha256:" + "c" * 64,
            "call_count": 3,
        },
    }


def test_sign_record_adds_signature_and_cnf():
    key = generate_key()
    record = sign_record(_minimal_record(), key)
    assert "signature" in record
    assert "cnf" in record
    assert record["cnf"]["jwk"]["kty"] == "OKP"
    assert record["cnf"]["jwk"]["crv"] == "Ed25519"
    assert "x" in record["cnf"]["jwk"]


def test_sign_record_signature_verifies():
    key = generate_key()
    record = sign_record(_minimal_record(), key)

    jwk = record["cnf"]["jwk"]
    pub_bytes = _b64url_decode(jwk["x"])
    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    sig_bytes = _b64url_decode(record["signature"])
    pub_key.verify(sig_bytes, body)  # raises InvalidSignature if wrong


def test_tampered_record_fails_verification():
    key = generate_key()
    record = sign_record(_minimal_record(), key)

    jwk = record["cnf"]["jwk"]
    pub_bytes = _b64url_decode(jwk["x"])
    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

    tampered = {**record, "data_class": "public"}
    body = _canonical_bytes({k: v for k, v in tampered.items() if k != "signature"})
    sig_bytes = _b64url_decode(record["signature"])
    with pytest.raises(InvalidSignature):
        pub_key.verify(sig_bytes, body)


def test_signed_record_passes_trust_record_validation():
    key = generate_key()
    record = sign_record(_minimal_record(), key)
    validated = TrustRecord.model_validate(record)
    assert validated.appraisal.status == "affirming"
    assert validated.subject.startswith("did:")


def test_key_to_jwk_shape():
    key = generate_key()
    jwk = key_to_jwk(key)
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert len(jwk["x"]) > 0


def test_sign_record_did_subject():
    key = generate_key()
    record = _minimal_record()
    record["subject"] = "did:key:z6MkhaXgBZDvotzL8oCYaXeFuJArwvX6mDMsKTJVjtN7R"
    signed = sign_record(record, key)
    validated = TrustRecord.model_validate(signed)
    assert validated.subject.startswith("did:key:")


def test_sign_record_spiffe_subject():
    key = generate_key()
    record = _minimal_record()
    record["subject"] = "spiffe://trust.example.org/agent/payments/prod"
    signed = sign_record(record, key)
    validated = TrustRecord.model_validate(signed)
    assert validated.subject.startswith("spiffe://")


def _trusted_jwk(record: dict) -> dict:
    """Return the public JWK of the key that signed *record* (the trust anchor)."""
    return record["cnf"]["jwk"]


def _fresh_record() -> dict:
    """A minimal record with a recent iat so the freshness check passes."""
    record = _minimal_record()
    record["iat"] = int(time.time())
    return record


def test_verify_record_passes_for_valid_signature():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    verify_record(record, key_to_jwk(key))  # must not raise


def test_verify_record_rejects_signed_unknown_top_level_field():
    key = generate_key()
    record = _fresh_record()
    record["unexpected_security_semantics"] = "trusted"
    signed = sign_record(record, key)

    with pytest.raises(ValueError, match="does not conform.*unexpected_security_semantics"):
        verify_record(signed, key_to_jwk(key))


def test_verify_record_rejects_signed_missing_required_claim():
    key = generate_key()
    record = _fresh_record()
    del record["appraisal"]
    signed = sign_record(record, key)

    with pytest.raises(ValueError, match="does not conform.*appraisal"):
        verify_record(signed, key_to_jwk(key))


def test_verify_record_rejects_signed_invalid_nested_value():
    key = generate_key()
    record = _fresh_record()
    record["policy"]["enforcement_mode"] = "bypass"
    signed = sign_record(record, key)

    with pytest.raises(ValueError, match=r"policy\.enforcement_mode"):
        verify_record(signed, key_to_jwk(key))


def _fresh_record_with_profile(profile) -> dict:
    record = _fresh_record()
    if profile is None:
        del record["eat_profile"]
    else:
        record["eat_profile"] = profile
    return record


def test_verify_record_rejects_superseded_v0_1_profile():
    """spec/trace-v0.2.md, under 'Changes from v0.1': a v0.2 verifier MUST reject v0.1.

    The signature is genuine; the refusal must come from the profile, not from
    tampering, or this would test the wrong check.
    """
    key = generate_key()
    record = sign_record(
        _fresh_record_with_profile("tag:agentrust.io,2026:trace-v0.1"), key
    )

    with pytest.raises(ValueError, match="superseded v0.1 profile"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_rejects_v0_1_in_the_accepted_set():
    """The configuration side of the same cutover: a verifier may not declare v0.1 in
    its accepted set, whatever record it is shown. Moved here from the #116 vector set
    on 2026-09-13 under the ruling that the cutover is merged normative text and its
    coverage belongs with the cutover, not with a proposal. The record is an ordinary
    v0.2 one so the refusal can only come from the set.
    """
    key = generate_key()
    record = sign_record(_fresh_record_with_profile(TRACE_PROFILE_V0_2), key)

    with pytest.raises(ValueError, match="superseded v0.1 identifier"):
        verify_record(record, key_to_jwk(key),
                      accepted_profiles=(_TRACE_PROFILE_V0_1, TRACE_PROFILE_V0_2))

    # Control: the same record and key with the v0.1 tag removed from the set verifies,
    # so the refusal above is the set's and not the record's.
    verify_record(record, key_to_jwk(key), accepted_profiles=(TRACE_PROFILE_V0_2,))


def test_the_two_retired_cutover_vectors_are_covered_here():
    """Vectors 03 and 08 of the #116 set, moved here on 2026-09-15.

    Both were cutover coverage under the same ruling that moved vector 10: the rule they
    pin is merged normative text in `spec/trace-v0.2.md` under "Changes from v0.1", not
    an obligation #116 proposes, and coverage that lives in a proposal's vector set
    becomes unowned when the proposal closes. Their ids are retired rather than reused.

    The two tests above already carry both rules on the default accepted set. What those
    do not carry, and what these vectors did, is the explicit configuration each one
    stated, so those exact pairings are pinned here rather than lost in the move.
    """
    key = generate_key()
    v01 = sign_record(_fresh_record_with_profile(_TRACE_PROFILE_V0_1), key)
    jwk = key_to_jwk(key)

    # 03: a v0.1 record against a verifier that declares v0.2 and nothing else. The
    # default set is this set, so this pins that the explicit spelling behaves the same.
    assert DEFAULT_ACCEPTED_PROFILES == (TRACE_PROFILE_V0_2,), (
        "this test spells out the default; if the default moves, so must the vector "
        "it stands in for")
    with pytest.raises(ValueError, match="superseded v0.1 profile"):
        verify_record(v01, jwk, accepted_profiles=(TRACE_PROFILE_V0_2,))

    # 08: a v0.1 record against a verifier that declares both. The configuration is
    # refused before the record is looked at, so the message is the set's and not the
    # record's, which is the distinction the vector existed to make.
    with pytest.raises(ValueError, match="superseded v0.1 identifier"):
        verify_record(v01, jwk,
                      accepted_profiles=(TRACE_PROFILE_V0_2, _TRACE_PROFILE_V0_1))

    # A verifier declaring v0.1 alone is refused for its configuration too, so the two
    # refusals above are not this record being unacceptable under every set.
    with pytest.raises(ValueError, match="superseded v0.1 identifier"):
        verify_record(v01, jwk, accepted_profiles=(_TRACE_PROFILE_V0_1,))

    # Control: an ordinary v0.2 record verifies under the same declared set that refused
    # the v0.1 one, so the first refusal is the record's profile and not the set.
    v02 = sign_record(_fresh_record_with_profile(TRACE_PROFILE_V0_2), key)
    verify_record(v02, jwk, accepted_profiles=(TRACE_PROFILE_V0_2,))


def test_verify_record_rejects_unknown_profile():
    """A future or foreign profile is refused, not best-effort verified."""
    key = generate_key()
    record = sign_record(
        _fresh_record_with_profile("tag:example.com,2031:trace-v9.9"), key
    )

    with pytest.raises(ValueError, match="is not"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_rejects_missing_profile():
    """A missing profile cannot be supplied by assumption."""
    key = generate_key()
    record = sign_record(_fresh_record_with_profile(None), key)

    with pytest.raises(ValueError, match="no 'eat_profile'"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_profile_check_runs_before_signature_work():
    """A wrong-profile record is refused even when its signature is garbage.

    The refusal must not depend on cryptographic work: the profile error, not a
    signature error, is what surfaces.
    """
    record = _fresh_record_with_profile("tag:agentrust.io,2026:trace-v0.1")
    record["signature"] = "not-even-base64url!!"

    with pytest.raises(ValueError, match="superseded v0.1 profile"):
        verify_record(record, key_to_jwk(generate_key()))


def test_verified_records_carry_the_exported_profile_constant():
    """The constant callers can pin is the one the verifier accepts."""
    assert TRACE_PROFILE_V0_2 == "tag:agentrust-io.com,2026:trace-v0.2"
    key = generate_key()
    record = sign_record(_fresh_record_with_profile(TRACE_PROFILE_V0_2), key)
    verify_record(record, key_to_jwk(key))  # must not raise


def test_verify_record_raises_for_tampered_record():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    trusted = key_to_jwk(key)
    record["iat"] = record["iat"] + 1  # tamper (and still fresh)
    with pytest.raises(InvalidSignature):
        verify_record(record, trusted)


def test_verify_record_raises_for_tampered_cnf_jwk():
    key = generate_key()
    other_key = generate_key()
    record = sign_record(_fresh_record(), key)
    trusted = key_to_jwk(key)
    record["cnf"]["jwk"] = key_to_jwk(other_key)
    with pytest.raises(ValueError, match=r"cnf\.jwk.*trusted key"):
        verify_record(record, trusted)


def test_verify_record_rejects_valid_signature_that_names_another_cnf_key():
    """A trusted signer must not authenticate another key as the confirmation key."""
    signer = generate_key()
    other = generate_key()
    record = _fresh_record()
    record["cnf"] = {"jwk": key_to_jwk(other)}
    body = _canonical_bytes(record)
    record["signature"] = base64.urlsafe_b64encode(signer.sign(body)).rstrip(b"=").decode()

    with pytest.raises(ValueError, match=r"cnf\.jwk.*trusted key"):
        verify_record(record, key_to_jwk(signer))


def test_verify_record_compares_key_identity_not_optional_jwk_metadata():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    trusted = {**key_to_jwk(key), "kid": "issuer-key-7", "use": "sig"}

    verify_record(record, trusted)


def test_verify_record_rejects_signed_record_without_confirmation_key():
    """A record with no confirmation key does not verify, whoever signed it.

    Since schema enforcement landed (#156) the rejection comes from the schema,
    which makes `cnf` required, rather than from the cnf-to-trusted-key binding
    below it: absent `cnf` is caught before the binding is reached. Both are
    correct refusals, and the earlier one is the more fundamental. Asserted on
    `cnf` rather than on the exact sentence so this does not re-break the next
    time the order of two correct checks changes.

    The binding itself is covered by test_verify_record_raises_for_tampered_cnf_jwk
    and test_verify_record_rejects_valid_signature_that_names_another_cnf_key,
    where `cnf` is present and names the wrong key.
    """
    key = generate_key()
    record = _fresh_record()
    record.pop("cnf", None)
    body = _canonical_bytes(record)
    record["signature"] = base64.urlsafe_b64encode(key.sign(body)).rstrip(b"=").decode()

    with pytest.raises(ValueError, match=r"cnf"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_raises_for_missing_signature():
    record = dict(_fresh_record())
    key = generate_key()
    with pytest.raises(ValueError, match="no 'signature' field"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_requires_trusted_key_by_default():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    with pytest.raises(ValueError, match="requires a trusted key"):
        verify_record(record)


def test_verify_record_embedded_key_opt_in_warns():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    with pytest.warns(UserWarning, match="cnf.jwk"):
        verify_record(record, allow_embedded_key=True)


def test_verify_record_rejects_wrong_trusted_key():
    key_a = generate_key()
    key_b = generate_key()
    record = sign_record(_fresh_record(), key_a)
    # Signed by A, verified against B's public key: must not verify.
    with pytest.raises(ValueError, match=r"cnf\.jwk.*trusted key"):
        verify_record(record, key_to_jwk(key_b))


def test_verify_record_rejects_expired_record():
    key = generate_key()
    record = _minimal_record()
    record["iat"] = int(time.time()) - 90000  # ~25h old, beyond 24h default
    record = sign_record(record, key)
    with pytest.raises(ValueError, match="stale"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_expired_allowed_when_max_age_none():
    key = generate_key()
    record = _minimal_record()
    record["iat"] = int(time.time()) - 90000
    record = sign_record(record, key)
    verify_record(record, key_to_jwk(key), max_age_seconds=None)  # must not raise


def test_verify_record_rejects_record_beyond_default_future_skew():
    key = generate_key()
    record = _minimal_record()
    record["iat"] = int(time.time()) + 301
    record = sign_record(record, key)

    with pytest.raises(ValueError, match="future"):
        verify_record(record, key_to_jwk(key))


def test_verify_record_accepts_record_within_default_future_skew():
    key = generate_key()
    record = _minimal_record()
    record["iat"] = int(time.time()) + 299
    record = sign_record(record, key)

    verify_record(record, key_to_jwk(key))


def test_verify_record_future_skew_is_deployment_configurable(monkeypatch):
    """The future-skew bound, asserted at exactly its edge under a frozen clock.

    This test used to set ``iat`` from ``int(time.time())``, which truncates,
    while ``verify_record`` compares against an unrounded ``time.time()``. Writing
    the true setup time as ``k + f`` and ``d`` for everything that elapses before
    the comparison, ``age = f + d - 601``, so it raised only while ``f + d < 1``.
    The margin was not one second out of six hundred, it was whatever remained of
    the current second minus the test's own runtime, and the per-run failure
    probability was ``d`` rather than anything fixed (#183).

    Freezing rather than widening is deliberate. Moving the assertion to ``+660``
    would remove the race by removing the test: an implementation whose comparison
    is off by a few seconds would pass either way, and this is a security-relevant
    freshness bound. With the clock frozen there is no race left, so the boundary
    is pinned on both sides instead.

    ``verify_record`` does a local ``import time``, which binds the same module
    object, so patching the attribute here reaches it.
    """
    frozen = 1_800_000_000.0
    monkeypatch.setattr(time, "time", lambda: frozen)

    key = generate_key()

    # 601s into the future is outside a 600s bound.
    beyond = _minimal_record()
    beyond["iat"] = int(frozen) + 601
    beyond = sign_record(beyond, key)
    with pytest.raises(ValueError, match="max_future_skew_seconds=600"):
        verify_record(beyond, key_to_jwk(key), max_future_skew_seconds=600)

    # ...and inside a bound configured above it.
    verify_record(beyond, key_to_jwk(key), max_future_skew_seconds=602)

    # 600s into the future is exactly at the bound, and accepted.
    at_edge = _minimal_record()
    at_edge["iat"] = int(frozen) + 600
    at_edge = sign_record(at_edge, key)
    verify_record(at_edge, key_to_jwk(key), max_future_skew_seconds=600)


def test_disabling_max_age_does_not_disable_future_bound():
    key = generate_key()
    record = _minimal_record()
    record["iat"] = int(time.time()) + 3600
    record = sign_record(record, key)

    with pytest.raises(ValueError, match="future"):
        verify_record(record, key_to_jwk(key), max_age_seconds=None)


def test_verify_record_rejects_negative_future_skew_configuration():
    key = generate_key()
    record = sign_record(_fresh_record(), key)

    with pytest.raises(ValueError, match="must be non-negative"):
        verify_record(record, key_to_jwk(key), max_future_skew_seconds=-1)


# --- freshness policy inputs, shared with provenance.py via `_check_seconds` --
#
# The age/skew bounds are verifier configuration, and a malformed one fails in
# the direction that matters: -1 is not a stricter bound, it calls every
# record ever issued stale, uniformly, with no error naming the cause. `bool`
# gets its own case because it is a subclass of `int`, so `True` would
# otherwise be accepted as one second. `provenance.verify_record` already
# guarded against this (per the review on #164); this is that same guard on
# the Trust Record side.


@pytest.mark.parametrize("bad", [-1, -86400, True, False, 1.5, "300", object()])
def test_a_malformed_max_age_is_reported_not_applied(bad) -> None:
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    with pytest.raises(ValueError) as exc:
        verify_record(record, key_to_jwk(key), max_age_seconds=bad)
    assert "max_age_seconds must be" in str(exc.value)


@pytest.mark.parametrize("bad", [True, False, 1.5, "300", None])
def test_a_malformed_skew_is_reported_not_applied(bad) -> None:
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    with pytest.raises(ValueError) as exc:
        verify_record(record, key_to_jwk(key), max_future_skew_seconds=bad)
    assert "max_future_skew_seconds must be" in str(exc.value)


@pytest.mark.parametrize("ok", [1, 86400])
def test_a_well_formed_bound_still_verifies(ok: int) -> None:
    key = generate_key()
    verify_record(sign_record(_fresh_record(), key), key_to_jwk(key), max_age_seconds=ok)
    verify_record(
        sign_record(_fresh_record(), key), key_to_jwk(key), max_future_skew_seconds=ok
    )


@pytest.mark.parametrize("bad", [-1, -86400, True, False, 1.5, "300", object(), None])
def test_a_malformed_bundle_age_is_reported_not_applied(bad) -> None:
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    with pytest.raises(ValueError) as exc:
        verify_record(record, key_to_jwk(key), max_bundle_age_seconds=bad)
    assert "max_bundle_age_seconds must be" in str(exc.value)


@pytest.mark.parametrize("ok", [1, 86400])
def test_a_well_formed_bundle_age_still_verifies(ok: int) -> None:
    key = generate_key()
    verify_record(
        sign_record(_fresh_record(), key), key_to_jwk(key), max_bundle_age_seconds=ok
    )


def test_zero_is_a_bound_and_not_a_falsy_stand_in_for_unset() -> None:
    """`0` and `None` are different policies and must not be conflated.

    `None` disables the age bound; `0` is the strictest one expressible - the
    record must be issued at this instant, so anything already in the past is
    stale. A validator that treated `0` as falsy would silently accept every
    record under the strictest policy a caller can write.
    """
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    time.sleep(1.1)
    verify_record(record, key_to_jwk(key), max_age_seconds=None)  # disabled: passes
    with pytest.raises(ValueError, match="stale"):
        verify_record(record, key_to_jwk(key), max_age_seconds=0)


def test_verify_record_rejects_non_okp_jwk():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    ec_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
    with pytest.raises(ValueError, match="kty"):
        verify_record(record, ec_jwk)


def test_verify_record_nonce_match():
    key = generate_key()
    record = _fresh_record()
    record["runtime"]["nonce"] = "abc123"
    record = sign_record(record, key)
    verify_record(record, key_to_jwk(key), expected_nonce="abc123")  # must not raise
    with pytest.raises(ValueError, match="nonce"):
        verify_record(record, key_to_jwk(key), expected_nonce="wrong")


def test_verify_record_rejects_malformed_signature():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    record["signature"] = "!!!not base64!!!"
    with pytest.raises(ValueError, match="base64url"):
        verify_record(record, key_to_jwk(key))


# --- RFC 7638 JWK thumbprints -----------------------------------------------


def test_jwk_thumbprint_rfc8037_known_answer():
    """Known-answer vector from RFC 8037 Appendix A.3 (Ed25519 JWK thumbprint).

    Pinning the published vector proves the member set, ordering, and encoding
    match the RFC, so a thumbprint computed here is the same identifier a
    revocation list published by anyone else is keyed on.
    """
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }
    assert jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_jwk_thumbprint_ignores_optional_members():
    """Only the required members are hashed, so kid/alg/use do not change the value."""
    key = generate_key()
    bare = key_to_jwk(key)
    decorated = {**bare, "kid": "key-2026-07", "alg": "EdDSA", "use": "sig"}
    assert jwk_thumbprint(decorated) == jwk_thumbprint(bare)


def test_jwk_thumbprint_distinguishes_keys():
    assert jwk_thumbprint(key_to_jwk(generate_key())) != jwk_thumbprint(
        key_to_jwk(generate_key())
    )


def test_jwk_thumbprint_rejects_unknown_kty():
    with pytest.raises(ValueError, match="kty"):
        jwk_thumbprint({"kty": "unknown", "x": "abc"})


def test_jwk_thumbprint_rejects_missing_member():
    with pytest.raises(ValueError, match="missing required thumbprint member 'x'"):
        jwk_thumbprint({"kty": "OKP", "crv": "Ed25519"})


# --- Revocation at verification time (#76) ----------------------------------


def test_verify_record_rejects_revoked_key_by_thumbprint():
    """A record signed by a listed key is rejected even though its signature is valid."""
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    trusted = key_to_jwk(key)
    revoked = {jwk_thumbprint(trusted)}

    # Sanity: the same record verifies when the key is not revoked.
    verify_record(record, trusted, revocation=set())

    with pytest.raises(ValueError, match="revoked"):
        verify_record(record, trusted, revocation=revoked)


def test_verify_record_passes_when_other_keys_revoked():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    other = jwk_thumbprint(key_to_jwk(generate_key()))
    verify_record(record, key_to_jwk(key), revocation={other})  # must not raise


def test_verify_record_rejects_revoked_key_by_kid():
    """A store keyed on kid works for issuers that publish one."""
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    trusted = {**key_to_jwk(key), "kid": "issuer-key-3"}
    with pytest.raises(ValueError, match="issuer-key-3"):
        verify_record(record, trusted, revocation={"issuer-key-3"})


def test_verify_record_revocation_accepts_callable_store():
    """A callable store models a live CRL / status / SCITT lookup."""
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    trusted = key_to_jwk(key)
    seen: list[str] = []

    def is_revoked(identifier: str) -> bool:
        seen.append(identifier)
        return False

    verify_record(record, trusted, revocation=is_revoked)  # must not raise
    assert seen == [jwk_thumbprint(trusted)]

    with pytest.raises(ValueError, match="revoked"):
        verify_record(record, trusted, revocation=lambda _identifier: True)


def test_verify_record_fails_closed_when_revocation_source_errors():
    """An unreachable revocation source is a rejection, not a pass.

    This is the whole point of checking: if a lookup failure fell through to
    "verified", an attacker holding a revoked key would only need to make the
    status endpoint unreachable.
    """
    key = generate_key()
    record = sign_record(_fresh_record(), key)

    def unreachable(_identifier: str) -> bool:
        raise ConnectionError("status endpoint unreachable")

    with pytest.raises(ValueError, match="could not be determined"):
        verify_record(record, key_to_jwk(key), revocation=unreachable)


@pytest.mark.parametrize("answer", [None, "", 0, [], {}, 0.0])
def test_verify_record_fails_closed_when_the_store_answers_with_a_non_bool(answer):
    """A falsy non-bool is not "not revoked". It is no answer at all.

    ``RevocationStore`` is ``Callable[[str], bool]``. Before this, the return value
    was read by truthiness, so every value here let the key through. ``None`` is the
    one that matters: it is what a lookup returns when its author handled the 200 and
    forgot the rest, which is precisely the outage
    ``test_verify_record_fails_closed_when_revocation_source_errors`` exists to
    survive. The two cases are one fact, and only the noisier half was covered.
    """
    key = generate_key()
    record = sign_record(_fresh_record(), key)

    with pytest.raises(ValueError, match="could not be determined"):
        verify_record(record, key_to_jwk(key), revocation=lambda _identifier: answer)


@pytest.mark.parametrize("answer", ["no", "false", "unrevoked", [0]])
def test_verify_record_fails_closed_when_a_truthy_non_bool_would_have_read_as_revoked(answer):
    """The same guard, from the side that would not have been a security hole.

    Truthiness read ``"no"`` as revoked and ``0`` as not revoked, which is not a
    conservative reading in one direction and a lax one in the other. It is no
    reading at all: the truth value of a string says nothing about revocation. Both
    halves have to fail closed or the guard is a coin flip that happens to land
    safely half the time.
    """
    key = generate_key()
    record = sign_record(_fresh_record(), key)

    with pytest.raises(ValueError, match="could not be determined"):
        verify_record(record, key_to_jwk(key), revocation=lambda _identifier: answer)


def test_verify_record_still_accepts_the_two_answers_the_type_allows():
    """Without this, refusing every callable would pass both tests above."""
    key = generate_key()
    record = sign_record(_fresh_record(), key)

    verify_record(record, key_to_jwk(key), revocation=lambda _identifier: False)

    with pytest.raises(ValueError, match="revoked"):
        verify_record(record, key_to_jwk(key), revocation=lambda _identifier: True)


def test_the_membership_branch_is_untouched_by_the_bool_guard():
    """``in`` yields a real bool whatever ``__contains__`` returns, so a container
    store needs no guard and must not acquire one by accident."""

    class AnswersWithAString:
        def __contains__(self, _identifier: object) -> bool:
            return "yes"  # type: ignore[return-value]

    key = generate_key()
    record = sign_record(_fresh_record(), key)

    with pytest.raises(ValueError, match="revoked"):
        verify_record(record, key_to_jwk(key), revocation=AnswersWithAString())

    verify_record(record, key_to_jwk(key), revocation=set())


def test_verify_record_revocation_works_with_public_key_object():
    """The trusted key may be an Ed25519PublicKey; its JWK is derived for the check."""
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(key_to_jwk(key)["x"]))

    verify_record(record, pub, revocation=set())  # must not raise
    with pytest.raises(ValueError, match="revoked"):
        verify_record(record, pub, revocation={jwk_thumbprint(key_to_jwk(key))})


def test_verify_record_revocation_rejects_underivable_trusted_key():
    """A trusted key whose identifiers cannot be derived is refused, not skipped."""

    class OpaqueKey:
        def verify(self, signature: bytes, data: bytes) -> None:
            return None

    key = generate_key()
    record = sign_record(_fresh_record(), key)
    with pytest.raises(ValueError, match="revocation checking needs"):
        verify_record(record, OpaqueKey(), revocation=set())


def test_verify_record_revocation_checked_against_trusted_key_not_record():
    """cnf.jwk is attacker-controlled until the signature verifies, so it is not the
    identifier the revocation check reads. A revoked issuer cannot escape the list by
    embedding some other key in the record."""
    revoked_key = generate_key()
    record = sign_record(_fresh_record(), revoked_key)
    record["cnf"]["jwk"] = key_to_jwk(generate_key())  # unlisted key, planted

    trusted = key_to_jwk(revoked_key)
    with pytest.raises(ValueError, match="revoked"):
        verify_record(record, trusted, revocation={jwk_thumbprint(trusted)})


def test_verify_record_without_revocation_store_stays_offline():
    """The default remains pure offline verification: no store, no check, no error."""
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    verify_record(record, key_to_jwk(key))  # must not raise


# --- RFC 8785 (JCS) canonicalization ----------------------------------------


def test_canonical_bytes_sorts_keys_no_whitespace():
    """JCS sorts object keys and emits no inter-token whitespace."""
    assert _canonical_bytes({"b": 1, "a": 2, "c": 3}) == b'{"a":2,"b":1,"c":3}'


def test_canonical_bytes_known_answer_non_ascii():
    """Known-answer vector: non-ASCII strings are raw UTF-8, NOT \\uXXXX escapes.

    This is the headline divergence from ``json.dumps(..., ensure_ascii=True)``,
    which the old implementation used. A regression to json.dumps would emit the
    escaped form on the right and fail this literal-bytes assertion.
    """
    obj = {"msg": "hüllo", "id": "café"}
    expected = b'{"id":"caf\xc3\xa9","msg":"h\xc3\xbcllo"}'
    assert _canonical_bytes(obj) == expected
    # The discarded json.dumps form would have escaped the non-ASCII code points.
    assert json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() == (
        b'{"id":"caf\\u00e9","msg":"h\\u00fcllo"}'
    )
    assert _canonical_bytes(obj) != json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def test_canonical_bytes_known_answer_numbers():
    """Known-answer vector for JCS / RFC 8785 §3.2.2.3 number serialization.

    ``1e-7`` is the RFC 8785 shortest round-trip form; Python's ``json.dumps``
    emits ``1e-07`` (zero-padded exponent), so this literal assertion catches a
    regression to json.dumps for number formatting.
    """
    assert _canonical_bytes({"n": 1e-7}) == b'{"n":1e-7}'
    assert json.dumps(1e-7) == "1e-07"  # the non-conformant form we moved away from


def test_canonical_bytes_matches_reference_library():
    """Cross-check the full record canonicalization against the rfc8785 reference."""
    record = _minimal_record()
    record["model"]["note"] = "résumé"  # non-ASCII to exercise the divergence
    assert _canonical_bytes(record) == rfc8785.dumps(record)


def test_jcs_distinguishes_unicode_key_order_from_json_dumps():
    """JCS sorts keys by UTF-16 code unit; this differs from naive byte sorting.

    Astral-plane code points (here U+1F600, encoded as a surrogate pair in
    UTF-16) sort AFTER the BMP key ``z`` under UTF-16 code-unit ordering. Python
    ``json.dumps(sort_keys=True)`` sorts by Unicode code point, placing the
    astral key (U+1F600) BEFORE ``z`` (U+007A). The two schemes therefore
    produce different byte sequences for the same object, even though both claim
    to "sort keys".
    """
    obj = {"z": 1, "\U0001f600": 2}
    jcs = _canonical_bytes(obj)
    jdump = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    # JCS (UTF-16 code unit): high surrogate 0xD83D > 0x007A, so "z" comes first.
    assert jcs == b'{"z":1,"\xf0\x9f\x98\x80":2}'
    # json.dumps (code point): 0x1F600 > 0x007A as a scalar, so order matches here,
    # but the emoji is escaped as a surrogate pair, diverging in bytes regardless.
    assert jcs != jdump


def test_round_trip_with_non_ascii_payload():
    """End-to-end: signing and verifying a record carrying non-ASCII data."""
    key = generate_key()
    record = _fresh_record()
    record["model"]["provider"] = "modèle français \U0001f916"
    signed = sign_record(record, key)
    verify_record(signed, key_to_jwk(key))  # must not raise


# ---------------------------------------------------------------------------
# Format-versioning and verifier-compatibility vectors (agentrust-io#116).
#
# Evidence outlives verifier builds: a compliance artifact is verified years
# after issuance, so a verifier that meets an unrecognised profile must refuse
# rather than verify on a best-effort basis, and must say which semantics it
# verified under. The four vectors below are the ones named in the issue.
#
# The first also implements a requirement already merged into spec/trace-v0.2.md
# ("Changes from v0.1"): a v0.2 verifier MUST reject the v0.1 identifier and MUST
# NOT accept both.
# ---------------------------------------------------------------------------


def _record_with_profile(profile: str) -> tuple[dict, dict]:
    """Return a correctly signed record carrying *profile*, plus its trusted JWK.

    The signature is genuine in every case. That is the point of these vectors:
    the question is never "does the signature check out", it is "does this build
    implement what the record was written under".
    """
    key = generate_key()
    record = _fresh_record()
    record["eat_profile"] = profile
    signed = sign_record(record, key)
    return signed, key_to_jwk(key)


def test_vector_unknown_version_is_refused():
    """Vector 1: unknown-version artifact must be refused, not best-effort verified."""
    record, jwk = _record_with_profile("tag:example.com,2031:trace-v9.9")

    with pytest.raises(ValueError, match="not in this verifier's accepted set"):
        verify_record(record, jwk)


def test_vector_superseded_v0_1_profile_is_refused():
    """spec/trace-v0.2.md: a v0.2 verifier MUST reject the v0.1 identifier."""
    record, jwk = _record_with_profile(_TRACE_PROFILE_V0_1)

    # Upstream #125's tailored message for this case, kept through the merge: the
    # v0.1 identifier is named as superseded, not merely absent from the accepted set.
    with pytest.raises(ValueError, match="superseded v0.1 profile"):
        verify_record(record, jwk)

    assert _TRACE_PROFILE_V0_1 not in DEFAULT_ACCEPTED_PROFILES, (
        "the default accepted set must not carry the superseded identifier; "
        "accepting both is what the v0.2 cutover forbids"
    )


def test_dual_accept_configuration_is_unrepresentable():
    """spec/trace-v0.2.md: a v0.2 verifier MUST NOT accept both identifiers.

    Enforced at configuration, not per record: a set containing the v0.1 tag is
    refused before any record is examined, so the dual-accepting verifier the
    cutover forbids cannot be built from this library at all, even when the record
    presented is a perfectly good v0.2 one.
    """
    record, jwk = _record_with_profile(TRACE_PROFILE_V0_2)

    with pytest.raises(ValueError, match="superseded v0.1 identifier"):
        verify_record(
            record,
            jwk,
            accepted_profiles=(TRACE_PROFILE_V0_2, _TRACE_PROFILE_V0_1),
        )

    v01_record, v01_jwk = _record_with_profile(_TRACE_PROFILE_V0_1)
    with pytest.raises(ValueError, match="superseded v0.1 identifier"):
        verify_record(v01_record, v01_jwk, accepted_profiles=(_TRACE_PROFILE_V0_1,))


def test_vector_known_version_verifies_and_echoes_the_profile():
    """Vector 2: a supported version verifies, and the statement names it."""
    record, jwk = _record_with_profile(TRACE_PROFILE_V0_2)

    statement = verify_record(record, jwk)

    assert isinstance(statement, VerificationResult)
    assert statement.profile == TRACE_PROFILE_V0_2
    assert statement.accepted_profiles == DEFAULT_ACCEPTED_PROFILES
    # `trusted_key_thumbprint` is upstream's, and it is what `key_source` was reaching
    # for before this branch was synced: the result names the key it verified against
    # rather than leaving the reader to assume which one ran.
    assert statement.trusted_key_thumbprint == jwk_thumbprint(jwk)


def test_vector_widening_to_an_unschemaed_profile_is_refused():
    """Vector 3: a verifier may only accept a profile whose shape it can check.

    This asserted the opposite until the set was measured: widening was treated as a
    disclosed downgrade and expected to verify. It never did. The record was refused
    a few lines later by the schema, whose ``eat_profile`` is a ``const``, so the
    declared set could be widened but no record could ever be verified under the
    addition. Refusing the configuration says that at the point the claim is made,
    rather than reporting a structural failure for a record that has nothing wrong
    with it.
    """
    older = "tag:example.com,2025:trace-v0.0"
    record, jwk = _record_with_profile(TRACE_PROFILE_V0_2)

    with pytest.raises(ValueError, match="carries no schema for"):
        verify_record(record, jwk, accepted_profiles=(TRACE_PROFILE_V0_2, older))

    assert older not in DEFAULT_ACCEPTED_PROFILES


def test_a_disclosed_downgrade_is_unreachable_in_this_build():
    """The consequence of the rule above, pinned rather than left to be rediscovered.

    ``VerificationResult`` can express a run under a profile other than the newest
    the verifier declared. This build cannot produce one: the only profiles it carries
    a schema for are v0.2 and the v0.1 identifier, and the cutover forbids accepting
    v0.1 under any configuration. So every accepted set this build permits is exactly
    ``(v0.2,)``, and a statement's profile is always its first element.

    That is a property of a single-schema build, not of the design. A build shipping a
    second acceptable schema would reach it, which is why the field stays.
    """
    from agentrust_trace.validate import profiles_with_schema

    permitted = profiles_with_schema() - {_TRACE_PROFILE_V0_1}
    assert permitted == {TRACE_PROFILE_V0_2}, (
        "a second acceptable schema is now shipped, so a disclosed downgrade is "
        "reachable and this test should be replaced by one that exercises it"
    )

    record, jwk = _record_with_profile(TRACE_PROFILE_V0_2)
    statement = verify_record(record, jwk, accepted_profiles=(TRACE_PROFILE_V0_2,))
    assert statement.profile == statement.accepted_profiles[0]


def test_vector_silent_downgrade_has_no_code_path():
    """Vector 4: silent fallback must fail conformance. Here it is unrepresentable.

    There is no argument to ``verify_record`` that verifies a profile outside the
    declared set, so a downgrade cannot happen without appearing in
    ``accepted_profiles``. The vector is satisfied structurally rather than by a
    runtime check that could itself be bypassed.
    """
    older = "tag:example.com,2025:trace-v0.0"
    record, jwk = _record_with_profile(older)

    # Default set: refused.
    with pytest.raises(ValueError):
        verify_record(record, jwk)

    # A set that excludes the record's profile: still refused, however the other
    # arguments are relaxed.
    with pytest.raises(ValueError):
        verify_record(record, jwk, max_age_seconds=None, accepted_profiles=(TRACE_PROFILE_V0_2,))


def test_verify_record_rejects_record_without_a_profile():
    """A missing profile cannot be supplied by assumption."""
    key = generate_key()
    record = _fresh_record()
    del record["eat_profile"]
    signed = sign_record(record, key)

    with pytest.raises(ValueError, match="no 'eat_profile'"):
        verify_record(signed, key_to_jwk(key))


def test_verify_record_rejects_empty_accepted_profiles():
    """A verifier that supports nothing must say so, not accept everything."""
    record, jwk = _record_with_profile(TRACE_PROFILE_V0_2)

    with pytest.raises(ValueError, match="accepted_profiles is empty"):
        verify_record(record, jwk, accepted_profiles=())


def test_verification_statement_reports_check_coverage():
    """The result distinguishes "checked and passed" from "never checked".

    This asserted four booleans this branch had added to a type of its own:
    `key_source`, `freshness_checked`, `nonce_checked` and `revocation_checked`. None of
    them is in #116, which asks for the profile and nothing else, and the branch was
    synced onto a main where `VerificationResult` already reports revocation coverage
    properly, as an outcome rather than a boolean. So the three that upstream does not
    carry are gone rather than ported: they were scope this proposal never claimed, and
    carrying them would have widened a #116 pull request by four fields nobody asked
    for. What survives is the property they were reaching for, asserted against the
    field upstream already ships.
    """
    record, jwk = _record_with_profile(TRACE_PROFILE_V0_2)

    # Documented in LIMITATIONS.md: without a store or a bundle, non-revocation is
    # unproven rather than disproven, and the result has to say which of the two.
    offline = verify_record(record, jwk)
    assert offline.revocation.outcome == "no_check_performed"

    nonce_key = generate_key()
    with_nonce = _fresh_record()
    with_nonce["runtime"]["nonce"] = "abc123"
    resigned = sign_record(with_nonce, nonce_key)
    checked = verify_record(
        resigned,
        key_to_jwk(nonce_key),
        max_age_seconds=None,
        expected_nonce="abc123",
        revocation=frozenset(),
    )
    assert checked.revocation.outcome != "no_check_performed"
    assert checked.profile == TRACE_PROFILE_V0_2


# --- the parameter's own type, not the shape inside it ------------------------
#
# verify_record documents ValueError and InvalidSignature; jwk_thumbprint
# documents ValueError. Both dereferenced their first parameter with `.get(...)`
# before establishing it was a mapping, so every non-dict input left through an
# AttributeError instead, which a caller's `except ValueError` does not catch.
#
# This is about the parameter itself rather than any field within it. Guards on
# fields inside a record cannot reach it: `record["identity"]` is only checkable
# once `record` is known to be a dict.

NON_OBJECTS = [None, 5, 0, "a string", "", [], [1, 2], True, False, b"bytes"]


@pytest.mark.parametrize("bad", NON_OBJECTS)
def test_verify_record_refuses_a_non_object_record(bad):
    key = generate_key()
    with pytest.raises(ValueError, match="record must be a JSON object"):
        verify_record(bad, key_to_jwk(key))


@pytest.mark.parametrize("bad", NON_OBJECTS)
def test_jwk_thumbprint_refuses_a_non_object_jwk(bad):
    with pytest.raises(ValueError, match="jwk must be a JSON object"):
        jwk_thumbprint(bad)


@pytest.mark.parametrize("body", [b"[1,2,3]", b'"a string"', b"null", b"42", b"true"])
def test_a_caller_catching_valueerror_catches_an_untrusted_body(body):
    """The shape this actually takes in a caller.

    A verifier receives bytes, parses them, and rejects what does not verify.
    Every one of these bodies is valid JSON and none is an object. With the
    parameter unchecked they raised AttributeError, which is not a ValueError,
    so they escaped the rejection branch entirely and surfaced as an unhandled
    error in whatever was calling the verifier.
    """
    key = generate_key()
    try:
        verify_record(json.loads(body), key_to_jwk(key))
    except ValueError:
        return
    pytest.fail(f"{body!r} was accepted, or left through something ValueError misses")


def test_the_record_type_is_checked_before_the_record_is_read():
    """Ordering: verifier-configuration errors still come first.

    `accepted_profiles` is the verifier's own configuration and is wrong before
    any record is involved, so it keeps reporting first. The record's type is
    checked after that and before the record is read.
    """
    key = generate_key()
    with pytest.raises(ValueError, match="accepted_profiles is empty"):
        verify_record(None, key_to_jwk(key), accepted_profiles=())
#: Values a caller can hand a function that documents an object argument. The last
#: five are the ones a record assembled from parsed JSON can actually carry.
_NOT_AN_OBJECT = ("a-string", 123, None, [1, 2], True, False, 0, "", b"bytes", 1.5)


@pytest.mark.parametrize("value", _NOT_AN_OBJECT)
def test_jwk_thumbprint_refuses_a_non_object_with_the_error_it_documents(value):
    """`jwk_thumbprint` documents `ValueError` and read `.get` off its argument first.

    A JWK reaches it from a peer, a key document, or a record's own `cnf`, so its shape
    is not something the caller has established. Before this it raised `AttributeError`,
    which a caller written against the documented contract does not catch.
    """
    with pytest.raises(ValueError):
        jwk_thumbprint(value)


@pytest.mark.parametrize("value", _NOT_AN_OBJECT)
def test_verify_record_refuses_a_non_object_record_with_the_error_it_documents(value):
    """Same shape, on the argument that is by definition untrusted.

    `verify_record`'s docstring says every rejection other than a bad signature is a
    `ValueError`. A non-object record reached `record.get("eat_profile")` and raised
    `AttributeError` instead.
    """
    key = generate_key()
    with pytest.raises(ValueError):
        verify_record(value, key_to_jwk(key))


def test_the_guards_do_not_refuse_what_they_should_accept():
    """Without this, raising unconditionally would pass both tests above."""
    key = generate_key()
    record = sign_record(_fresh_record(), key)

    jwk_thumbprint(key_to_jwk(key))
    verify_record(record, key_to_jwk(key))


@pytest.mark.parametrize("value", [None, 0, False, [], {}, 1, True, [0], {"a": 1}])
def test_present_non_string_signature_reports_wrong_type(value):
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    record["signature"] = value
    with pytest.raises(ValueError, match="^signature must be a base64url string$"):
        verify_record(record, key_to_jwk(key), now=record["iat"])


def test_present_empty_signature_is_invalid_not_missing():
    key = generate_key()
    record = sign_record(_fresh_record(), key)
    record["signature"] = ""
    with pytest.raises(ValueError, match="does not conform.*signature"):
        verify_record(record, key_to_jwk(key), now=record["iat"])


@pytest.mark.parametrize("nonce", ["abc123", "n\u00f8nce", "\U0001f512"])
def test_verify_record_nonce_unicode_match(nonce):
    key = generate_key()
    record = _fresh_record()
    record["runtime"]["nonce"] = nonce
    signed = sign_record(record, key)
    verify_record(signed, key_to_jwk(key), expected_nonce=nonce)


@pytest.mark.parametrize(
    ("actual", "expected"),
    [
        ("wrong", "abc123"),
        ("n\u00f8nce", "a-nonce-value"),
        ("a-nonce-value", "n\u00f8nce"),
        ("\U0001f512", "\U0001f513"),
        ("\u00e9", "e\u0301"),
    ],
)
def test_verify_record_nonce_unicode_mismatch(actual, expected):
    key = generate_key()
    record = _fresh_record()
    record["runtime"]["nonce"] = actual
    signed = sign_record(record, key)
    with pytest.raises(ValueError, match="record runtime.nonce does not match expected_nonce"):
        verify_record(signed, key_to_jwk(key), expected_nonce=expected)


@pytest.mark.parametrize("expected", [b"a-nonce-value", 123, [], True, {}])
def test_verify_record_rejects_invalid_expected_nonce_configuration(expected):
    key = generate_key()
    record = _fresh_record()
    record["runtime"]["nonce"] = "a-nonce-value"
    signed = sign_record(record, key)
    with pytest.raises(ValueError, match="^expected_nonce must be a string$"):
        verify_record(signed, key_to_jwk(key), expected_nonce=expected)


def test_nonce_verdict_uses_compare_digest_result(monkeypatch):
    key = generate_key()
    record = _fresh_record()
    record["runtime"]["nonce"] = "n\u00f8nce"
    signed = sign_record(record, key)
    real_compare = hmac.compare_digest
    seen = []

    def refuse_nonce(a, b):
        if isinstance(a, bytes) and isinstance(b, bytes):
            seen.append((a, b))
            return False
        return real_compare(a, b)

    monkeypatch.setattr(hmac, "compare_digest", refuse_nonce)
    with pytest.raises(ValueError, match="record runtime.nonce does not match expected_nonce"):
        verify_record(signed, key_to_jwk(key), expected_nonce="n\u00f8nce")
    assert seen == [("n\u00f8nce".encode("utf-8"), "n\u00f8nce".encode("utf-8"))]

"""Tests for agentrust_trace.sign."""

import base64
import json
import time

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace import (
    TRACE_PROFILE_V0_2,
    TrustRecord,
    generate_key,
    jwk_thumbprint,
    key_to_jwk,
    sign_record,
    verify_record,
)
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
    """spec/trace-v0.2.md section 2: a v0.2 verifier MUST reject the v0.1 identifier.

    The signature is genuine; the refusal must come from the profile, not from
    tampering, or this would test the wrong check.
    """
    key = generate_key()
    record = sign_record(
        _fresh_record_with_profile("tag:agentrust.io,2026:trace-v0.1"), key
    )

    with pytest.raises(ValueError, match="superseded v0.1 profile"):
        verify_record(record, key_to_jwk(key))


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

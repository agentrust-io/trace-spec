"""One signature, one spelling: the verifiers decode base64url strictly.

``sign._b64url_decode`` used ``base64.urlsafe_b64decode``, which is lenient: it
accepts the standard alphabet's ``+`` and ``/``, trailing ``=`` padding, and
characters outside any alphabet (discarded without a word), and it ignores the
unused low bits of the final character. So one set of signature bytes had many
spellings that all verified. Wherever a spelling is itself signed or digested,
that is malleability: a revocation bundle's ``bundle_digest`` covers
``sig.value``, so two spellings of one bundle produced two different digests
for the same evidence, each reported as ``verified``.

The decoder now accepts only canonical unpadded base64url (RFC 4648 section 5
alphabet, no padding, no other characters, unused bits zero), for every field
it reads: the Trust Record signature, a JWK ``x``, the provenance signature,
the PIC/TRACE bridge signature and the bundle signature.

The Trust Record's own ``signature`` pattern and the requirement that its
unused bits be zero are the normative half of this, proposed separately in
#401 and not changed here. This file tests the reference decoder.
"""

from __future__ import annotations

import base64
import time

import pytest

from agentrust_trace import intent_bridge, provenance
from agentrust_trace.revocation import check_bundle
from agentrust_trace.sign import (
    TRACE_PROFILE_V0_2,
    _b64url_decode,
    _canonical_bytes,
    generate_key,
    jwk_thumbprint,
    key_to_jwk,
    sign_record,
    verify_record,
)


def _respell_unused_bits(value: str) -> str:
    """Same decoded bytes, different final character: set the unused low bits."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    unused = {2: 4, 3: 2}[len(value) % 4]
    last = alphabet.index(value[-1])
    return value[:-1] + alphabet[last | ((1 << unused) - 1)]


def _to_standard_alphabet(value: str) -> str:
    return value.replace("-", "+").replace("_", "/")


# --- the decoder -------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling",
    [
        "AAE=",  # padding
        "AA E",  # a character outside the alphabet
        "AA.E",
        "AAE\n",
        "+/8",  # the standard alphabet
        "AAF",  # nonzero unused bits (canonical form is AAE)
        "A",  # a length no byte string encodes to
        "ＡＡＥ",  # non-ASCII lookalikes
    ],
)
def test_the_decoder_refuses_every_non_canonical_spelling(spelling):
    with pytest.raises(ValueError, match="base64url"):
        _b64url_decode(spelling, field="f")


@pytest.mark.parametrize("raw", [b"", b"\x00", b"\x00\x01", b"\xff\xfe\xfd", bytes(range(64))])
def test_the_decoder_round_trips_every_canonical_spelling(raw):
    spelled = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    assert _b64url_decode(spelled, field="f") == raw


# --- each verifier that decodes a signature ------------------------------------------


def _trust_record(key):
    return sign_record(
        {
            "eat_profile": TRACE_PROFILE_V0_2,
            "iat": int(time.time()),
            "subject": "spiffe://acme.example/agent/a",
            "model": {"provider": "acme", "model_id": "m-1"},
            "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
            "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
            "data_class": "internal",
            "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
            "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
        },
        key,
    )


def test_trust_record_signature_with_nonzero_unused_bits_is_refused():
    key = generate_key()
    record = _trust_record(key)
    verify_record(record, key_to_jwk(key))
    record["signature"] = _respell_unused_bits(record["signature"])
    with pytest.raises(ValueError, match="canonical"):
        verify_record(record, key_to_jwk(key))


@pytest.mark.parametrize("respell", [_respell_unused_bits, _to_standard_alphabet,
                                     lambda s: s + "==", lambda s: s[:10] + "\n" + s[10:]])
def test_provenance_signature_respellings_are_refused(respell):
    key = generate_key()
    record = provenance.sign_record(
        provenance.build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=[{"name": "t", "description": "d", "input_schema": {}}],
            artifact={"package": "p", "digest": "sha256:" + "a" * 64},
        ),
        key,
    )
    provenance.verify_record(record, key_to_jwk(key))
    respelled = respell(record["signature"])
    if respelled == record["signature"]:
        pytest.skip("this signature has no - or _ to respell")
    record["signature"] = respelled
    with pytest.raises(provenance.ProvenanceError):
        provenance.verify_record(record, key_to_jwk(key))


def test_bridge_signature_with_nonzero_unused_bits_is_refused():
    key = generate_key()
    tool_call = {"name": "t", "arguments": {}}
    declaration = {"impact": "i"}
    authorization = {
        "authorization_id": "a-1",
        "decision": "allow",
        "authorizer": "policy",
        "authorizer_key_id": "k-1",
        "authorized_at": 100,
        "expires_at": 200,
        "scope": {"tools": ["t"], "impacts": ["i"]},
        "pic": {
            "profile": "PIC-CJSON/1.0",
            "intent_digest": "sha256:" + "1" * 64,
            "args_digest": "sha256:" + "2" * 64,
        },
        "declaration_digest": intent_bridge.digest_jcs(declaration),
        "tool_call_digest": intent_bridge.digest_jcs(tool_call),
        "transcript_required": False,
    }
    bridge = intent_bridge.sign_bridge(authorization, key)
    kwargs = {
        "declaration": declaration,
        "pic_intent_digest": "sha256:" + "1" * 64,
        "pic_args_digest": "sha256:" + "2" * 64,
        "tool_call": tool_call,
        "now": 150,
    }
    trusted = {**key_to_jwk(key), "kid": "k-1"}
    intent_bridge.verify_bridge(bridge, trusted, **kwargs)
    bridge["signature"] = _respell_unused_bits(bridge["signature"])
    with pytest.raises(intent_bridge.IntentBridgeError, match="base64url"):
        intent_bridge.verify_bridge(bridge, trusted, **kwargs)


def test_a_respelled_bundle_signature_is_not_a_second_verified_bundle():
    """``bundle_digest`` covers ``sig.value``. Two spellings of one signature used to
    give one bundle two identities, both ``verified``."""
    bundle_key = generate_key()
    bundle_jwk = key_to_jwk(bundle_key)
    now = 1_785_000_000
    bundle = {
        "type": "TraceRevocationBundle/1.0",
        "log_id": "https://log.example/trace",
        "issued_at": now - 60,
        "valid_until": now + 3600,
        "statements": [],
        "bundle_key_id": jwk_thumbprint(bundle_jwk),
    }
    value = base64.urlsafe_b64encode(bundle_key.sign(_canonical_bytes(bundle)))
    bundle["sig"] = {"alg": "ed25519", "value": value.rstrip(b"=").decode()}
    kwargs = {
        "trusted_key_identifiers": ["record-key"],
        "trusted_bundle_keys": [bundle_jwk],
        "now": now,
        "max_bundle_age_seconds": 86400,
        "max_future_skew_seconds": 300,
    }
    assert check_bundle(bundle, **kwargs).outcome == "verified"
    for respelled in (_respell_unused_bits(bundle["sig"]["value"]),
                      bundle["sig"]["value"] + "\n"):
        altered = {**bundle, "sig": {"alg": "ed25519", "value": respelled}}
        check = check_bundle(altered, **kwargs)
        assert check.outcome == "unverified_for_revocation", respelled

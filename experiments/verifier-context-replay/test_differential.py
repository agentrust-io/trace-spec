"""Frozen-seed cross-implementation differential and adversarial suite.

All cases use fixed Ed25519 test seed. No external models, network, or
production credentials. Shared dependency: cryptography and rfc8785 primitives;
no shared TRACE verification implementation or helpers.
"""
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from independent_verifier import verify as independent_verify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentrust_trace.sign import verify_record, sign_record, key_to_jwk, jwk_thumbprint
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from test_sign import _minimal_record

SEED = hashlib.sha256(b"TRACE-retained-context-replay-fixture-v1").digest()
TIME = 1750000300

def fixture(nonce=None):
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    record = _minimal_record()
    if nonce is not None:
        record["runtime"]["nonce"] = nonce
    signed = sign_record(record, key)
    return signed, key_to_jwk(key), key

def compare(record, jwk, *, when=TIME, max_age=300, future_skew=10,
            nonce=None, revoked=()):
    options = dict(verification_time=when, max_age_seconds=max_age,
                   max_future_skew_seconds=future_skew, expected_nonce=nonce)
    independent = independent_verify(record, jwk, **options, revoked_identifiers=revoked)
    try:
        verify_record(record, jwk, revocation=set(revoked),
                      now=options["verification_time"],
                      max_age_seconds=options["max_age_seconds"],
                      max_future_skew_seconds=options["max_future_skew_seconds"],
                      expected_nonce=options["expected_nonce"])
        reference = "verified"
    except (ValueError, InvalidSignature) as exc:
        reference = "rejected"
    return reference, independent.status, independent.reason

class DifferentialReplay(unittest.TestCase):
    def assert_agreement(self, expected, record=None, jwk=None, **options):
        if record is None:
            record, jwk, _ = fixture()
        reference, independent, reason = compare(record, jwk, **options)
        actual = "verified" if independent == "verified-crypto" else independent
        self.assertEqual(reference, expected, "reference outcome")
        self.assertEqual(actual, expected, "independent outcome: " + reason)

    def test_valid_at_boundary(self):
        self.assert_agreement("verified")

    def test_one_second_stale(self):
        self.assert_agreement("rejected", when=TIME+1)

    def test_at_future_boundary(self):
        self.assert_agreement("verified", when=1749999990)

    def test_one_second_too_early(self):
        self.assert_agreement("rejected", when=1749999989)

    def test_different_trusted_root(self):
        record, _, _ = fixture()
        other = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"other").digest())
        self.assert_agreement("rejected", record, key_to_jwk(other))

    def test_revoked_thumbprint(self):
        record, jwk, _ = fixture()
        self.assert_agreement("rejected", record, jwk, revoked=(jwk_thumbprint(jwk),))

    def test_revoked_kid(self):
        record, jwk, _ = fixture()
        jwk = {**jwk, "kid": "revoked-key"}
        self.assert_agreement("rejected", record, jwk, revoked=("revoked-key",))

    def test_matching_nonce(self):
        record, jwk, _ = fixture("expected")
        self.assert_agreement("verified", record, jwk, nonce="expected")

    def test_nonce_mismatch(self):
        record, jwk, _ = fixture("other")
        self.assert_agreement("rejected", record, jwk, nonce="expected")

    def test_signature_mutated(self):
        record, jwk, _ = fixture()
        record = copy.deepcopy(record)
        raw = record["signature"]
        record["signature"] = ("A" if raw[0] != "A" else "B") + raw[1:]
        self.assert_agreement("rejected", record, jwk)

    def test_policy_mutation_without_resigning(self):
        record, jwk, _ = fixture()
        record = copy.deepcopy(record)
        record["policy"]["enforcement_mode"] = "monitor"
        self.assert_agreement("rejected", record, jwk)

    def test_profile_mutation(self):
        record, jwk, _ = fixture()
        record = copy.deepcopy(record)
        record["eat_profile"] = "tag:unknown"
        self.assert_agreement("rejected", record, jwk)

    def test_invalid_record_future_time(self):
        self.assert_agreement("rejected", when=1749999900)

    def test_signed_record_with_schema_violation(self):
        record, jwk, key = fixture()
        record = copy.deepcopy(record)
        record["unexpected_extension"] = {"status": "not-authorized"}
        record = sign_record(record, key)
        self.assert_agreement("rejected", record, jwk)

    def test_signed_record_with_bad_uri_format(self):
        record, jwk, key = fixture()
        record = copy.deepcopy(record)
        record["transparency"] = "not a uri"
        record = sign_record(record, key)
        self.assert_agreement("rejected", record, jwk)

    def test_missing_nonce(self):
        record, jwk, _ = fixture()
        self.assert_agreement("rejected", record, jwk, nonce="required")

    def test_disallow_implicit_time(self):
        record, jwk, _ = fixture()
        outcome = independent_verify(record, jwk, verification_time=None, max_age_seconds=300,
                                     max_future_skew_seconds=10)
        self.assertEqual(outcome.status, "not-established")

if __name__ == "__main__":
    unittest.main()

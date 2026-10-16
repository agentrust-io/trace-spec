"""Fail-closed regression tests for the pinned reference-verifier adapter."""
import unittest
from unittest.mock import patch

from trace_reference_adapter import verify_trace_record


class AcceptedVerification:
    pass


class FakeModule:
    VerificationResult = AcceptedVerification
    @staticmethod
    def verify_record(record, keys, *, now, max_age_seconds,
                      max_future_skew_seconds, expected_nonce=None, revocation=None):
        return AcceptedVerification()


class ReturningFalse:
    VerificationResult = AcceptedVerification
    @staticmethod
    def verify_record(record, keys, *, now, max_age_seconds,
                      max_future_skew_seconds, expected_nonce=None, revocation=None):
        return False


class MissingRevocation:
    VerificationResult = AcceptedVerification
    @staticmethod
    def verify_record(record, keys, *, now, max_age_seconds,
                      max_future_skew_seconds, expected_nonce=None):
        return AcceptedVerification()


class ReferenceAdapterSecurity(unittest.TestCase):
    def run_verifier(self, module, **extras):
        with patch("trace_reference_adapter.importlib.import_module", return_value=module):
            return verify_trace_record({}, {}, verification_time=1750000300,
                                       max_age_seconds=300,
                                       max_future_skew_seconds=10, **extras)

    def test_known_success_contract(self):
        self.assertEqual(self.run_verifier(FakeModule).status, "verified")

    def test_false_verdict_never_becomes_success(self):
        self.assertEqual(self.run_verifier(ReturningFalse).status, "not-established")

    def test_revocation_cannot_be_silently_dropped(self):
        self.assertEqual(self.run_verifier(MissingRevocation, revoked_keys=set()).status,
                         "not-established")


if __name__ == "__main__":
    unittest.main()

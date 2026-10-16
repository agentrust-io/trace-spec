"""Verifier-owned root enrollment: positive and adversarial decision tests."""

import tempfile
import unittest
from pathlib import Path

from enrolled_gate import canonical, digest, verify_enrolled


class FailClosedEnrollment(unittest.TestCase):
    def fixture(self, path):
        root = Path(path)
        root.mkdir(parents=True, exist_ok=True)
        # A verifier-owned registry is deliberately separate from producer evidence.
        registry = {
            "format": "frequency-verifier-policy-v1",
            "assurance": "simulation-only",
            "source_commit": "f" * 40,
            "host": "observer",
            "trace_root_digest": "sha256:" + "a" * 64,
            "policy_digest": "sha256:" + "b" * 64,
            "resolver_digest": "sha256:" + "c" * 64,
            "observer_public_digest": "sha256:" + "d" * 64,
            "ak_public_digest": "sha256:" + "e" * 64,
            "reference_pcr0": "0" * 64,
            "allowed_challenge": "nonce-should-be-external",
            "max_observation_age_seconds": 120,
            "not_before_unix": 1000,
            "not_after_unix": 2000,
        }
        p = root / "verifier-owned-policy.json"
        p.write_bytes(canonical(registry))
        return p, registry, digest(p.read_bytes())

    def test_pin_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _, _ = self.fixture(tmp)
            decision = verify_enrolled(
                tmp,
                "sha256:" + "0" * 64,
                registry_path=p,
                registry_pin=None,
                checkquote="/usr/bin/true",
                verification_time=1200,
            )
            self.assertEqual(decision["reason"], "missing-out-of-band-registry-pin")

    def test_modified_registry_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, data, pin = self.fixture(tmp)
            data["source_commit"] = "0" * 40
            p.write_bytes(canonical(data))
            decision = verify_enrolled(
                tmp,
                "sha256:" + "0" * 64,
                registry_path=p,
                registry_pin=pin,
                checkquote="/usr/bin/true",
                verification_time=1200,
            )
            self.assertEqual(decision["reason"], "verifier-registry-pin-mismatch")

    def test_hardware_label_rejected_even_if_registry_rehashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, data, _ = self.fixture(tmp)
            data["assurance"] = "hardware"
            p.write_bytes(canonical(data))
            decision = verify_enrolled(
                tmp,
                "sha256:" + "0" * 64,
                registry_path=p,
                registry_pin=digest(p.read_bytes()),
                checkquote="/usr/bin/true",
                verification_time=1200,
            )
            self.assertEqual(decision["reason"], "hardware-claim-forbidden")

    def test_expired_policy_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _, pin = self.fixture(tmp)
            decision = verify_enrolled(
                tmp,
                "sha256:" + "0" * 64,
                registry_path=p,
                registry_pin=pin,
                checkquote="/usr/bin/true",
                verification_time=2001,
            )
            self.assertEqual(decision["reason"], "policy-outside-validity")

    def test_operational_freshness_rejects_stale_pinned_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _, pin = self.fixture(tmp)
            result = verify_enrolled(
                tmp,
                "sha256:" + "0" * 64,
                registry_path=p,
                registry_pin=pin,
                checkquote="/usr/bin/true",
                verification_time=1200,
                operational_now=1400,
            )
            self.assertEqual(result["reason"], "operational-freshness-expired")

    def test_operational_clock_cannot_precede_historical_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, _, pin = self.fixture(tmp)
            result = verify_enrolled(
                tmp,
                "sha256:" + "0" * 64,
                registry_path=p,
                registry_pin=pin,
                checkquote="/usr/bin/true",
                verification_time=1200,
                operational_now=1199,
            )
            self.assertEqual(result["reason"], "operational-freshness-expired")

    def test_incomplete_enrollment_not_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, data, _ = self.fixture(tmp)
            del data["observer_public_digest"]
            p.write_bytes(canonical(data))
            decision = verify_enrolled(
                tmp,
                "sha256:" + "0" * 64,
                registry_path=p,
                registry_pin=digest(p.read_bytes()),
                checkquote="/usr/bin/true",
                verification_time=1200,
            )
            self.assertEqual(decision["status"], "not-established")


if __name__ == "__main__":
    unittest.main()

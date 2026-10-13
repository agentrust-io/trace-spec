"""Regression and adversarial tests for replay-context checker."""
import copy
import unittest
from replay import evaluate, envelope

BASE = dict(record_digest="sha256:record", issued_at=1000, verification_time=1300,
            max_age_seconds=300, max_future_skew_seconds=10,
            policy_digest="sha256:policy", trust_roots_digest="sha256:roots",
            verifier_identity="reference", verifier_version="pinned",
            resolver_evidence=[{"digest": "sha256:abc", "bytes_digest": "sha256:abc"}])

class ReplayTests(unittest.TestCase):
    def test_boundary(self):
        self.assertEqual(evaluate(BASE)["outcome"], "context-consistent")
        changed = copy.deepcopy(BASE)
        changed["verification_time"] = 1301
        self.assertEqual(evaluate(changed)["reason"], "stale")

    def test_missing(self):
        for key in ("verification_time", "policy_digest", "trust_roots_digest", "resolver_evidence"):
            with self.subTest(key=key):
                changed = copy.deepcopy(BASE)
                del changed[key]
                self.assertEqual(evaluate(changed)["outcome"], "not-established")

    def test_resolver(self):
        changed = copy.deepcopy(BASE)
        changed["resolver_evidence"][0]["bytes_digest"] = "sha256:changed"
        self.assertEqual(evaluate(changed)["reason"], "resolver-digest-mismatch")

    def test_context_binding(self):
        for key in ("policy_digest", "trust_roots_digest", "verifier_version"):
            with self.subTest(key=key):
                changed = copy.deepcopy(BASE)
                changed[key] = "changed"
                self.assertNotEqual(envelope(changed)["context_digest"], envelope(BASE)["context_digest"])

    def test_future(self):
        changed = copy.deepcopy(BASE)
        changed["verification_time"] = 989
        self.assertEqual(evaluate(changed)["reason"], "future")

    def test_no_positive_verification(self):
        self.assertNotEqual(evaluate(BASE)["outcome"], "verified")

    def test_boolean_time_rejected(self):
        changed = copy.deepcopy(BASE)
        changed["verification_time"] = True
        self.assertEqual(evaluate(changed)["reason"], "invalid-time")

    def test_empty_resolver_evidence(self):
        changed = copy.deepcopy(BASE)
        changed["resolver_evidence"] = []
        self.assertEqual(evaluate(changed)["reason"], "resolver-evidence-missing")

if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path
from retained_evidence import freeze, inspect

CONTEXT = {"verification_time": 1750000300, "max_age_seconds": 300,
           "max_future_skew_seconds": 10, "verifier_version": "pinned",
           "expected_nonce": None}

class RetentionTests(unittest.TestCase):
    def write(self, root):
        return freeze(root, record=b"record", root=b"key", policy=b"policy",
                      revocation=b"revocations", resolver=b"resolved-content",
                      context=CONTEXT)

    def test_complete_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp)
            self.assertEqual(inspect(tmp, expected_context=CONTEXT), (True, "integrity-established-only"))

    def test_mutated_artifacts(self):
        for name in ("record", "trusted_root", "policy", "revocation", "resolver"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                self.write(tmp)
                (Path(tmp) / (name + ".bin")).write_bytes(b"tampered")
                self.assertEqual(inspect(tmp)[0], False)

    def test_missing_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp)
            (Path(tmp) / "resolver.bin").unlink()
            self.assertFalse(inspect(tmp)[0])

    def test_context_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp)
            self.assertEqual(inspect(tmp, expected_context={**CONTEXT, "verification_time":1750000301}), (False, "context-drift"))

    def test_missing_context_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                freeze(tmp, record=b"a", root=b"b", policy=b"c", revocation=b"d",
                       resolver=b"e", context={"verification_time":None})

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp)
            with self.assertRaises(FileExistsError):
                self.write(tmp)

    def test_missing_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(inspect(tmp)[0])

if __name__ == "__main__":
    unittest.main()

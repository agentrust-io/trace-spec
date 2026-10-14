"""Bounded process observation tests; no external trust claim."""
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from captured_observer import capture
from observer_receipt import verify


class CapturedObserverTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def test_captured_exit_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, "abc123\n", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 7, b"out", b"err"),
                ]
                receipt = capture(argv=[sys.executable, "-c", "pass"],
                                  allowed_argv=[sys.executable, "-c", "pass"],
                                  repository=directory, expected_commit="abc123",
                                  private_key=self.key, host_label="development-host")
        self.assertEqual(receipt["observation"]["exit_code"], 7)
        self.assertTrue(verify(receipt, self.public))
        receipt["observation"]["exit_code"] = 0
        self.assertFalse(verify(receipt, self.public))

    def test_untracked_source_blocks_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, "abc123\n", ""),
                    subprocess.CompletedProcess([], 0, "?? injected.py\n", ""),
                ]
                with self.assertRaisesRegex(ValueError, "dirty working tree"):
                    capture(argv=[sys.executable, "-c", "pass"],
                            allowed_argv=[sys.executable, "-c", "pass"],
                            repository=directory, expected_commit="abc123",
                            private_key=self.key, host_label="development-host")
                self.assertEqual(run.call_count, 2)

    def test_child_timeout_cannot_yield_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, "abc123\n", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.TimeoutExpired("child", 3),
                ]
                with self.assertRaises(subprocess.TimeoutExpired):
                    capture(argv=[sys.executable, "-c", "pass"],
                            allowed_argv=[sys.executable, "-c", "pass"],
                            repository=directory, expected_commit="abc123",
                            private_key=self.key, host_label="development-host")

    def test_mismatched_commit_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "wrong\n", "")
                with self.assertRaisesRegex(ValueError, "commit mismatch"):
                    capture(argv=[sys.executable, "-c", "pass"],
                            allowed_argv=[sys.executable, "-c", "pass"],
                            repository=directory, expected_commit="abc123",
                            private_key=self.key, host_label="development-host")
                self.assertEqual(run.call_count, 1)

    def test_wrong_executable_rejected_without_running(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                with self.assertRaises(ValueError):
                    capture(argv=[sys.executable], allowed_argv=["/bin/false"],
                            repository=directory, expected_commit="abc123",
                            private_key=self.key, host_label="development-host")
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

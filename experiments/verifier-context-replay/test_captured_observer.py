"""Bounded process observation tests; no external trust claim."""
import subprocess
import hashlib
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
                    subprocess.CompletedProcess([], 0, "", ""),
                ]
                receipt = capture(argv=[sys.executable, "-c", "pass"],
                                  allowed_argv=[sys.executable, "-c", "pass"],
                                  repository=directory, expected_commit="abc123",
                                  private_key=self.key, host_label="development-host")
        self.assertEqual(receipt["observation"]["exit_code"], 7)
        self.assertEqual(
            receipt["observation"]["stdout_sha256"],
            hashlib.sha256(b"out").hexdigest(),
        )
        self.assertEqual(
            receipt["observation"]["stderr_sha256"],
            hashlib.sha256(b"err").hexdigest(),
        )
        self.assertTrue(verify(receipt, self.public))
        receipt["observation"]["exit_code"] = 0
        self.assertFalse(verify(receipt, self.public))

    def test_missing_isolation_tool_refuses_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, "abc123\n", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                ]
                with patch("captured_observer.shutil.which", return_value=None):
                    with self.assertRaisesRegex(RuntimeError, "bubblewrap unavailable"):
                        capture(argv=[sys.executable, "-c", "pass"],
                                allowed_argv=[sys.executable, "-c", "pass"],
                                repository=directory, expected_commit="abc123",
                                private_key=self.key, host_label="development-host",
                                isolate_network=True)
                self.assertEqual(run.call_count, 2)

    def test_failed_isolated_launch_cannot_be_signed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, "abc123\n", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 1, b"", b"bwrap refused"),
                ]
                with patch("captured_observer.shutil.which", return_value="/usr/bin/bwrap"):
                    with self.assertRaisesRegex(RuntimeError, "isolated execution"):
                        capture(argv=[sys.executable, "-c", "pass"],
                                allowed_argv=[sys.executable, "-c", "pass"],
                                repository=directory, expected_commit="abc123",
                                private_key=self.key, host_label="development-host",
                                isolate_network=True)

    def test_isolated_command_never_mounts_host_root(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, "abc123\n", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 0, b"ok", b""),
                    subprocess.CompletedProcess([], 0, "", ""),
                ]
                with patch("captured_observer.shutil.which", return_value="/usr/bin/bwrap"):
                    capture(argv=[sys.executable, "-c", "pass"],
                            allowed_argv=[sys.executable, "-c", "pass"],
                            repository=directory, expected_commit="abc123",
                            private_key=self.key, host_label="development-host",
                            isolate_network=True)
                argv = run.call_args_list[2].args[0]
                self.assertNotIn(["--ro-bind", "/", "/"],
                                 [argv[i:i+3] for i in range(len(argv)-2)])
                self.assertIn(["--ro-bind", directory, directory],
                              [argv[i:i+3] for i in range(len(argv)-2)])

    def test_source_changed_during_execution_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("captured_observer.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, "abc123\n", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 0, b"result", b""),
                    subprocess.CompletedProcess([], 0, " M source.py\n", ""),
                ]
                with self.assertRaisesRegex(ValueError, "source changed"):
                    capture(argv=[sys.executable, "-c", "pass"],
                            allowed_argv=[sys.executable, "-c", "pass"],
                            repository=directory, expected_commit="abc123",
                            private_key=self.key, host_label="development-host")

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

"""Load-bearing end-to-end rootless swtpm + Bubblewrap acceptance suite.

Set TRACE_SWTPM_BINARY, TRACE_SWTPM_TOOL_DIR and TRACE_REPLAY_REPO.
This is an explicit optional hardware-simulation integration test, not a unit mock.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from simulation_gate import create
from replay_bundle import run, sha256


@unittest.skipUnless(
    all(
        os.environ.get(name)
        for name in ("TRACE_SWTPM_BINARY", "TRACE_SWTPM_TOOL_DIR", "TRACE_REPLAY_REPO")
    )
    and shutil.which("bwrap"),
    "rootless swtpm and Bubblewrap live integration is opt-in",
)
class MixedSimulationEndToEnd(unittest.TestCase):
    def test_live_bounded_simulation_then_replay_failures(self):
        with tempfile.TemporaryDirectory(prefix="frequency-mixed-gate-") as tmp:
            directory = Path(tmp) / "bundle"
            tools = Path(os.environ["TRACE_SWTPM_TOOL_DIR"])
            report = create(
                repo=os.environ["TRACE_REPLAY_REPO"],
                tool_dir=tools,
                swtpm=os.environ["TRACE_SWTPM_BINARY"],
                output=directory,
                host_label="live-mixed-test-host",
            )
            self.assertEqual(report["status"], "simulated-evidence-validated")
            manifest = report["manifest_digest"]
            opts = {"tpm2_checkquote": tools / "tpm2_checkquote"}
            verified = run(directory, manifest, **opts)
            self.assertEqual(
                verified["simulation"]["tee"]["status"], "verified-simulation-only"
            )
            self.assertEqual(
                verified["simulation"]["tpm"]["status"], "verified-simulation-only"
            )
            self.assertEqual(verified["status"], "simulated-evidence-validated")
            self.assertEqual(
                run(directory, "sha256:" + "0" * 64, **opts)["reason"],
                "manifest-pin-mismatch",
            )
            self.assertEqual(
                run(directory, manifest)["reason"],
                "tpm2-quote-verifier-not-provisioned",
            )
            quote = directory / "simulation_tpm.bin"
            original = quote.read_bytes()
            quote.write_bytes(b'{"profile":"frequency-swtpm-quote-v1"}')
            self.assertEqual(run(directory, manifest, **opts)["status"], "rejected")
            quote.write_bytes(original)
            tee = directory / "simulation_tee.bin"
            original_tee = tee.read_bytes()
            tee.write_bytes(b'{"profile":"frequency-software-tee-v1"}')
            self.assertEqual(run(directory, manifest, **opts)["status"], "rejected")
            tee.write_bytes(original_tee)
            # Even an attacker who changes the manifest AND supplies its new
            # checksum cannot make two contradictory evidence sources agree.
            file = directory / "MANIFEST.json"
            contents = json.loads(file.read_bytes())
            contents["context"]["simulation_contract"]["tee"][
                "expected_workload_digest"
            ] = "0" * 64
            file.write_bytes(
                json.dumps(contents, sort_keys=True, separators=(",", ":")).encode()
            )
            repinned = "sha256:" + sha256(file.read_bytes()).removeprefix("sha256:")
            self.assertEqual(
                run(directory, repinned, **opts)["reason"],
                "tpm-tee-measurement-closure-disagreement",
            )


if __name__ == "__main__":
    unittest.main()

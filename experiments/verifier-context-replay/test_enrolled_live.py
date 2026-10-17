"""Live verifier-owned enrollment gate and adversarial tests.

Test-only enrollment explicitly derives public evidence selectors after capture.
It demonstrates mechanism, NOT independent external source authorization.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from enrolled_gate import canonical, digest, verify_enrolled
from simulation_gate import create


@unittest.skipUnless(
    all(
        os.environ.get(k)
        for k in ("TRACE_SWTPM_BINARY", "TRACE_SWTPM_TOOL_DIR", "TRACE_REPLAY_REPO")
    )
    and shutil.which("bwrap"),
    "requires live user-space TPM2 simulator and Bubblewrap",
)
class LiveVerifierEnrollment(unittest.TestCase):
    def test_live_separately_pinned_registry(self):
        with tempfile.TemporaryDirectory(prefix="frequency-verifier-policy-") as temp:
            root = Path(temp)
            bundle = root / "producer-bundle"
            evidence = create(
                repo=os.environ["TRACE_REPLAY_REPO"],
                tool_dir=os.environ["TRACE_SWTPM_TOOL_DIR"],
                swtpm=os.environ["TRACE_SWTPM_BINARY"],
                output=bundle,
                host_label="software-enrollment-test",
            )
            self.assertEqual(evidence["status"], "simulated-evidence-validated")
            manifest = json.loads((bundle / "MANIFEST.json").read_bytes())
            context = manifest["context"]
            tee = context["simulation_contract"]["tee"]
            tpm = context["simulation_contract"]["tpm"]
            # Fixture configuration lives OUTSIDE evidence root; a real policy
            # must be independently authorized and enrolled before acceptance.
            policy = {
                "format": "frequency-verifier-policy-v1",
                "assurance": "simulation-only",
                "source_commit": tee["expected_commit"],
                "host": tee["expected_host"],
                "trace_root_digest": digest((bundle / "trusted_root.bin").read_bytes()),
                "policy_digest": digest((bundle / "policy.bin").read_bytes()),
                "resolver_digest": digest((bundle / "resolver.bin").read_bytes()),
                "observer_public_digest": "sha256:" + tee["trusted_observer_digest"],
                "ak_public_digest": "sha256:" + tpm["expected_ak_digest"],
                "reference_pcr0": tpm["expected_pcr0"],
                "allowed_challenge": tee["expected_challenge"],
                "max_observation_age_seconds": 120,
                "not_before_unix": tee["verification_time"] - 1,
                "not_after_unix": tee["verification_time"] + 120,
            }
            # Linux memfd keeps test policy inputs out of persistent storage.
            # The live simulator test is Linux-only (Bubblewrap).
            fd = os.memfd_create("trace-verifier-policy", flags=0)
            self.addCleanup(os.close, fd)
            registry = Path(f"/proc/self/fd/{fd}")
            os.write(fd, canonical(policy))
            pinned_policy = digest(registry.read_bytes())
            options = {
                "registry_path": registry,
                "registry_pin": pinned_policy,
                "checkquote": Path(os.environ["TRACE_SWTPM_TOOL_DIR"])
                / "tpm2_checkquote",
                "verification_time": tee["verification_time"],
            }
            answer = verify_enrolled(bundle, evidence["manifest_digest"], **options)
            self.assertEqual(answer["status"], "simulation-enrolled-verified", answer)
            self.assertEqual(
                verify_enrolled(
                    bundle,
                    evidence["manifest_digest"],
                    **{**options, "registry_pin": None},
                )["status"],
                "not-established",
            )
            self.assertEqual(
                verify_enrolled(
                    bundle,
                    evidence["manifest_digest"],
                    **{**options, "operational_now": tee["verification_time"] + 121},
                )["reason"],
                "operational-freshness-expired",
            )
            policy["observer_public_digest"] = "sha256:" + "0" * 64
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, canonical(policy))
            self.assertEqual(
                verify_enrolled(
                    bundle,
                    evidence["manifest_digest"],
                    **{**options, "registry_pin": digest(registry.read_bytes())},
                )["reason"],
                "unauthorized-verifier-input:observer_public_digest",
            )


if __name__ == "__main__":
    unittest.main()

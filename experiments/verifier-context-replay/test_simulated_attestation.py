"""Adversarial software-only TPM/TEE evidence and process isolation tests."""
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from simulated_tpm import capture as tpm_capture, verify as tpm_verify, sha, expected_pcr
from simulated_tee import capture_software_tee, verify_software_tee
from observer_receipt import issue

class SoftwareEvidenceTests(unittest.TestCase):
    def test_pcr_replay_calculation(self):
        d="ab"*32
        self.assertEqual(expected_pcr([d]),hashlib.sha256(bytes(32)+bytes.fromhex(d)).hexdigest())
    def test_invalid_event_digest(self):
        with self.assertRaises(ValueError):
            expected_pcr(["invalid"])
    def test_tpm_profile_must_be_simulation(self):
        self.assertEqual(tpm_verify({"classification":"HARDWARE_TPM"},expected_manifest_digest="",
                                    expected_ak_digest="",expected_nonce="",expected_pcr0="",
                                    tpm2_checkquote="/usr/bin/true")["status"],"rejected")

class TeeReplayTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"software-tee-test-key").digest())
        self.pub=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.challenge="tpm-tee-test-challenge-2026"
        self.observed={"command":["/usr/bin/true"],"commit":"test-commit",
            "executable_sha256":"a"*64,"host":"observer",
            "network_isolation_requested":True,"exit_code":0,"summary":"captured simulated execution",
            "stdout_sha256":"b"*64,"stderr_sha256":"c"*64,
            "challenge":self.challenge,"observed_at_unix":1000}
        self.bundle={"profile":"frequency-software-tee-v1",
                     "classification":"SIMULATED_TEE_NO_HARDWARE_ROOT",
                     "receipt":issue(self.observed,self.key)}
    def check(self,bundle=None,**overrides):
        options=dict(trusted_observer_public=self.pub,
                     trusted_observer_digest=sha(self.pub),
                     expected_commit="test-commit",expected_executable_digest="a"*64,
                     expected_host="observer",expected_command=["/usr/bin/true"],
                     expected_challenge=self.challenge,
                     expected_stdout_digest="b"*64,expected_stderr_digest="c"*64,
                     verification_time=1001,
                     max_age_seconds=300)
        options.update(overrides)
        return verify_software_tee(bundle or self.bundle,**options)
    def test_observed_isolation_accepts_simulated_only(self):
        self.assertEqual(self.check()["status"],"verified-simulation-only")
    def test_wrong_observer_root(self):
        self.assertEqual(self.check(trusted_observer_digest="f"*64)["status"],"rejected")
    def test_nonce_substitution(self):
        self.assertEqual(self.check(expected_challenge="different-challenge-123")["reason"],"challenge-mismatch")
    def test_expired_observation(self):
        self.assertEqual(self.check(verification_time=1401)["reason"],"stale-or-future-observation")
    def test_future_observation(self):
        self.assertEqual(self.check(verification_time=999)["reason"],"stale-or-future-observation")
    def test_runtime_identity_substitution(self):
        self.assertEqual(self.check(expected_executable_digest="z"*64)["reason"],"execution-context-mismatch")
    def test_hardware_label_is_not_accepted(self):
        b=copy.deepcopy(self.bundle);b["classification"]="GENUINE_TEE"
        self.assertEqual(self.check(b)["status"],"rejected")
    def test_wrong_expected_output(self):
        self.assertEqual(self.check(expected_stdout_digest="0"*64)["reason"],
                         "execution-output-digest-mismatch")

    def test_receipt_tamper(self):
        b=copy.deepcopy(self.bundle);b["receipt"]["observation"]["exit_code"]=1
        self.assertEqual(self.check(b)["reason"],"invalid-observer-signature")

@unittest.skipUnless(os.environ.get("TRACE_SWTPM_TOOL_DIR") and os.environ.get("TRACE_SWTPM_TCTI"),
                     "real swtpm + tpm2-tools integration requires explicit lab environment")
class LiveSwtpmQuoteTests(unittest.TestCase):
    def test_quote_challenge_and_pcr_adversarial(self):
        tools=Path(os.environ["TRACE_SWTPM_TOOL_DIR"])
        tcti=os.environ["TRACE_SWTPM_TCTI"]
        nonce="2345aabbccdd56789900ab12"
        event="ab"*32
        with tempfile.TemporaryDirectory(prefix="frequency-swtpm-") as tmp:
            b=tpm_capture(tool_dir=tools,tcti=tcti,event_digests=[event],
                          nonce_hex=nonce,directory=tmp)
            digest=sha(json.dumps(b,sort_keys=True,separators=(",",":")).encode())
            root_digest=sha(b["ak_pem"].encode())
            def check(bundle=b,**overrides):
                args=dict(expected_manifest_digest=digest,expected_ak_digest=root_digest,
                          expected_nonce=nonce,expected_pcr0=expected_pcr([event]),
                          tpm2_checkquote=tools/"tpm2_checkquote")
                args.update(overrides)
                return tpm_verify(bundle,**args)
            self.assertEqual(check()["status"],"verified-simulation-only")
            self.assertEqual(check(expected_nonce="8765432100abcdef")["status"],"rejected")
            self.assertEqual(check(expected_ak_digest="0"*64)["status"],"rejected")
            self.assertEqual(check(expected_pcr0="0"*64)["status"],"rejected")
            self.assertEqual(check(expected_manifest_digest="0"*64)["status"],"not-established")
            wrong=copy.deepcopy(b)
            wrong["quote_sig_b64"]=base64.b64encode(bytes([0])*256).decode()
            updated=sha(json.dumps(wrong,sort_keys=True,separators=(",",":")).encode())
            self.assertEqual(check(wrong,expected_manifest_digest=updated)["status"],"rejected")

if __name__=="__main__":
    unittest.main()


@unittest.skipUnless(os.environ.get("TRACE_REPLAY_REPO") and shutil.which("bwrap"),
                     "live Bubblewrap integration needs explicit repository and isolation runtime")
class LiveSoftwareTeeTests(unittest.TestCase):
    def test_actual_isolated_process_signed_and_replayed(self):
        import time
        import uuid
        repo=Path(os.environ["TRACE_REPLAY_REPO"]).resolve()
        commit=subprocess.check_output(["git","-C",str(repo),"rev-parse","HEAD"],text=True).strip()
        key=Ed25519PrivateKey.generate()
        public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        challenge=uuid.uuid4().hex
        executable=Path("/usr/bin/true")
        b=capture_software_tee(argv=[str(executable)],repository=repo,
                               expected_commit=commit,signing_key=key,
                               host_label="software-tee-test",challenge=challenge)
        opts=dict(trusted_observer_public=public,trusted_observer_digest=sha(public),
                  expected_commit=commit,
                  expected_executable_digest=sha(executable.read_bytes()),
                  expected_host="software-tee-test",expected_command=[str(executable)],
                  expected_challenge=challenge,expected_stdout_digest=sha(b""),
                  expected_stderr_digest=sha(b""),verification_time=int(time.time()),
                  max_age_seconds=60)
        self.assertEqual(verify_software_tee(b,**opts)["status"],"verified-simulation-only")
        self.assertEqual(verify_software_tee(b,**{**opts,"expected_challenge":"substituted-nonce-test"})["status"],"rejected")
        self.assertEqual(verify_software_tee(b,**{**opts,"verification_time":opts["verification_time"]+61})["status"],"rejected")

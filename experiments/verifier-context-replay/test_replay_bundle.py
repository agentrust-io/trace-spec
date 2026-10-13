"""Real frozen-bundle replay, not merely parallel fixtures."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from agentrust_trace.sign import sign_record, key_to_jwk
from retained_evidence import freeze
from replay_bundle import run, sha256
from test_differential import _minimal_record, SEED
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY = Ed25519PrivateKey.from_private_bytes(SEED)
POLICY = b'{"policy_version":1,"enforcement_mode":"enforce"}'
RESOLVER = b'{"manifest":"pinned-response"}'
CONTEXT = {"verification_time":1750000300,"max_age_seconds":300,
           "max_future_skew_seconds":10,"expected_nonce":None,
           "verifier_version":"pinned-test"}

def build(path, policy=POLICY, trusted_key=None, revoked=None, when=1750000300, semantic_contract=None):
    record = _minimal_record()
    record["policy"]["bundle_hash"] = sha256(POLICY)
    signed = sign_record(record, KEY)
    freeze(path,
           record=json.dumps(signed,sort_keys=True,separators=(",",":")).encode(),
           root=json.dumps(trusted_key or key_to_jwk(KEY),sort_keys=True).encode(),
           policy=policy,
           revocation=json.dumps(revoked if revoked is not None else []).encode(),
           resolver=RESOLVER,
           context={**CONTEXT,"verification_time":when, **({"semantic_contract":semantic_contract} if semantic_contract is not None else {})})
    return sha256((Path(path)/"MANIFEST.json").read_bytes())

class BundleReplayTests(unittest.TestCase):
    def test_pinned_valid(self):
        with tempfile.TemporaryDirectory() as path:
            pin=build(path)
            v=run(path,pin)
            self.assertEqual(v["status"],"crypto-and-context-verified")

    def test_no_external_pin(self):
        with tempfile.TemporaryDirectory() as path:
            build(path)
            self.assertEqual(run(path,None)["reason"],"missing-external-manifest-pin")

    def test_changed_manifest(self):
        with tempfile.TemporaryDirectory() as path:
            pin=build(path)
            p=Path(path)/"MANIFEST.json"
            p.write_bytes(p.read_bytes()+b" ")
            self.assertEqual(run(path,pin)["reason"],"manifest-pin-mismatch")

    def test_unbound_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            pin=build(path,policy=b'{"not":"signed-policy"}')
            self.assertEqual(run(path,pin)["reason"],"signed-policy-digest-mismatch")

    def test_revoked_key(self):
        from agentrust_trace.sign import jwk_thumbprint
        with tempfile.TemporaryDirectory() as path:
            pin=build(path,revoked=[jwk_thumbprint(key_to_jwk(KEY))])
            self.assertEqual(run(path,pin)["status"],"rejected")

    def test_stale_time(self):
        with tempfile.TemporaryDirectory() as path:
            pin=build(path,when=1750000301)
            self.assertEqual(run(path,pin)["status"],"rejected")

    def test_resolver_mutation(self):
        with tempfile.TemporaryDirectory() as path:
            pin=build(path)
            (Path(path)/"resolver.bin").write_bytes(b"changed")
            self.assertEqual(run(path,pin)["status"],"rejected")

    def test_policy_mutation(self):
        with tempfile.TemporaryDirectory() as path:
            pin=build(path)
            (Path(path)/"policy.bin").write_bytes(b"changed")
            self.assertEqual(run(path,pin)["status"],"rejected")

    def test_semantic_snapshots_match(self):
        with tempfile.TemporaryDirectory() as path:
            contract={"version":1,"enforcement_mode":"enforce",
                      "policy":json.loads(POLICY),"resolver":json.loads(RESOLVER)}
            pin=build(path,semantic_contract=contract)
            output=run(path,pin)
            self.assertEqual(output["status"],"crypto-and-context-verified")
            self.assertEqual(output["semantic_status"],"exact-snapshot-matched")

    def test_semantic_resolver_drift(self):
        with tempfile.TemporaryDirectory() as path:
            contract={"version":1,"enforcement_mode":"enforce",
                      "policy":json.loads(POLICY),"resolver":{"manifest":"different"}}
            pin=build(path,semantic_contract=contract)
            self.assertEqual(run(path,pin)["reason"],"resolver-semantic-drift")

    def test_semantic_policy_drift(self):
        with tempfile.TemporaryDirectory() as path:
            contract={"version":1,"enforcement_mode":"enforce",
                      "policy":{"enforcement_mode":"monitor"},"resolver":json.loads(RESOLVER)}
            pin=build(path,semantic_contract=contract)
            self.assertEqual(run(path,pin)["reason"],"policy-semantic-drift")

    def test_semantic_non_enforcing(self):
        with tempfile.TemporaryDirectory() as path:
            contract={"version":1,"enforcement_mode":"monitor",
                      "policy":json.loads(POLICY),"resolver":json.loads(RESOLVER)}
            pin=build(path,semantic_contract=contract)
            self.assertEqual(run(path,pin)["reason"],"enforcement-mode-mismatch")

    def test_semantic_contract_incomplete(self):
        with tempfile.TemporaryDirectory() as path:
            pin=build(path,semantic_contract={"version":1})
            self.assertEqual(run(path,pin)["reason"],"incomplete-semantic-contract")

    def test_absent_root(self):
        with tempfile.TemporaryDirectory() as path:
            pin=build(path)
            (Path(path)/"trusted_root.bin").unlink()
            self.assertEqual(run(path,pin)["status"],"rejected")

if __name__=="__main__":
    unittest.main()

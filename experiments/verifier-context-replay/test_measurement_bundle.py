"""End-to-end measurement replay from retained signed evidence; no external network."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
import rfc8785

from agentrust_trace.sign import sign_record, key_to_jwk
from test_differential import _minimal_record, SEED
from test_measurement_appraisal import MeasurementReplayTests, signed, public
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from measurement_appraisal import digest
from retained_evidence import freeze
from replay_bundle import run, sha256

TRACE_KEY=Ed25519PrivateKey.from_private_bytes(SEED)
POLICY=b'{"policy_version":1,"enforcement_mode":"enforce"}'
CONTEXT={"verification_time":1750000300,"max_age_seconds":300,
         "max_future_skew_seconds":10,"expected_nonce":None}

class MeasurementBundleAcceptance(unittest.TestCase):
    def setUp(self):
        self.evidence=MeasurementReplayTests()
        self.evidence.setUp()
    def build(self, directory, *, required=("pcr:0",), changed_reference=None,
              change_pin=False, omit_evidence=False, preexecution=False):
        ev=self.evidence
        record=_minimal_record()
        record["policy"]["bundle_hash"]=sha256(POLICY)
        record["runtime"]["measurement"]=ev.record["runtime"]["measurement"]
        signed_record=sign_record(record,TRACE_KEY)
        policy={**ev.policy,"required_layers":list(required),
                "require_preexecution_appraisal":preexecution}
        reference=changed_reference or ev.reference
        contract={"policy":policy,"reference_public_key_hex":public(ev.source).hex(),
                  "quote_public_key_hex":public(ev.attestor).hex(),
                  "reference_digest":digest(rfc8785.dumps(ev.reference if change_pin else reference))}
        kwargs={"record":json.dumps(signed_record,sort_keys=True).encode(),
                "root":json.dumps(key_to_jwk(TRACE_KEY)).encode(),
                "policy":POLICY, "revocation":b"[]", "resolver":b'{"source":"frozen"}',
                "context":{**CONTEXT,"measurement_contract":contract}}
        if not omit_evidence:
            kwargs.update(measurement_reference=json.dumps(reference).encode(),
                          measurement_quote=json.dumps(ev.quote).encode())
        freeze(directory,**kwargs)
        return sha256((Path(directory)/"MANIFEST.json").read_bytes())
    def test_retained_reference_success(self):
        with tempfile.TemporaryDirectory() as directory:
            pin=self.build(directory)
            result=run(directory,pin)
            self.assertEqual(result["status"],"crypto-and-context-verified")
            self.assertEqual(result["measurement_appraisal"]["status"],"affirming")
    def test_same_record_new_required_layer_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            pin=self.build(directory,required=("pcr:0","pcr:2"))
            result=run(directory,pin)
            self.assertEqual(result["status"],"not-established")
            self.assertEqual(result["measurement_appraisal"]["layers"]["pcr:2"]["reason"],"layer-not-measured")
    def test_required_preexecution_appraisal_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            pin=self.build(directory,preexecution=True)
            self.assertEqual(run(directory,pin)["status"],"not-established")
    def test_reference_mutated_but_old_pin(self):
        ev=self.evidence
        reference=copy.deepcopy(ev.reference)
        reference["payload"]["version"]="changed"
        with tempfile.TemporaryDirectory() as directory:
            pin=self.build(directory,changed_reference=reference,change_pin=True)
            self.assertEqual(run(directory,pin)["reason"],"measurement-appraisal-reference-evidence-changed")
    def test_missing_measurement_bytes_refused_at_freeze(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.build(directory,omit_evidence=True)
    def test_retained_reference_tampered(self):
        with tempfile.TemporaryDirectory() as directory:
            pin=self.build(directory)
            (Path(directory)/"measurement_reference.bin").write_bytes(b"{}")
            self.assertEqual(run(directory,pin)["status"],"rejected")
    def test_retained_quote_tampered(self):
        with tempfile.TemporaryDirectory() as directory:
            pin=self.build(directory)
            (Path(directory)/"measurement_quote.bin").write_bytes(b"{}")
            self.assertEqual(run(directory,pin)["status"],"rejected")

if __name__=="__main__":
    unittest.main()

"""Adversarial retained-context cases for upstream #524 reference-value route."""
import base64
import copy
import hashlib
import unittest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from measurement_appraisal import appraise, digest

def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def signed(payload, key):
    signature=key.sign(rfc8785.dumps(payload))
    return {"payload":payload,"signature":base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}

class MeasurementReplayTests(unittest.TestCase):
    def setUp(self):
        self.source=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"source-v1").digest())
        self.attestor=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"quote-v1").digest())
        self.record={"runtime":{"measurement":"sha256:"+("a"*64)}}
        self.reference=signed({"source_id":"signed-release-reference","version":"rc14",
            "layers":{"pcr:0":{"value":"sha256:boot"},"pcr:2":{"value":"sha256:separator"}}},self.source)
        self.quote=signed({"measurement":self.record["runtime"]["measurement"],
            "layers":{"pcr:0":{"value":"sha256:boot","holds_measurements":True,
                     "event_log_present":False,"preexecution_appraised":False},
                      "pcr:2":{"value":"sha256:separator","holds_measurements":False,
                     "event_log_present":False,"preexecution_appraised":False}}},self.attestor)
        self.policy={"policy_id":"policy-pcr0","required_layers":["pcr:0"],
                     "trusted_reference_key_digest":digest(public(self.source)),
                     "trusted_quote_key_digest":digest(public(self.attestor)),
                     "require_preexecution_appraisal":False}
    def check(self,**updates):
        args={"record":self.record,"reference":self.reference,"quote":self.quote,
              "policy":self.policy,"reference_public_key":public(self.source),
              "quote_public_key":public(self.attestor),
              "expected_reference_digest":digest(rfc8785.dumps(self.reference))}
        args.update(updates)
        return appraise(**args)
    def test_signed_reference_affirms_required_measured_layer(self):
        v=self.check()
        self.assertEqual(v["status"],"affirming")
        self.assertEqual(v["layers"]["pcr:0"]["route"],"trusted-reference")
    def test_identical_record_but_different_required_layers(self):
        policy={**self.policy,"policy_id":"require-both","required_layers":["pcr:0","pcr:2"]}
        v=self.check(policy=policy)
        self.assertEqual(v["status"],"not-established")
        self.assertEqual(v["layers"]["pcr:2"]["reason"],"layer-not-measured")
    def test_missing_policy_is_not_established(self):
        self.assertEqual(self.check(policy=None)["status"],"not-established")
    def test_substituted_trust_root(self):
        fake=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"substitute").digest())
        self.assertEqual(self.check(reference_public_key=public(fake))["status"],"rejected")
    def test_reference_changed_with_old_pin(self):
        mutated=copy.deepcopy(self.reference);mutated["payload"]["version"]="different"
        self.assertEqual(self.check(reference=mutated)["reason"],"reference-evidence-changed")
    def test_reference_signed_by_untrusted_source(self):
        other=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"other").digest())
        reference=signed(self.reference["payload"],other)
        v=self.check(reference=reference,expected_reference_digest=digest(rfc8785.dumps(reference)))
        self.assertEqual(v["status"],"rejected")
    def test_quote_signature_changed(self):
        mutated=copy.deepcopy(self.quote);mutated["payload"]["layers"]["pcr:0"]["value"]="fake"
        self.assertEqual(self.check(quote=mutated)["status"],"rejected")
    def test_conflicting_event_log_precedes_matching_reference(self):
        changed=copy.deepcopy(self.quote["payload"])
        changed["layers"]["pcr:0"]["event_log_present"]=True
        changed["layers"]["pcr:0"]["event_log_replays"]=False
        v=self.check(quote=signed(changed,self.attestor))
        self.assertEqual(v["layers"]["pcr:0"]["reason"],"evidence-spans-multiple-boots")
    def test_preexecution_appraisal_required(self):
        policy={**self.policy,"require_preexecution_appraisal":True}
        v=self.check(policy=policy)
        self.assertEqual(v["layers"]["pcr:0"]["reason"],"measured-not-appraised")
    def test_measurement_mismatch(self):
        record={"runtime":{"measurement":"sha256:"+("b"*64)}}
        self.assertEqual(self.check(record=record)["reason"],"quote-record-measurement-mismatch")
    def test_reference_value_mismatch(self):
        payload=copy.deepcopy(self.reference["payload"])
        payload["layers"]["pcr:0"]["value"]="different"
        ref=signed(payload,self.source)
        v=self.check(reference=ref,expected_reference_digest=digest(rfc8785.dumps(ref)))
        self.assertEqual(v["layers"]["pcr:0"]["reason"],"reference-value-mismatch")
    def test_missing_external_pin(self):
        self.assertEqual(self.check(expected_reference_digest=None)["status"],"not-established")
    def test_missing_required_layer(self):
        policy={**self.policy,"required_layers":["pcr:9"]}
        self.assertEqual(self.check(policy=policy)["layers"]["pcr:9"]["reason"],"missing-layer-evidence")

if __name__=="__main__":
    unittest.main()

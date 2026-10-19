import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from observer_receipt import issue, verify

class ObserverReceiptTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public=self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.observation={"commit":"pinned","host":"observer-vps","command":"pytest -q",
                          "exit_code":0,"summary":"tests passed"}

    def test_authentic_receipt(self):
        self.assertTrue(verify(issue(self.observation,self.key),self.public))

    def test_observation_mutations(self):
        for name,value in (("commit","substituted"),("host","other"),
                           ("command","different"),("exit_code",1),("summary","fabricated")):
            with self.subTest(name=name):
                receipt=issue(self.observation,self.key)
                receipt["observation"][name]=value
                self.assertFalse(verify(receipt,self.public))

    def test_signer_substitution(self):
        other=Ed25519PrivateKey.from_private_bytes(bytes(range(1,33)))
        self.assertFalse(verify(issue(self.observation,other),self.public))

    def test_missing_required_field(self):
        incomplete=copy.deepcopy(self.observation)
        del incomplete["command"]
        with self.assertRaises(ValueError):
            issue(incomplete,self.key)

    def test_boolean_exit_code(self):
        wrong=copy.deepcopy(self.observation)
        wrong["exit_code"]=False
        with self.assertRaises(ValueError):
            issue(wrong,self.key)

if __name__=="__main__":
    unittest.main()

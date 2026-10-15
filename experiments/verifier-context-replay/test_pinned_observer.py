import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from observer_receipt import issue
from pinned_observer import verify_pinned


def test_pinned_receipt_and_negative_cases():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    obs = {"commit": "abc", "host": "vps", "command": ["/bin/true"],
           "exit_code": 0, "summary": "test", "network_isolation_requested": True}
    with TemporaryDirectory() as directory:
        p = Path(directory) / "trusted.raw"
        p.write_bytes(pub)
        fp = hashlib.sha256(pub).hexdigest()
        def check(receipt):
            return verify_pinned(receipt, p, fp, "abc", "vps")
        assert check(issue(obs, key))
        assert not check(issue({**obs, "commit": "substituted"}, key))
        assert not check(issue({**obs, "host": "forged"}, key))
        assert not check(issue({**obs, "network_isolation_requested": False}, key))
        malformed = issue(dict(obs), key)
        malformed["observation"]["exit_code"] = True
        assert not check(malformed)
        assert not check(issue(obs, Ed25519PrivateKey.generate()))
        p.write_bytes(bytes(32))
        assert not check(issue(obs, key))

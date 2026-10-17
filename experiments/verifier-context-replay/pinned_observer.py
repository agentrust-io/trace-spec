"""Verify development receipts using a separately provisioned public-key pin.

A matching key proves key continuity, not a host's real-world identity.
"""
from hashlib import sha256
from pathlib import Path

from observer_receipt import verify


def verify_pinned(receipt, key_path, fingerprint, commit, host):
    try:
        path = Path(key_path)
        if path.is_symlink():
            return False
        key = path.read_bytes()
        observation = receipt["observation"]
        if not isinstance(observation, dict):
            return False
        return (
            len(key) == 32
            and sha256(key).hexdigest() == fingerprint
            and observation.get("commit") == commit
            and observation.get("host") == host
            and observation.get("network_isolation_requested") is True
            and type(observation.get("exit_code")) is int
            and verify(receipt, key)
        )
    except (OSError, TypeError, KeyError, AttributeError, ValueError):
        return False

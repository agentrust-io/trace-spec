"""Sign a separate-host test observation; this is NOT third-party certification.

The signing key MUST be an externally provisioned Ed25519 key controlled by
an observer. An ephemeral key is permitted only for development experiments.
The verifier must pin the observer's public key out of band.
"""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def issue(observation, private_key):
    if not isinstance(observation, dict):
        raise ValueError("observation must be an object")
    if any(key not in observation for key in ("commit", "host", "command", "exit_code", "summary")):
        raise ValueError("incomplete observation")
    if type(observation["exit_code"]) is not int:
        raise ValueError("exit_code must be an integer")
    return {"format":"trace-observer-receipt-v1",
            "observation":observation,
            "signature":base64.urlsafe_b64encode(private_key.sign(canonical(observation))).rstrip(b"=").decode()}

def verify(receipt, pinned_public_key):
    try:
        if receipt["format"] != "trace-observer-receipt-v1":
            return False
        raw=receipt["signature"]
        if not isinstance(raw,str):
            return False
        signature=base64.urlsafe_b64decode(raw+"="*(-len(raw)%4))
        if len(signature)!=64:
            return False
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(signature,canonical(receipt["observation"]))
        return True
    except (ValueError,TypeError,KeyError,AttributeError):
        return False
    except Exception:
        return False

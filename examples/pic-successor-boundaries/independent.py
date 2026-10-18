"""A deliberately bounded independent checker of these twelve published vectors.

Not a general PIC or TRACE verifier. No agentrust_trace imports; schema validation,
canonicalization and Ed25519 primitives are reused, not the reference control flow.
"""

from __future__ import annotations
import base64
import hashlib
import json
import re
from pathlib import Path
import jsonschema
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]


def signature(artifact, jwk):
    body = {k: v for k, v in artifact.items() if k != "signature"}

    def decode(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    Ed25519PublicKey.from_public_bytes(decode(jwk["x"])).verify(
        decode(artifact["signature"]), rfc8785.dumps(body)
    )


def digest(obj):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def require(condition):
    if not condition:
        raise ValueError("bounded vector condition is not met")


def check(data):
    result = {"authorization_bound": False, "successor_bound": None, "outcome": None}
    auth = data["bridge"]["authorization"]
    try:
        schema = json.loads((ROOT / "schema/pic-trace-bridge-v1.json").read_text(encoding="utf-8"))
        jsonschema.validate(data["bridge"], schema)
        signature(data["bridge"], data["authorizer_jwk"])
        require(auth["decision"] == "allow")
        require(auth["authorized_at"] <= 160 < auth["expires_at"])
        require(auth["declaration_digest"] == digest(data["declaration"]))
        require(auth["tool_call_digest"] == digest(data["tool_call"]))
        require(data["tool_call"]["name"] in auth["scope"]["tools"])
        require(data["declaration"]["impact"] in auth["scope"]["impacts"])
        require(data["transcript"] == {"before": {"tool_call": data["tool_call"]}})
        for field in ["intent_digest", "args_digest"]:
            supplied = data["pic_" + field]
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", supplied))
            require(supplied == auth["pic"][field])
    except (ValueError, AssertionError, InvalidSignature, jsonschema.ValidationError):
        return result
    result["authorization_bound"] = True
    result["successor_bound"] = False
    after, artifact = data["after"], data["successor"]
    try:
        schema = json.loads(
            (ROOT / "schema/pic-trace-successor-v1.json").read_text(encoding="utf-8")
        )
        jsonschema.validate(artifact, schema)
        signature(artifact, data["observer_jwk"])
        require(artifact["observer_key_id"] == data["observer_jwk"]["kid"])
        require(artifact["authorization_id"] == auth["authorization_id"])
        require(artifact["observer"] == "observer-1")
        require(set(after) == {"observation", "observer", "observed_at"})
        require(isinstance(after["observation"], dict))
        require(artifact["observer"] == after["observer"])
        require(artifact["observed_at"] == after["observed_at"])
        require(artifact["successor_observation_digest"] == digest(after))
    except (ValueError, AssertionError, InvalidSignature, jsonschema.ValidationError):
        return result
    result["successor_bound"] = True
    value = after["observation"].get("reachable")
    if not (130 <= after["observed_at"] <= 160):
        result["outcome"] = "not-established"
    else:
        result["outcome"] = (
            "established"
            if value is True
            else "contradicted"
            if value is False
            else "not-established"
        )
    return result

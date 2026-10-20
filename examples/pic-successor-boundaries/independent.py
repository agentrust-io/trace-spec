"""A deliberately bounded independent checker of these published vectors.

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


def require(condition, reason="outside-bounded-profile"):
    if not condition:
        raise ValueError(reason)


def validate_case(case):
    schema = json.loads((Path(__file__).parent / "case-v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(case)


def check(data, context):
    result = {
        "authorization_bound": False,
        "successor_bound": None,
        "outcome": None,
        "reason": None,
    }
    auth = data["bridge"]["authorization"]
    try:
        schema = json.loads((ROOT / "schema/pic-trace-bridge-v1.json").read_text(encoding="utf-8"))
        # Classify the digest representation before general schema rejection.
        for field in ["intent_digest", "args_digest"]:
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", auth["pic"][field]), "pic-digest-syntax")
        jsonschema.validate(data["bridge"], schema)
        # A valid signature under the trusted key is not enough: the signed key ID
        # must also name that verifier-configured key.
        require(
            auth["authorizer_key_id"] == data["authorizer_jwk"].get("kid"),
            "authorizer-key-mismatch",
        )
        signature(data["bridge"], data["authorizer_jwk"])
        require(auth["decision"] == "allow")
        require(auth["authorized_at"] <= context["now"] < auth["expires_at"])
        require(auth["declaration_digest"] == digest(data["declaration"]))
        require(auth["tool_call_digest"] == digest(data["tool_call"]))
        require(data["tool_call"]["name"] in auth["scope"]["tools"])
        require(data["declaration"]["impact"] in auth["scope"]["impacts"])
        require(data["transcript"] == {"before": {"tool_call": data["tool_call"]}})
        for field in ["intent_digest", "args_digest"]:
            supplied = data["pic_" + field]
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", supplied), "pic-digest-syntax")
            require(supplied == auth["pic"][field])
    except (ValueError, InvalidSignature, jsonschema.ValidationError) as exc:
        result["reason"] = str(exc)
        return result
    result["authorization_bound"] = True
    result["successor_bound"] = False
    after, artifact = data["after"], data["successor"]
    try:
        schema = json.loads(
            (ROOT / "schema/pic-trace-successor-v1.json").read_text(encoding="utf-8")
        )
        jsonschema.validate(artifact, schema)
        try:
            signature(artifact, data["observer_jwk"])
        except InvalidSignature:
            raise ValueError("successor-signature-invalid") from None
        require(artifact["observer_key_id"] == data["observer_jwk"]["kid"])
        require(
            artifact["authorization_id"] == auth["authorization_id"],
            "successor-authorization-mismatch",
        )
        require(artifact["observer"] == context["trusted_observer"], "successor-observer-mismatch")
        require(
            set(after) == {"observation", "observer", "observed_at"},
            "successor-envelope-missing-fields",
        )
        require(isinstance(after["observation"], dict))
        require(artifact["observer"] == after["observer"])
        require(artifact["observed_at"] == after["observed_at"])
        require(
            artifact["successor_observation_digest"] == digest(after), "successor-digest-mismatch"
        )
    except (ValueError, InvalidSignature, jsonschema.ValidationError) as exc:
        result["reason"] = str(exc)
        return result
    result["successor_bound"] = True
    value = after["observation"].get("reachable")
    if after["observed_at"] > context["now"]:
        result.update(outcome="not-established", reason="observation-future")
    elif context["now"] - after["observed_at"] > context["max_age_seconds"]:
        result.update(outcome="not-established", reason="observation-stale")
    elif context["independence_required"] and after["observer"] == context["executor_id"]:
        result.update(outcome="not-established", reason="observer-not-independent")
    elif value is True:
        result.update(outcome="established", reason="predicate-satisfied")
    elif value is False:
        result.update(outcome="contradicted", reason="predicate-contradicted")
    else:
        result.update(outcome="not-established", reason="predicate-undecidable")
    return result

"""Deterministic small successor corpus; never regenerates the held #363 corpus."""

from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
AUTH = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"trace-206-authorizer").digest())
OBS = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"trace-206-observer").digest())


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def digest(obj):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def sign(body, key):
    return {**body, "signature": b64(key.sign(rfc8785.dumps(body)))}


def jwk(key, kid):
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64(raw), "kid": kid}


def base(observation):
    call = {"name": "commit", "arguments": {"commit": "abc123"}}
    declaration = {"impact": "external-side-effect"}
    authorization = {
        "authorization_id": "auth-003",
        "decision": "allow",
        "authorizer": "policy",
        "authorizer_key_id": "auth-key",
        "authorized_at": 100,
        "expires_at": 200,
        "scope": {"tools": ["commit"], "impacts": ["external-side-effect"]},
        "pic": {
            "profile": "PIC-CJSON/1.0",
            "intent_digest": "sha256:" + "1" * 64,
            "args_digest": "sha256:" + "2" * 64,
        },
        "declaration_digest": digest(declaration),
        "tool_call_digest": digest(call),
        "transcript_required": True,
    }
    after = {"observation": observation, "observer": "observer-1", "observed_at": 150}
    successor = {
        "profile": "tag:agentrust-io.com,2026:pic-trace-successor-v1",
        "authorization_id": "auth-003",
        "observer": "observer-1",
        "observer_key_id": "observer-key",
        "observed_at": 150,
        "successor_observation_digest": digest(after),
    }
    return {
        "bridge": sign(
            {
                "profile": "tag:agentrust-io.com,2026:pic-trace-bridge-v1",
                "authorization": authorization,
            },
            AUTH,
        ),
        "authorizer_jwk": jwk(AUTH, "auth-key"),
        "observer_jwk": jwk(OBS, "observer-key"),
        "declaration": declaration,
        "tool_call": call,
        "transcript": {"before": {"tool_call": call}},
        "pic_intent_digest": authorization["pic"]["intent_digest"],
        "pic_args_digest": authorization["pic"]["args_digest"],
        "successor": sign(successor, OBS),
        "after": after,
    }


CONTEXT = {
    "now": 160,
    "max_age_seconds": 30,
    "trusted_observer": "observer-1",
    "executor_id": "executor-1",
    "independence_required": True,
    "predicate": "reachable",
}


def generate(out=ROOT):
    cases = []

    def add(name, inputs, expected):
        reason = {
            "003-established": "predicate-satisfied",
            "003a-empty-envelope": "successor-envelope-missing-fields",
            "003b-empty-observation": "predicate-undecidable",
            "003c-unrelated-observation": "predicate-undecidable",
            "004-contradicted": "predicate-contradicted",
            "006-wrong-authorization": "successor-authorization-mismatch",
            "007-substituted-envelope": "successor-digest-mismatch",
            "008-invalid-observer-signature": "successor-signature-invalid",
            "009-observer-relabel": "successor-observer-mismatch",
            "010-stale-observation": "observation-stale",
            "011-future-observation": "observation-future",
            "012-authorizer-key-mismatch": "authorizer-key-mismatch",
        }.get(name, "pic-digest-syntax")
        cases.append(
            {
                "schema_version": "1.0",
                "id": name,
                "context": dict(CONTEXT),
                "inputs": inputs,
                "expected": {**expected, "reason": reason},
            }
        )

    ok = {"authorization_bound": True, "successor_bound": True, "outcome": "established"}
    add("003-established", base({"reachable": True}), ok)
    empty = base({"reachable": True})
    empty["after"] = {}
    add("003a-empty-envelope", empty, {**ok, "successor_bound": False, "outcome": None})
    for name, observation in [
        ("003b-empty-observation", {}),
        ("003c-unrelated-observation", {"other": True}),
        ("004-contradicted", {"reachable": False}),
    ]:
        add(
            name,
            base(observation),
            {**ok, "outcome": "contradicted" if name.startswith("004") else "not-established"},
        )
    for source in ["signed", "supplied"]:
        for field in ["intent_digest", "args_digest"]:
            data = base({"reachable": True})
            if source == "signed":
                data["bridge"]["authorization"]["pic"][field] = data["bridge"]["authorization"][
                    "pic"
                ][field][7:]
                body = {k: v for k, v in data["bridge"].items() if k != "signature"}
                data["bridge"] = sign(body, AUTH)
            else:
                data["pic_" + field] = data["pic_" + field][7:]
            add(
                f"005-{source}-{field}-bare",
                data,
                {"authorization_bound": False, "successor_bound": None, "outcome": None},
            )
    wrong = base({"reachable": True})
    wrong["successor"]["authorization_id"] = "auth-other"
    wrong["successor"] = sign(
        {k: v for k, v in wrong["successor"].items() if k != "signature"}, OBS
    )
    add("006-wrong-authorization", wrong, {**ok, "successor_bound": False, "outcome": None})
    altered = base({"reachable": True})
    altered["after"]["observation"]["reachable"] = False
    add("007-substituted-envelope", altered, {**ok, "successor_bound": False, "outcome": None})
    bad = base({"reachable": True})
    signature = bad["successor"]["signature"]
    bad["successor"]["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    add("008-invalid-observer-signature", bad, {**ok, "successor_bound": False, "outcome": None})
    for name, observer, observed_at in [
        ("009-observer-relabel", "observer-other", 150),
        ("010-stale-observation", "observer-1", 129),
        ("011-future-observation", "observer-1", 161),
    ]:
        data = base({"reachable": True})
        data["after"].update(observer=observer, observed_at=observed_at)
        body = {k: v for k, v in data["successor"].items() if k != "signature"}
        body.update(
            observer=observer,
            observed_at=observed_at,
            successor_observation_digest=digest(data["after"]),
        )
        data["successor"] = sign(body, OBS)
        expected = {**ok, "outcome": "not-established"}
        if name.startswith("009"):
            expected.update(successor_bound=False, outcome=None)
        add(name, data, expected)
    # Re-signed with the published authorizer key, so the signature still verifies
    # against the trusted JWK; only the signed key ID no longer names that JWK's kid.
    renamed = base({"reachable": True})
    body = {k: v for k, v in renamed["bridge"].items() if k != "signature"}
    body["authorization"]["authorizer_key_id"] = "auth-key-other"
    renamed["bridge"] = sign(body, AUTH)
    add(
        "012-authorizer-key-mismatch",
        renamed,
        {"authorization_bound": False, "successor_bound": None, "outcome": None},
    )
    for case in cases:
        (out / (case["id"] + ".json")).write_text(
            json.dumps(case, indent=2) + "\n", encoding="utf-8", newline="\n"
        )


if __name__ == "__main__":
    import sys

    generate(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT)

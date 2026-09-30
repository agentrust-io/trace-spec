#!/usr/bin/python3
"""Fuzz ``intent_bridge.verify_bridge`` and the successor-observation evaluator.

Input: one mode byte, then a JSON object carrying the verifier's inputs:
``bridge``, ``declaration``, ``pic_intent_digest``, ``pic_args_digest``,
``tool_call`` and ``transcript``. With mode bit 0 set, ``bridge.authorization``
is signed with the pinned authorizer key, so the fuzzer reaches the scope,
digest and transcript checks behind the signature.

Property: ``verify_bridge`` documents ``IntentBridgeError`` and its two
subclasses; ``evaluate_successor_observation`` documents
``SuccessorObservationError``. Every argument here is execution evidence from
outside the verifier, so any other exception is that evidence crashing it. An
accepted bridge must carry the decision ``allow``.
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agentrust_trace.intent_bridge import IntentBridgeError, sign_bridge, verify_bridge
    from agentrust_trace.sign import key_to_jwk
    from agentrust_trace.successor_observation import (
        SuccessorObservationError,
        evaluate_successor_observation,
    )

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
TRUSTED_JWK = {**key_to_jwk(KEY), "kid": "authorizer-key-1"}
NOW = 150


def _predicate(observation):
    status = observation.get("status")
    if not isinstance(status, str):
        return None
    return {"accepted": True, "rejected": False}.get(status)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, body = data[0], data[1:]
    try:
        case = json.loads(body)
    except (ValueError, RecursionError):
        return
    if not isinstance(case, dict):
        return
    bridge = case.get("bridge")
    if mode & 1 and isinstance(bridge, dict):
        try:
            bridge = sign_bridge(bridge.get("authorization"), KEY)
        except IntentBridgeError:
            return
    try:
        authorization = verify_bridge(
            bridge,
            TRUSTED_JWK,
            declaration=case.get("declaration"),
            pic_intent_digest=case.get("pic_intent_digest"),
            pic_args_digest=case.get("pic_args_digest"),
            tool_call=case.get("tool_call"),
            transcript=case.get("transcript"),
            now=NOW,
        )
    except IntentBridgeError:
        pass
    else:
        assert authorization["decision"] == "allow", authorization

    transcript = case.get("transcript")
    after = transcript.get("after") if isinstance(transcript, dict) else None
    try:
        evaluate_successor_observation(
            after,
            expected_successor_digest=case.get("successor_digest", "sha256:" + "0" * 64),
            trusted_observers=["observer-1"],
            executor_id="executor-1" if mode & 2 else None,
            independence_required=bool(mode & 4),
            now=NOW,
            max_age_seconds=3600,
            predicate=_predicate,
        )
    except SuccessorObservationError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

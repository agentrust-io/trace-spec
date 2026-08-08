"""Close the seven receipt rules the conformance set never exercised.

Each of these checks exists in the verifier with no vector behind it, so an
implementation could omit the check entirely and still pass. One fixture per rule,
each triggering exactly that rule and nothing else.

The existing fixtures pin a key whose private half is not published, so these pin
their own deterministic test key. Public JWKs only.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path("examples/action-receipts/conformance")
PROFILE = "trace.action_receipt.conformance.v0"
ISSUER = "did:web:factory.example:safety-controller"
KEY_ID = f"{ISSUER}#ed25519-coverage-2026q3"
ACTION_REF_FIELDS = ("agent_id", "action_type", "action_scope", "action_timestamp")

KEY = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"trace-spec action-receipt rule-coverage fixture key").digest()
)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk() -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64u(
            KEY.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
    }


def sha256_jcs(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


CALL_ID = "01986d7c-6b2f-7c68-9ff8-3e2f9d0db337"
SESSION = "trace-session-2026-07-06T15:22:11Z"
PREV_HASH = "sha256:" + "c1" * 32

ACTION = {
    "agent_id": "spiffe://factory.example/agent/ros2-fibonacci/dev",
    "action_type": "ros2.action.example_interfaces/Fibonacci",
    "action_scope": "/abort_fibonacci_process",
    "action_timestamp": "2026-07-06T15:22:13Z",
}
EVIDENCE = {
    "terminal_state": "accepted",
    "physical_completion_claim": "none",
    "completeness_claim": "not_proven",
}


def build(
    name: str,
    description: str,
    failure: str,
    *,
    action: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    receipt_overrides: dict[str, Any] | None = None,
    context_overrides: dict[str, Any] | None = None,
    trusted: dict[str, Any] | None = None,
) -> dict[str, Any]:
    act = copy.deepcopy(action or ACTION)
    ev = copy.deepcopy(evidence or EVIDENCE)

    context = {
        "call_id": CALL_ID,
        "session_id": SESSION,
        "require_receipt": True,
        "verification_time": "2026-07-06T15:24:00Z",
        "max_receipt_age_seconds": 300,
        "expected_previous_receipt_hash": PREV_HASH,
    }
    context.update(context_overrides or {})

    action_block = {**act, "action_ref": sha256_jcs({f: act[f] for f in ACTION_REF_FIELDS})}

    receipt: dict[str, Any] = {
        "issuer": ISSUER,
        "issuer_key_id": KEY_ID,
        "issuer_independence": "separate_process",
        "linked_call_id": CALL_ID,
        "session_id": SESSION,
        "action_ref": action_block["action_ref"],
        "evidence_type": "application/vnd.agentrust.action-receipt+json",
        "evidence_hash": sha256_jcs(ev),
        "previous_receipt_hash": PREV_HASH,
        "issued_at": "2026-07-06T15:22:15Z",
        "decision": "accepted",
    }
    receipt.update(receipt_overrides or {})

    body = rfc8785.dumps({k: v for k, v in receipt.items() if k != "signature"})
    receipt["signature"] = b64u(KEY.sign(body))

    return {
        "name": name,
        "description": description,
        "profile": PROFILE,
        "context": context,
        "action": action_block,
        "trusted_issuer_keys": trusted if trusted is not None else {KEY_ID: jwk()},
        "evidence": ev,
        "receipt": receipt,
        "expected": {
            "status": "receipt_invalid",
            "controller_outcome": "unknown",
            "failures": [failure],
            "warnings": [],
        },
    }


def main() -> None:
    fixtures: list[tuple[str, dict[str, Any]]] = []

    # action_ref_invalid — the declared action_ref is not the digest of its own preimage.
    f = build(
        "action-ref-not-recomputable",
        "The action's declared action_ref is not the digest of its own canonical "
        "preimage. A verifier that trusts the declared value instead of recomputing it "
        "would accept an action reference that binds nothing.",
        "action_ref_invalid",
    )
    forged = "sha256:" + "de" * 32
    f["action"]["action_ref"] = forged
    f["receipt"]["action_ref"] = forged  # keep them equal, so only the digest rule fires
    body = rfc8785.dumps({k: v for k, v in f["receipt"].items() if k != "signature"})
    f["receipt"]["signature"] = b64u(KEY.sign(body))
    fixtures.append(("10-action-ref-not-recomputable.json", f))

    fixtures.append((
        "11-call-id-mismatch.json",
        build(
            "call-id-mismatch",
            "An authentic receipt bound to a different call. Without this check a valid "
            "receipt from one call could be presented as evidence for another.",
            "call_id_mismatch",
            receipt_overrides={"linked_call_id": "01986d7c-0000-7c68-9ff8-000000000000"},
        ),
    ))

    fixtures.append((
        "12-session-id-mismatch.json",
        build(
            "session-id-mismatch",
            "An authentic receipt from a different session. Session binding is what "
            "stops a receipt being replayed into an unrelated run.",
            "session_id_mismatch",
            receipt_overrides={"session_id": "trace-session-2026-07-06T09:00:00Z"},
        ),
    ))

    # evidence_hash_mismatch — the evidence is altered after the receipt was signed over
    # its digest, so the receipt is authentic but describes different evidence.
    f = build(
        "evidence-hash-mismatch",
        "The receipt is authentic but its evidence_hash does not match the detached "
        "evidence supplied with it. The signature covers the digest, not the document, "
        "so only recomputation catches a swapped evidence body.",
        "evidence_hash_mismatch",
    )
    f["evidence"]["terminal_state"] = "rejected"  # after the hash was taken
    fixtures.append(("13-evidence-hash-mismatch.json", f))

    # issuer_key_unknown — the one non-failure in this set. Spec section 3.3.1: a
    # receipt whose issuer key is unknown to the verifier is unverified, not invalid.
    # An unpinned key means the signature cannot be checked, which confers no trust and
    # proves no forgery, so the expected block is written by hand rather than through
    # build()'s invalid-with-one-failure shape.
    f = build(
        "receipt-issuer-key-unknown",
        "The receipt names an issuer key the verifier has not pinned. A signature "
        "verifies against whatever key it names; only a pinned set decides whether "
        "that key was ever entitled to speak. Not holding the key is an inability to "
        "check, not evidence of forgery: the receipt is unverified, not invalid.",
        "issuer_key_unknown",
        trusted={f"{ISSUER}#ed25519-some-other-key": jwk()},
    )
    f["expected"] = {
        "status": "receipt_unverified",
        "controller_outcome": "unknown",
        "failures": [],
        "warnings": ["issuer_key_unknown"],
    }
    fixtures.append(("14-receipt-issuer-key-unknown.json", f))

    fixtures.append((
        "15-receipt-from-future.json",
        build(
            "receipt-from-future",
            "The receipt is issued after the verification time. A future-dated receipt "
            "is not stale, so the freshness ceiling alone never rejects it, and a "
            "verifier that only checks an upper bound on age accepts it.",
            "receipt_from_future",
            receipt_overrides={"issued_at": "2026-07-06T15:26:00Z"},
        ),
    ))

    fixtures.append((
        "16-decision-not-in-enum.json",
        build(
            "decision-not-in-enum",
            "The controller decision is outside the accepted vocabulary. An unrecognised "
            "verb must not be read as either acceptance or rejection.",
            "decision_invalid",
            receipt_overrides={"decision": "deferred"},
        ),
    ))

    for filename, doc in fixtures:
        (OUT / filename).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print("wrote", OUT / filename)


if __name__ == "__main__":
    main()

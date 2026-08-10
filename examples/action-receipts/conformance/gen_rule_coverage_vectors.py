"""Rule-coverage vectors for the receipt verifier: 10-16, and the second set 17-30.

10-16 close the seven receipt rules the conformance set never exercised (merged
upstream as PR #122): each triggers exactly one rule that previously had no vector
behind it.

17-30 give **every** receipt rule a second, independent vector (upstream #124: at
least two independent vectors per rule, where two vectors are independent if a single
implementation defect causes one to pass and the other to fail). Each second vector is
adversarially placed against a specific implementation shortcut its partner cannot
detect: digests that agree with the expected value through the first sixteen hex
characters but not after, identifiers that differ only by case, freshness violations
of exactly one second, a structurally well-formed signature of the wrong length, and
a receipt that is explicitly ``null`` rather than absent. The defect each pair is
split by is declared in ``tests/test_vector_completeness.py::DEFECTS`` and enforced
there.

The 01-09 fixtures pin a key whose private half is not published, so everything here
pins its own deterministic test key. Public JWKs only.
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

OUT = Path(__file__).resolve().parent
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

    # -----------------------------------------------------------------------
    # 17-30: the second vector for every receipt rule (#124).
    #
    # Each is placed where its partner has no reach. The partner vectors above and
    # in 01-09 violate their rule loudly — a wholly different digest, a different
    # identifier, minutes of staleness. These violate the same rules at the margin
    # an implementation shortcut would forgive: matching prefixes, case variants,
    # one-second boundaries, well-formed-but-wrong structures.
    # -----------------------------------------------------------------------

    def tail_flip(digest: str) -> str:
        """The same digest through every prefix, wrong in the final character."""
        return digest[:-1] + ("0" if digest[-1] != "0" else "1")

    correct_ref = sha256_jcs({name: ACTION[name] for name in ACTION_REF_FIELDS})

    # receipt_missing, second vector: the receipt key is present and null. An
    # implementation that tests key presence rather than null-ness reads this as a
    # receipt and falls through to dereference it.
    fixtures.append((
        "17-missing-receipt-explicit-null.json",
        {
            "name": "missing-receipt-explicit-null",
            "description": "A required receipt supplied as an explicit null rather "
            "than omitted. The same absence as 03 through a different door: a "
            "verifier that checks for the key rather than the value treats this as "
            "a present receipt.",
            "profile": PROFILE,
            "context": {
                "call_id": CALL_ID,
                "session_id": SESSION,
                "require_receipt": True,
                "verification_time": "2026-07-06T15:24:00Z",
                "max_receipt_age_seconds": 300,
                "expected_previous_receipt_hash": PREV_HASH,
            },
            "action": {**ACTION, "action_ref": correct_ref},
            "trusted_issuer_keys": {KEY_ID: jwk()},
            "receipt": None,
            "expected": {
                "status": "receipt_missing_required",
                "controller_outcome": "unknown",
                "failures": ["receipt_missing"],
                "warnings": [],
            },
        },
    ))

    forged_tail = tail_flip(correct_ref)
    f = build(
        "action-ref-tail-forged",
        "The declared action_ref equals the recomputed digest through the first "
        "sixteen hex characters and differs in the last. 10 is caught by any "
        "comparison at all; this one requires comparing the whole digest.",
        "action_ref_invalid",
        receipt_overrides={"action_ref": forged_tail},
    )
    f["action"]["action_ref"] = forged_tail  # keep them equal: only the digest rule fires
    fixtures.append(("18-action-ref-tail-forged.json", f))

    fixtures.append((
        "19-action-ref-mismatch-in-tail.json",
        build(
            "action-ref-mismatch-in-tail",
            "The receipt's action_ref differs from the action's only in the final "
            "character. 05 differs from the first character; a truncated comparison "
            "passes this one.",
            "action_ref_mismatch",
            receipt_overrides={"action_ref": tail_flip(correct_ref)},
        ),
    ))

    fixtures.append((
        "20-call-id-case-mismatch.json",
        build(
            "call-id-case-mismatch",
            "The receipt's linked_call_id is the context's call id upper-cased. 11 is "
            "a different call outright; this one is the same bytes through any "
            "case-normalising comparison.",
            "call_id_mismatch",
            receipt_overrides={"linked_call_id": CALL_ID.upper()},
        ),
    ))

    fixtures.append((
        "21-session-id-case-mismatch.json",
        build(
            "session-id-case-mismatch",
            "The receipt's session_id is the context's session id upper-cased. Session "
            "identifiers are opaque strings: two that differ by case are two sessions.",
            "session_id_mismatch",
            receipt_overrides={"session_id": SESSION.upper()},
        ),
    ))

    fixtures.append((
        "22-evidence-hash-mismatch-in-tail.json",
        build(
            "evidence-hash-mismatch-in-tail",
            "The receipt's evidence_hash agrees with the recomputed digest through "
            "every prefix and is wrong in the final character. 13 is wrong from the "
            "start; only a full-width comparison catches this one.",
            "evidence_hash_mismatch",
            receipt_overrides={"evidence_hash": tail_flip(sha256_jcs(EVIDENCE))},
        ),
    ))

    # issuer_key_unknown, second vector: the pinned set holds this very key under a
    # case-variant of the receipt's key id. Key identifiers are opaque: a lookup that
    # normalises case resolves this and treats the receipt as verifiable.
    f = build(
        "receipt-issuer-key-case-variant",
        "The trusted set pins the right public key under a case-variant of the "
        "receipt's issuer_key_id. An exact lookup does not hold this key; a "
        "case-normalising lookup does, and verifies. 14 names a key absent under "
        "any normalisation.",
        "issuer_key_unknown",
        trusted={KEY_ID.upper(): jwk()},
    )
    f["expected"] = {
        "status": "receipt_unverified",
        "controller_outcome": "unknown",
        "failures": [],
        "warnings": ["issuer_key_unknown"],
    }
    fixtures.append(("23-receipt-issuer-key-case-variant.json", f))

    # signature_or_key_mismatch, second vector: a signature that decodes cleanly to
    # the wrong number of bytes. 04 is a well-formed 64-byte signature by the wrong
    # key, which only cryptographic verification rejects; this one is rejected by
    # structure alone. An implementation that stops at structure passes 04.
    f = build(
        "receipt-signature-malformed",
        "The signature is valid base64url decoding to 32 bytes — half an Ed25519 "
        "signature. 04 carries a well-formed signature by the wrong key; together "
        "they separate structural validation from cryptographic verification.",
        "signature_or_key_mismatch",
    )
    f["receipt"]["signature"] = b64u(bytes(32))  # after signing: structurally short
    fixtures.append(("24-receipt-signature-malformed.json", f))

    fixtures.append((
        "25-stale-receipt-boundary.json",
        build(
            "stale-receipt-boundary",
            "Stale by exactly one second: age 301 against a 300-second ceiling. 06 is "
            "stale by nineteen minutes; any tolerance an implementation grants "
            "swallows this one.",
            "receipt_stale",
            receipt_overrides={"issued_at": "2026-07-06T15:18:59Z"},
        ),
    ))

    fixtures.append((
        "26-receipt-from-future-boundary.json",
        build(
            "receipt-from-future-boundary",
            "Issued one second after the verification time. 15 is two minutes ahead; "
            "a clock-skew allowance passes this one.",
            "receipt_from_future",
            receipt_overrides={"issued_at": "2026-07-06T15:24:01Z"},
        ),
    ))

    fixtures.append((
        "27-receipt-chain-gap-in-tail.json",
        build(
            "receipt-chain-gap-in-tail",
            "The previous_receipt_hash matches the expected predecessor through every "
            "prefix and differs in the final character. 07 links somewhere else "
            "entirely.",
            "receipt_chain_gap",
            receipt_overrides={"previous_receipt_hash": tail_flip(PREV_HASH)},
        ),
    ))

    fixtures.append((
        "28-physical-completion-claim-case.json",
        build(
            "physical-completion-claim-case",
            "The claim is 'None' — the vocabulary word 'none' through any "
            "case-normalising comparison, and outside the vocabulary as bytes. 09 "
            "claims completion outright.",
            "unsupported_physical_completion_claim",
            evidence={**EVIDENCE, "physical_completion_claim": "None"},
        ),
    ))

    # issuer_not_independent, second vector: the same self-report on the rejected
    # path. A warning wired only into the acceptance branch — a natural shortcut,
    # since acceptance is where self-reporting profits — goes silent here.
    f = build(
        "same-party-self-report-rejected",
        "A gateway self-report on a rejected action. 08 self-reports an acceptance; "
        "independence of the issuer matters on both branches, and a warning emitted "
        "only for acceptances misses this one.",
        "issuer_not_independent",
        evidence={**EVIDENCE, "terminal_state": "rejected"},
        receipt_overrides={
            "issuer_independence": "gateway_self_report",
            "decision": "rejected",
        },
    )
    f["expected"] = {
        "status": "receipt_valid_rejected",
        "controller_outcome": "rejected",
        "failures": [],
        "warnings": ["issuer_not_independent"],
    }
    fixtures.append(("29-same-party-self-report-rejected.json", f))

    fixtures.append((
        "30-decision-case-variant.json",
        build(
            "decision-case-variant",
            "The decision is 'Accepted' — inside the vocabulary case-insensitively, "
            "outside it as bytes. 16 is a word the vocabulary never contained. An "
            "enum check that normalises case reads this as an acceptance.",
            "decision_invalid",
            receipt_overrides={"decision": "Accepted"},
        ),
    ))

    for filename, doc in fixtures:
        (OUT / filename).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print("wrote", OUT / filename)


if __name__ == "__main__":
    main()

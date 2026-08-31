"""Regenerate the gap-disclosure fixtures under the splice model.

A disclosure is a chain element, not a description of a range: the argument for that
shape is in spec/trace-v0.2.md section 3.3.4 and the review on
agentrust-io/trace-spec#117. Deterministic keys; public JWKs only.

01-08 are one vector per rule. 09-16 are the second set (upstream #124: two
independent vectors per rule), each placed against an implementation shortcut its
partner cannot detect — case-normalised key and session lookups, digest comparisons
truncated to a prefix, structural signature validation, and a contradiction check
gated on the sealed path. 12 and 13 cover `disclosure_stream_mismatch`, the rule the
#117 review asked for: a disclosure must be bound to the receipt stream it excuses,
or one honestly signed for stream A is a transplantable excuse for a gap in stream B.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path(__file__).resolve().parent
PROFILE = "trace.action_receipt.conformance.v0"
SESSION = "trace-session-2026-07-06T15:22:11Z"
ISSUER = "did:web:factory.example:safety-controller"

# The key that signed the element before the gap. Under the splice model this is the
# only key entitled to disclose, together with its ancestors.
KEY_ID = f"{ISSUER}#ed25519-2026q3"
PARENT_KEY_ID = f"{ISSUER}#ed25519-workload-attestation"
FOREIGN_KEY_ID = f"{ISSUER}#ed25519-unrelated-but-trusted"

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PARENT = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
FOREIGN = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"trace-spec#117 unrelated trusted key").digest()
)

# A distinct keypair registered under a case-variant of the parent's key id: the
# confusable-identifier attack, for vector 11. Key ids are opaque strings, so the
# variant names a different key, not the parent.
CONFUSABLE_KEY_ID = f"{ISSUER}#ED25519-WORKLOAD-ATTESTATION"
CONFUSABLE = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"trace-spec#117 confusable ancestor key").digest()
)

PREDECESSOR_HASH = "sha256:" + "a1" * 32

# The two outcome names this set defines, held once each. #117's carry note expects
# the disclosed outcome to keep its semantics and possibly not its name under the
# vocabulary being unified across the "not established" threads; a rename is an edit
# here, its twin in the fixture test, the spec section, the docs row, and one
# regeneration.
DISCLOSED = "receipt_gap_disclosed"
UNVERIFIED = "gap_disclosure_unverified"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk(key: Ed25519PrivateKey) -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64u(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
    }


def digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def sign(disclosure: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    body = {k: v for k, v in disclosure.items() if k != "signature"}
    return {**disclosure, "signature": b64u(key.sign(rfc8785.dumps(body)))}


TRUSTED = {KEY_ID: jwk(KEY), PARENT_KEY_ID: jwk(PARENT), FOREIGN_KEY_ID: jwk(FOREIGN)}


def base_disclosure() -> dict[str, Any]:
    return {
        "type": "GapDisclosure/1.0",
        "previous_receipt_hash": PREDECESSOR_HASH,
        "session_id": SESSION,
        "issuer_key_id": KEY_ID,
        "cause": "crash",
        "receipts_lost_estimate": 3,
    }


def base_context(**over: Any) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "session_id": SESSION,
        "require_receipt": True,
        "verification_time": "2026-07-06T15:24:00Z",
        "max_receipt_age_seconds": 300,
        "expected_previous_receipt_hash": PREDECESSOR_HASH,
        "chain": {
            # The element the disclosure links back to, and whether it is in the chain.
            "predecessor_hash": PREDECESSOR_HASH,
            "predecessor_present": True,
            # Who signed it. Issuer binding is derived from this, not supplied.
            "predecessor_issuer_key_id": KEY_ID,
            "permitted_ancestor_key_ids": [PARENT_KEY_ID],
            # What the next emitted element links back to. Filled in per fixture once
            # the disclosure has been signed and its digest is known.
            "successor_previous_receipt_hash": None,
            "successor_present": True,
            # Elements the disclosure implicitly claims are absent but which are in
            # fact present in the chain.
            "claimed_absent_but_present": [],
            "consecutive_disclosures": 1,
        },
    }
    ctx["chain"].update(over)
    return ctx


def fixture(
    name: str,
    description: str,
    disclosure: dict[str, Any],
    expected: dict[str, Any],
    context: dict[str, Any],
    *,
    link_successor: bool = True,
    trusted: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if link_successor and context["chain"]["successor_previous_receipt_hash"] is None:
        context["chain"]["successor_previous_receipt_hash"] = digest(disclosure)
    return {
        "name": name,
        "description": description,
        "profile": PROFILE,
        "source": {
            "issue": "agentrust-io/trace-spec#117",
            "spec": "spec/trace-v0.2.md section 3.3.4",
        },
        "context": context,
        "action": {
            "agent_id": "spiffe://factory.example/agent/ros2-fibonacci/dev",
            "action_type": "ros2.action.example_interfaces/Fibonacci",
            "action_scope": "/abort_fibonacci_process",
            "action_timestamp": "2026-07-06T15:22:13Z",
            "action_ref": "sha256:" + "e3" * 32,
        },
        "trusted_issuer_keys": trusted if trusted is not None else TRUSTED,
        "gap_disclosure": disclosure,
        "expected": {
            **expected,
            # Reporting (spec section 3.3.4): each disclosed gap is reported with the
            # predecessor it links and the cause when one was supplied. Echoed from
            # the disclosure as carried, never judged: a tampered cause is reported
            # as carried and refused by the signature rule, not by this field.
            "linked_predecessor": disclosure.get("previous_receipt_hash"),
            "cause": disclosure.get("cause"),
        },
    }


def ok(consecutive: int = 1) -> dict[str, Any]:
    return {
        "status": DISCLOSED,
        "controller_outcome": "unknown",
        "failures": [],
        "warnings": [DISCLOSED],
        "consecutive_disclosures": consecutive,
    }


def bad(*failures: str) -> dict[str, Any]:
    return {
        "status": "receipt_invalid",
        "controller_outcome": "unknown",
        "failures": list(failures),
        "warnings": [],
        "consecutive_disclosures": 1,
    }


def unverified(*advisories: str) -> dict[str, Any]:
    """Unverifiable is not invalid (spec section 3.3.2): advisory, no failures."""
    return {
        "status": UNVERIFIED,
        "controller_outcome": "unknown",
        "failures": [],
        "warnings": list(advisories),
        "consecutive_disclosures": 1,
    }


def main() -> None:
    out: list[tuple[str, dict[str, Any]]] = []

    out.append(("01-gap-disclosed-valid.json", fixture(
        "gap-disclosed-valid",
        "A disclosure spliced into the chain: it links back to a present element and "
        "the next element links back to it. Coverage is structural, so nothing is "
        "asserted about a range.",
        sign(base_disclosure(), KEY), ok(), base_context())))

    out.append(("02-gap-disclosure-dangling-predecessor.json", fixture(
        "gap-disclosure-dangling-predecessor",
        "The disclosure links back to an element that is not in the chain. Half a "
        "splice is not a splice: it fixes nothing in place.",
        sign(base_disclosure(), KEY),
        bad("disclosure_predecessor_absent"),
        base_context(predecessor_present=False))))

    out.append(("03-gap-disclosure-successor-does-not-link.json", fixture(
        "gap-disclosure-successor-does-not-link",
        "The next element after resumption links past the disclosure to the element "
        "before the gap, leaving the disclosure attached at one end only. A disclosure "
        "no successor names can be minted later and slid over any gap.",
        sign(base_disclosure(), KEY),
        bad("disclosure_not_sealed_by_successor"),
        base_context(successor_previous_receipt_hash=PREDECESSOR_HASH),
        link_successor=False)))

    out.append(("04-gap-disclosure-contradicted.json", fixture(
        "gap-disclosure-contradicted",
        "Elements the disclosure implies are absent are present in the chain. A "
        "self-contradictory disclosure impeaches the emitter rather than excusing it.",
        sign(base_disclosure(), KEY),
        bad("disclosure_contradicted"),
        base_context(claimed_absent_but_present=["sha256:" + "c9" * 32]))))

    out.append(("05-gap-disclosure-foreign-key.json", fixture(
        "gap-disclosure-foreign-key",
        "Signed by a key the verifier trusts, but which is neither the key that signed "
        "the linked element nor an ancestor of it. A gap is where introducing an "
        "unrelated key is most useful and least distinguishable from recovery.",
        sign({**base_disclosure(), "issuer_key_id": FOREIGN_KEY_ID}, FOREIGN),
        bad("disclosure_issuer_not_chain_key"), base_context())))

    out.append(("06-gap-disclosed-parent-key-null-estimate.json", fixture(
        "gap-disclosed-parent-key-null-estimate",
        "Signed by the hierarchical parent, because the crash took the session key "
        "with it, and the count of lost receipts is not bounded. The estimate is an "
        "unverifiable self-report either way; the chain links are what hold.",
        sign({**base_disclosure(), "issuer_key_id": PARENT_KEY_ID,
              "receipts_lost_estimate": None}, PARENT),
        ok(consecutive=3), base_context(consecutive_disclosures=3))))

    out.append(("07-gap-disclosure-unknown-key.json", fixture(
        "gap-disclosure-unknown-key",
        "The named key is the one that signed the linked element, but the verifier "
        "does not hold it. Chain position does not confer trust — and the verifier's "
        "ignorance does not prove forgery. Unverifiable is not invalid (spec "
        "section 3.3.2): the disclosure is surfaced as unverified with an advisory, "
        "conferring nothing and accusing no one.",
        sign({**base_disclosure(), "issuer_key_id": f"{ISSUER}#ed25519-2027q1"}, KEY),
        unverified("disclosure_key_unknown"),
        # The chain names the same key, so issuer binding is satisfied and only trust
        # fails. Otherwise this fixture would fire two rules and stop isolating one.
        base_context(predecessor_issuer_key_id=f"{ISSUER}#ed25519-2027q1"))))

    tampered = sign(base_disclosure(), KEY)
    tampered["cause"] = "shutdown"  # altered after signing
    out.append(("08-gap-disclosure-tampered.json", fixture(
        "gap-disclosure-tampered",
        "Altered after signing, so the signature no longer covers its contents.",
        tampered, bad("disclosure_signature_invalid"), base_context())))

    # -----------------------------------------------------------------------
    # 09-16: the second vector for every disclosure rule (#124), each placed
    # against an implementation shortcut its partner in 01-08 cannot detect.
    # -----------------------------------------------------------------------

    def tail_flip(value: str) -> str:
        """The same digest through every prefix, wrong in the final character."""
        return value[:-1] + ("0" if value[-1] != "0" else "1")

    # disclosure_key_unknown, second vector: the verifier pins this very key under a
    # case-variant of its id. An exact lookup fails; a case-normalising lookup
    # resolves it and verifies. 07 names a key absent under any normalisation.
    out.append(("09-gap-disclosure-key-case-variant.json", fixture(
        "gap-disclosure-key-case-variant",
        "The trusted set pins the right public key under a case-variant of the "
        "disclosure's issuer_key_id. Key identifiers are opaque strings: holding the "
        "key under a different spelling is not holding the key the disclosure names.",
        sign(base_disclosure(), KEY),
        unverified("disclosure_key_unknown"),
        base_context(),
        trusted={
            KEY_ID.upper(): jwk(KEY),
            PARENT_KEY_ID: jwk(PARENT),
            FOREIGN_KEY_ID: jwk(FOREIGN),
        })))

    # disclosure_signature_invalid, second vector: a signature that decodes cleanly
    # to 32 bytes — half an Ed25519 signature. 08 is a well-formed 64-byte signature
    # over altered content, which only cryptographic verification rejects; this one
    # falls to structure alone, so the pair separates the two kinds of check.
    malformed = sign(base_disclosure(), KEY)
    malformed["signature"] = b64u(bytes(32))
    out.append(("10-gap-disclosure-signature-malformed.json", fixture(
        "gap-disclosure-signature-malformed",
        "The signature is valid base64url of the wrong length. Together with the "
        "tampered vector this separates structural validation from verification.",
        malformed, bad("disclosure_signature_invalid"), base_context())))

    # disclosure_issuer_not_chain_key, second vector: a distinct key registered
    # under a case-variant of the permitted ancestor's id. The verifier trusts it and
    # the signature verifies — entitlement is what fails. A membership test that
    # normalises case admits it. 05's foreign key fails under any normalisation.
    out.append(("11-gap-disclosure-confusable-ancestor-key.json", fixture(
        "gap-disclosure-confusable-ancestor-key",
        "Signed by a trusted key whose id is the permitted ancestor's id in a "
        "different case — a confusable registration, not the ancestor. Entitlement "
        "to disclose is bound to the chain's exact key ids.",
        sign({**base_disclosure(), "issuer_key_id": CONFUSABLE_KEY_ID}, CONFUSABLE),
        bad("disclosure_issuer_not_chain_key"),
        base_context(),
        trusted={**TRUSTED, CONFUSABLE_KEY_ID: jwk(CONFUSABLE)})))

    # disclosure_stream_mismatch, both vectors: the rule the #117 review added.
    out.append(("12-gap-disclosure-replayed-stream.json", fixture(
        "gap-disclosure-replayed-stream",
        "A disclosure honestly signed for a different session, presented against "
        "this one. Every structural check passes — the splice is sound, the key is "
        "entitled — because the disclosure was genuine where it was minted. Stream "
        "binding is the only thing that refuses the transplant.",
        sign({**base_disclosure(),
              "session_id": "trace-session-2026-07-01T08:00:00Z"}, KEY),
        bad("disclosure_stream_mismatch"), base_context())))

    out.append(("13-gap-disclosure-stream-case-variant.json", fixture(
        "gap-disclosure-stream-case-variant",
        "The disclosure's session_id is this session's id upper-cased. Session "
        "identifiers are opaque: a case-normalising comparison reads this as bound "
        "to the stream, and it is not.",
        sign({**base_disclosure(), "session_id": SESSION.upper()}, KEY),
        bad("disclosure_stream_mismatch"), base_context())))

    # disclosure_predecessor_absent, second vector: the predecessor is present and
    # the link agrees with its hash through every prefix, wrong in the last
    # character. 02's predecessor is absent outright, which a truncated comparison
    # still catches via the presence bit — this one it forgives.
    out.append(("14-gap-disclosure-predecessor-link-tail.json", fixture(
        "gap-disclosure-predecessor-link-tail",
        "The disclosure's previous_receipt_hash matches the present predecessor's "
        "hash in all but the final character. A link to almost the right element is "
        "a link to nothing.",
        sign({**base_disclosure(),
              "previous_receipt_hash": tail_flip(PREDECESSOR_HASH)}, KEY),
        bad("disclosure_predecessor_absent"), base_context())))

    # disclosure_not_sealed_by_successor, second vector: the successor's link agrees
    # with the disclosure's digest through every prefix. 03's successor links
    # somewhere else entirely.
    sealed_almost = sign(base_disclosure(), KEY)
    out.append(("15-gap-disclosure-seal-tail-mismatch.json", fixture(
        "gap-disclosure-seal-tail-mismatch",
        "The next element's previous_receipt_hash matches the disclosure's digest "
        "in all but the final character: sealed to a truncated comparison, unsealed "
        "in fact.",
        sealed_almost,
        bad("disclosure_not_sealed_by_successor"),
        base_context(successor_previous_receipt_hash=tail_flip(digest(sealed_almost))),
        link_successor=False)))

    # disclosure_contradicted, second vector: the contradiction stands at the tail
    # of the chain, where no successor exists yet. A contradiction check gated on
    # the sealed path — natural, since sealing is where cross-examination happens —
    # never runs here. 04's contradiction sits on the sealed path. The tail position
    # additionally carries the disclosure_not_yet_sealed advisory: a failure decides
    # the outcome, and the advisory still reports what could not be checked.
    out.append(("16-gap-disclosure-contradicted-at-tail.json", fixture(
        "gap-disclosure-contradicted-at-tail",
        "Elements the disclosure implies are absent are present, and the disclosure "
        "sits at the live tail with no successor yet. Self-contradiction impeaches "
        "the emitter wherever it stands.",
        sign(base_disclosure(), KEY),
        {**bad("disclosure_contradicted"), "warnings": ["disclosure_not_yet_sealed"]},
        base_context(
            claimed_absent_but_present=["sha256:" + "c9" * 32],
            successor_present=False,
            successor_previous_receipt_hash=None,
        ),
        link_successor=False)))

    # disclosure_not_yet_sealed, both vectors. At the live tail — after the crash,
    # before resumption — no successor exists and the seal cannot be checked. Spec
    # section 3.3.2 logic a third time: inability to check is not evidence of a
    # defect, so the outcome is gap_disclosure_unverified with an advisory, not
    # receipt_gap_disclosed and not receipt_invalid. Without this rule the verifier
    # granted full disclosed status to a splice attached at one end — the state the
    # draft text says covers nothing, and one an adversary reaches at will by
    # truncating the chain immediately after a disclosure.
    out.append(("17-gap-disclosure-at-unsealed-tail.json", fixture(
        "gap-disclosure-at-unsealed-tail",
        "A well-formed disclosure at the live tail of the chain: signed by the "
        "chain key, linked to a present predecessor, and with no successor yet to "
        "seal it. Not invalid — nothing is defective — and not disclosed either: "
        "half a splice covers nothing until the chain resumes and the seal can be "
        "checked. Re-verification after resumption upgrades it.",
        sign(base_disclosure(), KEY),
        unverified("disclosure_not_yet_sealed"),
        base_context(successor_present=False, successor_previous_receipt_hash=None),
        link_successor=False)))

    # Second vector: the successor is absent but the context's successor-link field
    # carries a stale value. An implementation that derives sealed-ness from "is
    # there a link value" rather than "is there a successor" reads this as sealed —
    # the same presence-versus-state confusion as an explicit-null receipt.
    out.append(("18-gap-disclosure-tail-with-stale-link.json", fixture(
        "gap-disclosure-tail-with-stale-link",
        "The same unsealed tail, but the successor-link field in the verification "
        "context holds a leftover value from a previous verification. There is "
        "still no successor: sealed-ness is a fact about the chain, not about a "
        "field being non-null.",
        sign(base_disclosure(), KEY),
        unverified("disclosure_not_yet_sealed"),
        base_context(
            successor_present=False,
            successor_previous_receipt_hash="sha256:" + "d7" * 32,
        ),
        link_successor=False)))

    # disclosure_type_unsupported, both vectors. The type member is the contract the
    # rest of the element is read under, and it is covered by the signature, so a
    # wrong value is well-signed and fails nothing else: only an explicit equality
    # check refuses it. 19 carries a plausible future version; 20 omits the member,
    # which separates an equality check from a presence check.
    out.append(("19-gap-disclosure-type-version-unknown.json", fixture(
        "gap-disclosure-type-version-unknown",
        "A well-signed disclosure whose type names a version this verifier does not "
        "implement. An unknown version is rejected rather than parsed best-effort.",
        sign({**base_disclosure(), "type": "GapDisclosure/2.0"}, KEY),
        bad("disclosure_type_unsupported"), base_context())))

    no_type = {k: v for k, v in base_disclosure().items() if k != "type"}
    out.append(("20-gap-disclosure-type-absent.json", fixture(
        "gap-disclosure-type-absent",
        "A well-signed disclosure with no type member at all. A presence check and "
        "an equality check differ exactly here.",
        sign(no_type, KEY),
        bad("disclosure_type_unsupported"), base_context())))

    for name, doc in out:
        (OUT / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print("wrote", name)



if __name__ == "__main__":
    main()

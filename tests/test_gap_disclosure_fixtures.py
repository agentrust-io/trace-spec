"""Conformance checks for the gap-disclosure fixture set (spec section 3.3.4, #117).

A ``GapDisclosure`` is a chain element: it links back to the element before the gap,
and the next element emitted after resumption links back to it. Coverage is
structural, never asserted, so this verifier performs no range arithmetic. It checks
the splice, and it checks the two things a splice cannot carry by itself: that the
signing key is entitled to disclose for this chain, and that the disclosure is bound
to the stream it excuses.

The registry below is the inventory, in the shape #124 settled for the receipt
verifier next door: every obligation is one ``RULES`` entry, and a check that is not
registered is a check that never runs. Codes match the fixture set one to one.

Three outcomes, and the boundaries between them are the content of section 3.3.4:

- ``receipt_gap_disclosed`` needs everything to hold, including the seal.
- ``receipt_invalid`` means a check ran and failed. A forged, transplanted or
  self-contradictory disclosure is worse evidence than none.
- ``gap_disclosure_unverified`` means a check could not run: the issuer key is not
  held, or the chain has not resumed so no successor seals the splice. Inability to
  check is not evidence of a defect (spec section 3.3.2's treatment of unknown
  issuer keys), so nothing here is refused; nothing is granted either.

The tail is the adversarial case among these, pinned by its own test below rather
than left to the fixture sweep: a chain truncated immediately after a disclosure is
indistinguishable from an honest live tail, so whatever outcome the tail gets, a
deliberate truncation gets too. Granting the tail ``receipt_gap_disclosed`` would
hand an adversary that outcome at will.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURE_DIR = Path(__file__).parent.parent / "examples" / "action-receipts" / "gap-disclosure"

# The two outcome names this set defines, held once each; their twins live in the
# generator. #117's carry note expects the disclosed outcome to keep its semantics
# and possibly not its name, so a rename is these two constants, the generator's,
# the spec section, the docs row, and one regeneration.
DISCLOSED = "receipt_gap_disclosed"
UNVERIFIED = "gap_disclosure_unverified"

STATUSES = frozenset({DISCLOSED, "receipt_invalid", UNVERIFIED})


def _element_digest(element: dict[str, Any]) -> str:
    """The chain digest of an element, over its full canonical form, signature included.

    The successor's ``previous_receipt_hash`` names the disclosure as it stands in the
    chain, which is the signed object. Hashing the unsigned body instead would let two
    disclosures with different signatures collide under one seal.
    """
    return "sha256:" + hashlib.sha256(rfc8785.dumps(element)).hexdigest()


def _signature_valid(disclosure: dict[str, Any], jwk: dict[str, Any]) -> bool:
    """One code for every way a signature fails to verify.

    Structural malformation and cryptographic mismatch are one obligation here, not
    two: the signature does not verify. A separate length guard before the library
    call would be a guard the fixtures cannot see, deletable with every vector still
    green, which is the deletable-guard defect this suite is built to refuse. The
    library refuses malformed input on its own; fixture 10 pins that a 32-byte
    signature yields this code and not an error.
    """
    encoded = disclosure.get("signature")
    if not isinstance(encoded, str):
        return False
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (binascii.Error, ValueError):
        return False
    body = {k: v for k, v in disclosure.items() if k != "signature"}
    key = Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    )
    try:
        key.verify(raw, rfc8785.dumps(body))
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True)
class Rule:
    """One registered obligation: a failure code and the predicate that fires it."""

    code: str
    fires: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], bool]


def _issuer_not_chain_key(d: dict[str, Any], chain: dict[str, Any], _: dict[str, Any]) -> bool:
    # Entitlement is bound to the chain's exact key ids: the key that signed the
    # linked element, or a permitted ancestor. Identifiers are opaque strings, so no
    # case normalisation; fixture 11 is a distinct trusted key under a case-variant
    # of the ancestor's id, and it must fail here.
    permitted = {chain["predecessor_issuer_key_id"], *chain["permitted_ancestor_key_ids"]}
    return d.get("issuer_key_id") not in permitted


def _stream_mismatch(d: dict[str, Any], _: dict[str, Any], ctx: dict[str, Any]) -> bool:
    # Exact comparison. Session ids are opaque; fixture 13 is this session's id
    # upper-cased, and a normalising comparison reads it as bound.
    return d.get("session_id") != ctx["session_id"]


def _predecessor_absent(d: dict[str, Any], chain: dict[str, Any], _: dict[str, Any]) -> bool:
    # The disclosure must name a chain element that is present, by its exact digest.
    # Fixture 14 agrees with the present predecessor through every prefix and is
    # wrong in the final character: a link to almost the right element is a link to
    # nothing.
    if not chain["predecessor_present"]:
        return True
    return d.get("previous_receipt_hash") != chain["predecessor_hash"]


def _contradicted(_: dict[str, Any], chain: dict[str, Any], __: dict[str, Any]) -> bool:
    # Runs wherever the disclosure stands, sealed or at the tail (fixture 16): a
    # self-contradictory disclosure impeaches the emitter wherever it is.
    return bool(chain["claimed_absent_but_present"])


def _not_sealed(d: dict[str, Any], chain: dict[str, Any], _: dict[str, Any]) -> bool:
    # Only decidable once the chain has resumed. Sealed-ness is a fact about the
    # chain, not about a link field being non-null: fixture 18 carries a stale link
    # value with no successor, and must fall to the tail advisory instead.
    if not chain["successor_present"]:
        return False
    return chain["successor_previous_receipt_hash"] != _element_digest(d)


def _type_unsupported(d: dict[str, Any], _: dict[str, Any], __: dict[str, Any]) -> bool:
    # The type member is the contract the rest of the element is read under, and it
    # is covered by the signature, so a wrong value is well-signed and fails nothing
    # else: only this equality refuses it. Absence fails the same way (fixture 20):
    # a presence check alone reads an omitted contract as satisfied.
    return d.get("type") != "GapDisclosure/1.0"


RULES: tuple[Rule, ...] = (
    Rule("disclosure_type_unsupported", _type_unsupported),
    Rule("disclosure_issuer_not_chain_key", _issuer_not_chain_key),
    Rule("disclosure_stream_mismatch", _stream_mismatch),
    Rule("disclosure_predecessor_absent", _predecessor_absent),
    Rule("disclosure_contradicted", _contradicted),
    Rule("disclosure_not_sealed_by_successor", _not_sealed),
)


def verify_gap_disclosure(
    disclosure: dict[str, Any],
    context: dict[str, Any],
    trusted_issuer_keys: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate one disclosure against its chain context. Returns the outcome shape
    the fixtures pin: status, failures, warnings, and the consecutive-disclosure
    count, which is reported rather than judged (an emitter failing repeatedly and
    disclosing each time is behaving better than one that is silent)."""
    chain = context["chain"]
    failures: list[str] = []
    warnings: list[str] = []

    # Signature first, and only when the named key is held. An exact lookup: holding
    # the key under a different spelling is not holding the key the disclosure names
    # (fixture 09). An unknown key is an advisory, not a failure: chain position does
    # not confer trust, and the verifier's ignorance does not prove forgery.
    jwk = trusted_issuer_keys.get(disclosure.get("issuer_key_id", ""))
    if jwk is None:
        warnings.append("disclosure_key_unknown")
    elif not _signature_valid(disclosure, jwk):
        failures.append("disclosure_signature_invalid")

    failures.extend(rule.code for rule in RULES if rule.fires(disclosure, chain, context))

    if not chain["successor_present"]:
        warnings.append("disclosure_not_yet_sealed")

    if failures:
        status = "receipt_invalid"
    elif warnings:
        status = UNVERIFIED
    else:
        status = DISCLOSED
        warnings = [DISCLOSED]

    assert status in STATUSES
    return {
        "status": status,
        "controller_outcome": "unknown",
        "failures": failures,
        "warnings": warnings,
        "consecutive_disclosures": chain["consecutive_disclosures"],
        # Reporting (spec section 3.3.4): the linked predecessor and the cause, echoed
        # as carried. Judged nowhere: a wrong link fails the predecessor rule and a
        # tampered cause fails the signature rule, so reporting stays reporting.
        "linked_predecessor": disclosure.get("previous_receipt_hash"),
        "cause": disclosure.get("cause"),
    }


FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))


def test_fixture_set_is_complete() -> None:
    assert [p.name for p in FIXTURES] == [
        "01-gap-disclosed-valid.json",
        "02-gap-disclosure-dangling-predecessor.json",
        "03-gap-disclosure-successor-does-not-link.json",
        "04-gap-disclosure-contradicted.json",
        "05-gap-disclosure-foreign-key.json",
        "06-gap-disclosed-parent-key-null-estimate.json",
        "07-gap-disclosure-unknown-key.json",
        "08-gap-disclosure-tampered.json",
        "09-gap-disclosure-key-case-variant.json",
        "10-gap-disclosure-signature-malformed.json",
        "11-gap-disclosure-confusable-ancestor-key.json",
        "12-gap-disclosure-replayed-stream.json",
        "13-gap-disclosure-stream-case-variant.json",
        "14-gap-disclosure-predecessor-link-tail.json",
        "15-gap-disclosure-seal-tail-mismatch.json",
        "16-gap-disclosure-contradicted-at-tail.json",
        "17-gap-disclosure-at-unsealed-tail.json",
        "18-gap-disclosure-tail-with-stale-link.json",
        "19-gap-disclosure-type-version-unknown.json",
        "20-gap-disclosure-type-absent.json",
    ]


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_fixture(path: Path) -> None:
    doc = json.loads(path.read_text())
    result = verify_gap_disclosure(
        doc["gap_disclosure"], doc["context"], doc["trusted_issuer_keys"]
    )
    assert result == doc["expected"], f"{path.name}: {result} != {doc['expected']}"


def test_the_live_tail_is_not_granted_what_the_seal_earns() -> None:
    """The tail case, as a test rather than a paragraph.

    Fixtures 01 and 17 carry byte-identical disclosures; the only difference is
    whether a successor exists to seal the splice. The sealed one earns
    ``receipt_gap_disclosed``. The tail one is ``gap_disclosure_unverified``: not
    invalid, because nothing is defective and the chain may resume in a moment, and
    not disclosed, because half a splice covers nothing.

    The adversarial reading is the reason this is pinned separately: a chain
    truncated immediately after a disclosure is byte-for-byte an honest live tail,
    so this test is also the assertion that truncation buys an adversary an
    advisory, never an outcome. Re-verification after resumption upgrades or
    impeaches the disclosure on the seal that then exists.
    """
    sealed = json.loads((FIXTURE_DIR / "01-gap-disclosed-valid.json").read_text())
    tail = json.loads((FIXTURE_DIR / "17-gap-disclosure-at-unsealed-tail.json").read_text())
    assert sealed["gap_disclosure"] == tail["gap_disclosure"], (
        "the contrast only isolates the seal if the disclosures are identical"
    )

    sealed_result = verify_gap_disclosure(
        sealed["gap_disclosure"], sealed["context"], sealed["trusted_issuer_keys"]
    )
    tail_result = verify_gap_disclosure(
        tail["gap_disclosure"], tail["context"], tail["trusted_issuer_keys"]
    )
    assert sealed_result["status"] == DISCLOSED
    assert tail_result["status"] == UNVERIFIED
    assert tail_result["failures"] == []
    assert tail_result["warnings"] == ["disclosure_not_yet_sealed"]


def test_every_registered_rule_is_load_bearing_for_two_fixtures() -> None:
    """Two independent vectors per rule (#124), enforced rather than remembered.

    Each code must decide at least two fixtures' expected outcomes. The unknown-key
    advisory and the tail advisory are counted from warnings; failure codes from
    failures. A rule below two vectors is a rule one fixture regression away from
    being unenforced."""
    counts: dict[str, int] = {}
    for path in FIXTURES:
        expected = json.loads(path.read_text())["expected"]
        for code in [*expected["failures"], *expected["warnings"]]:
            if code != DISCLOSED:
                counts[code] = counts.get(code, 0) + 1
    registered = {rule.code for rule in RULES} | {
        "disclosure_signature_invalid",
        "disclosure_key_unknown",
        "disclosure_not_yet_sealed",
    }
    assert set(counts) == registered, (
        f"codes in fixtures and codes registered diverge: {sorted(set(counts) ^ registered)}"
    )
    thin = {code: n for code, n in counts.items() if n < 2}
    assert not thin, f"rules below the two-vector margin: {thin}"

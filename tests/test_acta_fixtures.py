"""Conformance checks for the Acta action-receipt fixtures.

Validates every fixture in examples/action-receipts/acta/ against
draft-farley-acta-signed-receipts-02 (fixtures 01 to 06) or its revision 03
(07 to 11) and against the expected positive/negative results declared in
expected.json, column by column, so envelope or fixture drift fails CI instead
of passing silently.

The signature and chain checks are the ones tools/acta_receipt_verifier.py
applies to any receipt, so these fixtures and the verifier cannot drift apart.
That module uses only dependencies this project already declares: rfc8785 for
JCS canonicalization and cryptography for Ed25519 verification.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tools.acta_receipt_verifier import chain_link_matches, envelope_hash, jcs, signature_verifies

ACTA_DIR = Path(__file__).resolve().parents[1] / "examples" / "action-receipts" / "acta"
EXPECTED = json.loads((ACTA_DIR / "expected.json").read_text(encoding="utf-8"))
FIXTURES = sorted(p.name for p in ACTA_DIR.glob("[0-9][0-9]-*.json"))
REVISION_03 = [name for name in FIXTURES if int(name[:2]) >= 7]

SIGNER_KEY = Ed25519PublicKey.from_public_bytes(
    bytes.fromhex(EXPECTED["signer_public_key_hex"])
)


def _load(name: str) -> dict:
    return json.loads((ACTA_DIR / name).read_text(encoding="utf-8"))


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def _key_window(kid: str) -> tuple[datetime, datetime]:
    """``valid_from`` and ``valid_until`` of the key the committed key set gives ``kid``."""
    (jwk,) = [key for key in _load(EXPECTED["key_set"])["keys"] if key["kid"] == kid]
    return _utc(jwk["valid_from"]), _utc(jwk["valid_until"])


def _signature_verifies(envelope: dict) -> bool:
    return signature_verifies(envelope, SIGNER_KEY)


def test_expected_manifest_covers_all_fixtures():
    assert set(EXPECTED["results"]) == set(FIXTURES)


@pytest.mark.parametrize("name", FIXTURES)
def test_envelope_structure(name):
    """Draft-02 s2: exactly {payload, signature{alg,kid,sig}}; s2.2: issuer_id == kid."""
    env = _load(name)
    assert set(env) == {"payload", "signature"}
    assert set(env["signature"]) == {"alg", "kid", "sig"}
    assert env["signature"]["alg"] == "EdDSA"
    assert re.fullmatch(r"[0-9a-f]{128}", env["signature"]["sig"])
    payload = env["payload"]
    assert payload["type"] == "protectmcp:decision"
    # require_approval is the value revision 03 adds (s3.1.1).
    assert payload["decision"] in {"allow", "deny", "rate_limit", "require_approval"}
    assert payload["issuer_id"] == env["signature"]["kid"]
    datetime.fromisoformat(payload["issued_at"])  # RFC 3339 with Z parses in 3.11+
    assert payload["issued_at"].endswith("Z")


@pytest.mark.parametrize("name", FIXTURES)
def test_signature_result_matches_expected(name):
    """Draft-02 s5.6: PureEdDSA over JCS(payload), key resolved from kid (not the receipt)."""
    expected = EXPECTED["results"][name]["signature"]
    actual = "pass" if _signature_verifies(_load(name)) else "fail"
    assert actual == expected, f"{name}: signature check {actual}, expected {expected}"


@pytest.mark.parametrize("name", sorted(EXPECTED["chain"]))
def test_chain_link_result_matches_expected(name):
    """Draft-02 s5.7: previousReceiptHash = SHA-256(JCS(entire predecessor envelope)).

    Revision 03 s6.7 writes the same digest with a ``sha256:`` prefix (08, 09).
    This is a distinct check from signature verification: fixtures 04 and 09 are
    validly signed and must PASS the signature check while FAILING here.
    """
    env = _load(name)
    predecessor = _load(EXPECTED["chain"][name])
    link = env["payload"].get("previousReceiptHash")
    actual = "pass" if chain_link_matches(link, predecessor) else "fail"
    assert actual == EXPECTED["results"][name]["chain"]


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_policy_freshness_result_matches_expected(name):
    """Every fixture's declared freshness, not only the one meant to fail it.

    Asserting the failure alone passes whether one fixture is stale or all of them
    are, which is how the set came to share a single ``policy_digest`` while four
    fixtures were declared to pass a comparison they failed.
    """
    declared = EXPECTED["results"][name]["policy_freshness"]
    if declared == "n/a":
        return
    env = _load(name)
    fresh = env["payload"]["policy_digest"] == EXPECTED["current_policy_digest"]
    assert ("pass" if fresh else "fail") == declared


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_session_binding_result_matches_expected(name):
    declared = EXPECTED["results"][name]["session_binding"]
    if declared == "n/a":
        return
    env = _load(name)
    actual = "pass" if env["payload"]["session_id"] == EXPECTED["expected_session_id"] else "fail"
    assert actual == declared


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_signing_input_result_matches_expected(name):
    """Revision 03 s6.6: the payload carries no ``signature`` member, not even ``null``.

    The shared signature helper does not apply this rule, which is why 10 passes
    ``test_signature_result_matches_expected``: its Ed25519 signature is valid.
    """
    declared = EXPECTED["results"][name]["signing_input"]
    if declared == "n/a":
        return
    actual = "fail" if "signature" in _load(name)["payload"] else "pass"
    assert actual == declared


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_key_window_result_matches_expected(name):
    """Revision 03 s9.2, read against ``issued_at``: ``valid_from`` <= issued_at < ``valid_until``.

    The comparison is made here, against the window the committed key set gives the
    fixture's ``kid``; the shared helpers take no window.
    """
    declared = EXPECTED["results"][name]["key_window"]
    if declared == "n/a":
        return
    env = _load(name)
    valid_from, valid_until = _key_window(env["signature"]["kid"])
    inside = valid_from <= _utc(env["payload"]["issued_at"]) < valid_until
    assert ("pass" if inside else "fail") == declared


def test_no_fixture_is_issued_near_an_end_of_its_key_window():
    """s9.2 does not say whether an end of the window is inclusive.

    Every fixture is issued at least a day from both ends, so no declared
    ``key_window`` result depends on that reading.
    """
    for name in FIXTURES:
        env = _load(name)
        issued = _utc(env["payload"]["issued_at"])
        ends = _key_window(env["signature"]["kid"])
        assert min(abs(issued - end) for end in ends) >= timedelta(days=1), name


@pytest.mark.parametrize("name", sorted(set(EXPECTED["chain"]) & set(REVISION_03)))
def test_revision_03_links_carry_the_sha256_prefix(name):
    """Revision 03 s6.7: the link MUST be ``sha256:`` and 64 lowercase hex digits.

    No verdict shows this, because a verifier MAY still accept the bare hex of
    revision 02 that 02 and 04 carry.
    """
    link = _load(name)["payload"]["previousReceiptHash"]
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", link)


def test_the_two_distinguishing_fixtures_are_otherwise_valid():
    """05 and 06 must isolate their own axis: signature passes, one comparison fails."""
    for name in ("05-stale-policy-digest.json", "06-session-binding-mismatch.json"):
        assert _signature_verifies(_load(name)), f"{name} must pass signature verification"


# Each revision 03 negative: the valid fixture it was made from, the one payload member
# it changes (10 adds its member; the others alter one), and the column that member fails.
REVISION_03_NEGATIVES = {
    "09-payload-only-chain-link.json": (
        "08-valid-prefixed-chain-link.json", "previousReceiptHash", "chain"
    ),
    "10-signature-member-in-payload.json": (
        "07-valid-inside-key-window.json", "signature", "signing_input"
    ),
    "11-outside-key-window.json": ("07-valid-inside-key-window.json", "issued_at", "key_window"),
}
_ABSENT = object()


@pytest.mark.parametrize("name", sorted(REVISION_03_NEGATIVES))
def test_each_revision_03_negative_changes_one_member_and_fails_only_its_rule(name):
    """09, 10 and 11 differ from a valid fixture in one payload member, absent ones included.

    The column that member breaks is the only one declared ``fail``, and the tests
    above check every declared column against the fixture itself.
    """
    twin, member, column = REVISION_03_NEGATIVES[name]
    negative, valid = _load(name)["payload"], _load(twin)["payload"]
    changed = {
        key
        for key in negative.keys() | valid.keys()
        if negative.get(key, _ABSENT) != valid.get(key, _ABSENT)
    }
    assert changed == {member}
    assert "fail" not in EXPECTED["results"][twin].values(), f"{twin} must be valid"
    failing = [check for check, result in EXPECTED["results"][name].items() if result == "fail"]
    assert failing == [column]


def test_crosswalk_document_quotes_the_live_fixture_values():
    """The crosswalk embeds real digests and says so; regenerating must not falsify that.

    ``docs/crosswalks/acta-decision-receipts.md`` quotes 01 in full and states that the
    ``chain_head`` it shows "is real". Both go stale the moment the fixtures are
    regenerated, and nothing else would notice.
    """
    doc = (Path(__file__).resolve().parents[1] / "docs" / "crosswalks").joinpath(
        "acta-decision-receipts.md"
    ).read_text(encoding="utf-8")
    r01 = _load("01-valid-accepted.json")
    chain_head = envelope_hash(_load("02-valid-denied.json"))

    assert r01["payload"]["policy_digest"] in doc, "the quoted 01 payload is stale"
    assert r01["signature"]["sig"][:64] in doc, "the quoted 01 signature is stale"
    assert chain_head in doc, "the quoted chain head is not 02's current envelope hash"


def test_key_mismatch_fixture_is_signed_by_the_committed_second_key():
    """03 is a real signature by the committed mismatched key, not random bytes."""
    env = _load("03-signature-key-mismatch.json")
    other = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(
            (ACTA_DIR / "mismatched-signer-public-key.txt").read_text(encoding="utf-8").strip()
        )
    )
    other.verify(bytes.fromhex(env["signature"]["sig"]), jcs(env["payload"]))

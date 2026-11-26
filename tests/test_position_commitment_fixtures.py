"""A position in an externally ordered sequence as a `position-commitment` entry
validated by recomputation (spec section 3.1.2, v0.3 draft, #321).

Re-verifies examples/position-commitment/ from the committed bytes. The generator wrote
expected.json alongside the vectors, and a generator's own summary of its output is a
claim, so every outcome here is recomputed with this repository's dependencies and
compared with expected.json, never read from it. The generator is deterministic, and
the last test re-runs it against the committed files.

The records use `validation: "recompute"`, which the v0.2 schema refuses, so
`verify_record()` cannot check them: each is validated against the v0.3 draft schema
and its signature checked with the SDK's own canonicalization, as
tests/test_runtime_evidence_vectors.py does for the other v0.3 draft set.
"""

from __future__ import annotations

import base64
import binascii
import copy
import functools
import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import jsonschema
import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace.sign import JCS_SAFE_INTEGER, _canonical_bytes

REPO = Path(__file__).resolve().parents[1]
DIR = REPO / "examples" / "position-commitment"
GENERATOR = DIR / "gen_position_commitment_vectors.py"
EXPECTED = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
RELYING_PARTY = json.loads((DIR / "relying-party.json").read_text(encoding="utf-8"))
DRAFT = json.loads((REPO / "schema" / "trace-claim-v0.3-draft.json").read_text(encoding="utf-8"))
V02 = json.loads((REPO / "schema" / "trace-claim.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
OUTCOME_KEYS = (
    "proof_held",
    "commitment_recomputes",
    "binds_this_record",
    "committer_key_independent",
    "committer_identity_matches",
    "signatures_verify",
    "sequence_position_matches",
    "verdict",
)


def _load(name: str) -> dict:
    return json.loads((DIR / name).read_text(encoding="utf-8"))


def _jcs_sha256(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


# Section 3.1.3 permits SHA-256 or SHA-384, and "the digest algorithm named in the
# prefix MUST match the algorithm used, and a verifier MUST reject a record whose
# prefix names an algorithm it does not support rather than fall back to another."
# `06-sha384-commitment.json` is this set's only SHA-384 case; `_jcs_sha256` above is
# kept as-is for the SHA-256 cases and the fixtures that build raw `sha256:` values by
# hand, so none of those recomputations change shape.
_DIGEST_ALGORITHMS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384}


def _digest_matches(obj: object, prefixed: str) -> bool:
    """`obj` is `slot` or `record`, read from a proof a holder supplied; `_canonical_bytes`
    is used rather than raw `rfc8785.dumps` so a value neither canonicalizes, such as a
    non-finite number a permissive JSON parser admitted, raises the single
    `rfc8785.CanonicalizationError` `_recompute` already catches, the same as every
    other value JCS has no form for -- not a bare, differently-shaped exception from
    this one call site."""
    algorithm, _, _ = prefixed.partition(":")
    hasher = _DIGEST_ALGORITHMS.get(algorithm)
    if hasher is None:
        return False
    return f"{algorithm}:" + hasher(_canonical_bytes(obj)).hexdigest() == prefixed


def _b64u_decode(text: str) -> bytes:
    """Strict unpadded base64url, not merely permissive decoding. Python's own
    `urlsafe_b64decode` "discards" (its own documentation's word) any character
    outside the base64url alphabet before checking padding, so a string with stray
    characters spliced into an otherwise valid encoding, or one that substitutes the
    standard `+`/`/` alphabet for `-`/`_`, decodes to the same bytes as the clean
    canonical original instead of being refused (review on the third round:
    `"YWJj!!!!"` decodes to the same `b"abc"` as `"YWJj"`). Re-encoding the decoded
    bytes and comparing the result to the input catches all three at once -- stray
    characters, the wrong alphabet, and non-canonical padding or unused trailing
    bits -- without hand-rolling a validator for each: whatever this round-trips to
    is the one canonical base64url spelling of those bytes, and anything else was
    never that spelling to begin with.
    """
    decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != text:
        raise ValueError(f"not canonical base64url: {text!r}")
    return decoded


def _thumbprint(jwk: dict) -> str:
    required = {k: jwk[k] for k in ("crv", "kty", "x")}
    raw = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()


def _signed_by(obj: dict, jwk: dict) -> bool:
    """`obj` is `slot` or `binding`, read from a proof a holder supplied. `_canonical_bytes`,
    not raw `rfc8785.dumps`, for the reason `_digest_matches` gives: a value elsewhere
    in `obj` that cannot be canonicalized must raise the one exception `_recompute`
    catches, not crash this call differently than that one does."""
    body = {k: v for k, v in obj.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"])).verify(
            _b64u_decode(obj["signature"]), _canonical_bytes(body)
        )
    except InvalidSignature:
        return False
    return True


# The one proof wire format this verifier implements (examples/position-commitment/
# gen_position_commitment_vectors.py and every committed proof-*.json). The registry
# deliberately leaves the sequence and the committer free to define their own wire
# format for the proof a holder carries, so an unrecognized `type` is not a forgery;
# it is a format this verifier was never taught to read, and it gets the same
# "unusable" outcome as a proof this verifier was taught to read but that arrived
# truncated or malformed. Either way nothing is recomputed, and that is the fact the
# verdict has to carry rather than crashing or guessing a shape onto the bytes.
_SUPPORTED_PROOF_TYPE = "position-commitment-proof"
# The registry (docs/references-registry.md, "The referenced object") requires four
# facts of the proof, one of them "the committing party: an identifier and a reference
# to its verification key". The wire format in examples/position-commitment/ carries
# that as two separate strings -- `committer` (the identifier) and `committer_key_id`
# (the key reference) -- not one; an earlier pass of this gate required only the
# latter, which left a slot with no committing-party identifier structurally
# "usable" (review on #595).
_REQUIRED_SLOT_STRINGS = (
    "sequence",
    "sequence_value",
    "committer",
    "committer_key_id",
    "signature",
)
_REQUIRED_BINDING_STRINGS = ("slot_commitment", "record_digest", "committer_key_id", "signature")


def _proof_is_usable(proof: dict) -> bool:
    """Structural gate before `_recompute` reaches into `proof["slot"]["..."]` and
    `proof["binding"]["..."]`. Section 3.1.2 rule 3 names exactly two outcomes for a
    recompute entry: the evidence is not held (absent), or it was recomputed and
    disagreed (contradiction). A proof that *is* held but cannot be parsed or
    interpreted -- a missing or wrong-shaped `slot`/`binding`/`committer_jwk`, or a
    `type` this verifier does not implement -- is neither: nothing is recomputed, so
    it is not a contradiction, and reporting it as a contradiction would fail a
    record over bytes the verifier never actually checked. It is kept distinct from
    `position-absent` (case 03, no proof at all) only in the verdict string, per the
    review on #595: the two must not collapse into one reason a relying party cannot
    tell apart.
    """
    if not isinstance(proof, dict):
        return False
    if proof.get("type") != _SUPPORTED_PROOF_TYPE:
        return False
    slot = proof.get("slot")
    if not isinstance(slot, dict) or slot.get("type") != "position-slot":
        return False
    # A required string must also be non-empty: an empty `committer` is not an
    # identifier, and the same holds for an empty signature or sequence id. The
    # structural check alone -- `isinstance(..., str)` -- let `""` through (review on
    # the second round).
    if any(not isinstance(slot.get(k), str) or slot.get(k) == "" for k in _REQUIRED_SLOT_STRINGS):
        return False
    # Section 3.2.2, "What counts as an integer": integer-by-value, not by JSON
    # spelling -- `8812`, `8812.0`, and `8.812e3` are the same integer, and RFC 8785
    # canonicalizes all three to the same form. A verifier that accepts only
    # Python's own `int` type rejects the latter two as unusable, disagreeing with
    # its own spec the same way the first round's JWK fix was written to stop (review
    # on the third round). `bool` is still rejected: it is an `int` subclass in
    # Python and not a sequence position in JSON. A position outside the JCS
    # safe-integer domain cannot be canonicalized and compared without ambiguity, the
    # same domain `_is_canonicalizable_value` in models.py holds a JWK's extra
    # members to.
    position = slot.get("position")
    if isinstance(position, bool):
        return False
    if isinstance(position, float) and position.is_integer():
        position = int(position)
    if not isinstance(position, int):
        return False
    if not -JCS_SAFE_INTEGER <= position <= JCS_SAFE_INTEGER:
        return False
    binding = proof.get("binding")
    if not isinstance(binding, dict) or binding.get("type") != "position-binding":
        return False
    if any(not isinstance(binding.get(k), str) for k in _REQUIRED_BINDING_STRINGS):
        return False
    committer_jwk = proof.get("committer_jwk")
    if not isinstance(committer_jwk, dict):
        return False
    if any(not isinstance(committer_jwk.get(k), str) for k in ("kty", "crv", "x")):
        return False
    # This verifier implements exactly one key type, the one every committed proof
    # uses; a `committer_jwk` of another type is a format it was never taught to
    # read, same as an unrecognized `type` above -- unusable, not a forged signature.
    if (committer_jwk.get("kty"), committer_jwk.get("crv")) != ("OKP", "Ed25519"):
        return False
    # `_signed_by` hands `x` and each `signature` straight to base64url decoding and
    # an Ed25519 constructor that only checks length, not shape -- a syntactically
    # fine but undecodable or wrong-length value raises `binascii.Error` or
    # `ValueError` there uncaught. Review on #595 (malformed key: `x="a"` fails to
    # decode at all; `x="abc"` decodes to 2 bytes, not the 32 Ed25519 requires).
    # Checked once here, for the one key and the two signatures, so `_signed_by`
    # never has to re-validate what this gate has already let through.
    try:
        x_len = len(_b64u_decode(committer_jwk["x"]))
        slot_sig_len = len(_b64u_decode(slot["signature"]))
        binding_sig_len = len(_b64u_decode(binding["signature"]))
    except (ValueError, binascii.Error):
        return False
    if x_len != 32 or slot_sig_len != 64 or binding_sig_len != 64:
        return False
    return True


def _record_verifies(record: dict) -> None:
    """The v0.3 draft envelope: schema-valid, and signed under the key the relying party
    holds for the producer, not the one the record embeds."""
    jsonschema.validate(record, DRAFT)
    jwk = EXPECTED["trace_signer_jwk"]
    assert record["cnf"]["jwk"] == jwk
    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"])).verify(
        _b64u_decode(record["signature"]), body
    )


def _recompute(record: dict, proof: dict | None, relying_party: dict) -> dict:
    """What a relying party concludes from a `position-commitment` entry.

    Section 3.1.2, "Entries validated by recomputation": not holding the proof makes the
    entry absent, which is no finding against the record; a recomputation that runs and
    disagrees is a contradiction and is never reported as an absence. Agreement under a
    committer key the proof supplies for itself is consistency only: ordering is
    established only under a key and a sequence the relying party holds independently.

    A proof that is held but cannot be parsed -- malformed, truncated, or in a format
    this verifier does not implement -- is a third outcome the rule above does not
    name directly: it is not absent (the holder did carry something) and it is not a
    contradiction (nothing was recomputed to disagree with anything). See
    `_proof_is_usable`.
    """
    (entry,) = record["references"]
    assert entry["rel"] == "position-commitment"
    assert entry["validation"] == "recompute"
    assert "resolver" not in entry and "retention" not in entry
    result = dict.fromkeys(OUTCOME_KEYS)
    if proof is None:
        return {**result, "proof_held": False, "verdict": "position-absent"}
    result["proof_held"] = True
    if not _proof_is_usable(proof):
        return {**result, "verdict": "position-absent-proof-unusable"}
    slot, binding = proof["slot"], proof["binding"]
    try:
        return _recompute_usable(record, entry, slot, binding, proof, relying_party, result)
    except rfc8785.CanonicalizationError:
        # `_proof_is_usable` validates every field the recomputation itself reads;
        # it does not walk every additional member a producer might have put
        # elsewhere in `slot` or `binding`. A non-finite number a permissive JSON
        # parser admits, an unpaired surrogate, or nesting deep enough to exhaust
        # the canonicalizer all fail here, inside `_canonical_bytes`, rather than at
        # that gate -- possibly after `_recompute_usable` has already set some of
        # `result`'s other keys from a check that ran before the one that failed. A
        # partial, un-crashed-at-the-time check is not a weaker finding than a check
        # that never started: every key but `proof_held` is reset to `None`, so this
        # case is reported exactly as any other unusable proof is, whatever progress
        # happened to be made before the value that could not be interpreted was
        # reached. Nothing was recomputed with any confidence, so it is not a
        # contradiction either.
        return {
            **dict.fromkeys(OUTCOME_KEYS),
            "proof_held": True,
            "verdict": "position-absent-proof-unusable",
        }


def _recompute_usable(
    record: dict,
    entry: dict,
    slot: dict,
    binding: dict,
    proof: dict,
    relying_party: dict,
    result: dict,
) -> dict:
    """The rest of `_recompute`, once `_proof_is_usable` has passed: every value this
    function and its helpers canonicalize can still raise `rfc8785.CanonicalizationError`
    for a member that gate does not check (see the docstring at the call site)."""
    # `entry["id"]`'s own prefix names the algorithm; an unrecognized one never
    # matches rather than being retried under SHA-256 (section 3.1.3, quoted above
    # `_digest_matches`).
    result["commitment_recomputes"] = _digest_matches(slot, entry["id"])
    if not result["commitment_recomputes"]:
        return {**result, "verdict": "contradiction-commitment-mismatch"}

    # Section 3.1.3's preimage: the complete record as published, signature included.
    result["binds_this_record"] = binding["slot_commitment"] == entry["id"] and _digest_matches(
        record, binding["record_digest"]
    )
    if not result["binds_this_record"]:
        return {**result, "verdict": "contradiction-commits-another-record"}

    kid = slot["committer_key_id"]
    independent = relying_party["committer_keys"].get(kid)
    result["committer_key_independent"] = independent is not None
    # Trusting a key and knowing who holds it are different facts (registry, "The
    # referenced object": a reference to the verification key is one required fact,
    # an identifier for the committing party is another). `slot["committer"]` is
    # signed, so a proof cannot change it without invalidating the signature, but
    # nothing before this point has checked it says what the relying party expects
    # for this specific key -- a key it independently trusts can still sign a slot
    # naming a different committer, and that was previously accepted as consistent.
    # With no independently trusted key (case 05's shape), there is no independent
    # identity to check the claim against either, so this is `False` the same way
    # `committer_key_independent` is: nothing here is established independently of
    # the proof.
    result["committer_identity_matches"] = (
        independent is not None and independent.get("committer") == slot["committer"]
    )
    if independent is not None and not result["committer_identity_matches"]:
        return {**result, "verdict": "contradiction-committer-identity-mismatch"}
    jwk = independent if independent is not None else proof["committer_jwk"]
    if _thumbprint(jwk) != kid or binding["committer_key_id"] != kid:
        return {**result, "signatures_verify": False, "verdict": "contradiction-signature-invalid"}
    result["signatures_verify"] = _signed_by(slot, jwk) and _signed_by(binding, jwk)
    if not result["signatures_verify"]:
        return {**result, "verdict": "contradiction-signature-invalid"}

    sequence = relying_party["sequence"]
    # `_proof_is_usable` has already established `slot["position"]` is, by value, a
    # safe integer -- `int` or an integral `float` such as `8812.0` -- so normalizing
    # with `int()` before building the lookup key treats both spellings alike. Without
    # it, `str(8812.0)` is `"8812.0"`, which no key in `positions` would ever match,
    # silently turning an accepted float position into a sequence mismatch.
    result["sequence_position_matches"] = (
        slot["sequence"] == sequence["id"]
        and sequence["positions"].get(str(int(slot["position"]))) == slot["sequence_value"]
    )
    # The sequence is the relying party's own independent copy, held regardless of
    # which key signed the slot, so a value it disagrees with is a contradiction
    # whether or not the committer key is independently trusted. Rule 3 ("recompute
    # entries") never softens a disagreement to an absence or a lesser outcome, and an
    # untrusted-key verdict is exactly that: checking committer-key independence first
    # let an independently-held sequence mismatch be swallowed by it. The key verdict
    # only decides what a *matching* sequence establishes (trust vs. mere
    # consistency); it does not gate whether a mismatch is reported at all.
    if not result["sequence_position_matches"]:
        return {**result, "verdict": "contradiction-sequence-mismatch"}
    if not result["committer_key_independent"]:
        return {**result, "verdict": "position-consistent-not-established"}
    return {**result, "verdict": "position-established"}


def _case(name: str) -> dict:
    case = EXPECTED["cases"][name]
    proof = _load(case["proof"]) if case["proof"] else None
    return _recompute(_load(name), proof, RELYING_PARTY)


def test_the_committed_records_are_exactly_the_declared_cases() -> None:
    assert {p.name for p in DIR.glob("0*.json")} == set(CASES)
    for case in EXPECTED["cases"].values():
        assert case["proof"] is None or (DIR / case["proof"]).is_file()


@pytest.mark.parametrize("name", CASES)
def test_every_case_verifies_as_a_v03_draft_trust_record(name: str) -> None:
    # What the entry recomputes to never decides whether the signature verifies: the
    # contradiction cases are signed records too, and the contradiction is reported.
    _record_verifies(_load(name))
    assert EXPECTED["cases"][name]["record_signature_verifies"] is True


@pytest.mark.parametrize("name", CASES)
def test_v02_refuses_every_record_in_the_set(name: str) -> None:
    """The version gate: recompute entries are a v0.3 draft shape only."""
    record = _load(name)
    record["eat_profile"] = V02["properties"]["eat_profile"]["const"]
    assert list(jsonschema.Draft202012Validator(V02).iter_errors(record))


@pytest.mark.parametrize("name", CASES)
def test_the_outcome_is_recomputed_from_the_committed_bytes(name: str) -> None:
    case = EXPECTED["cases"][name]
    assert _case(name) == {k: case[k] for k in OUTCOME_KEYS}


def test_absence_and_contradiction_are_different_answers() -> None:
    """Section 3.1.2 rule 3 of the recompute entries: no proof is absent, a proof that
    disagrees is a contradiction, and neither is reported as the other."""
    assert _case("03-proof-not-held.json")["verdict"] == "position-absent"
    for name in ("02-same-proof-other-record.json", "04-proof-altered.json"):
        verdict = _case(name)["verdict"]
        assert verdict.startswith("contradiction-"), name
        assert _case(name)["proof_held"] is True


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda p: p.pop("binding"), id="missing-binding"),
        pytest.param(lambda p: p.__setitem__("binding", []), id="binding-is-a-list"),
        pytest.param(lambda p: p.__setitem__("binding", {}), id="binding-is-empty"),
        pytest.param(lambda p: p.pop("slot"), id="missing-slot"),
        pytest.param(
            lambda p: p["slot"].pop("committer_key_id"), id="slot-missing-committer-key-id"
        ),
        pytest.param(lambda p: p["slot"].pop("signature"), id="slot-missing-signature"),
        pytest.param(lambda p: p["slot"].pop("committer"), id="slot-missing-committer"),
        pytest.param(
            lambda p: p["slot"].__setitem__("committer", ""), id="slot-committer-is-empty"
        ),
        pytest.param(
            lambda p: p.__setitem__("type", "position-commitment-proof-v999"),
            id="unsupported-proof-type",
        ),
        pytest.param(lambda p: p.pop("committer_jwk"), id="missing-committer-jwk"),
        pytest.param(
            lambda p: p["slot"].__setitem__("position", JCS_SAFE_INTEGER + 1),
            id="position-above-the-safe-integer-range",
        ),
        pytest.param(
            lambda p: p["slot"].__setitem__("position", -JCS_SAFE_INTEGER - 1),
            id="position-below-the-safe-integer-range",
        ),
        pytest.param(
            lambda p: p["committer_jwk"].__setitem__("x", "a"),
            id="committer-jwk-x-is-not-valid-base64url",
        ),
        pytest.param(
            # Decodes to 2 bytes, not the 32 an Ed25519 public key requires.
            lambda p: p["committer_jwk"].__setitem__(
                "x", base64.urlsafe_b64encode(b"ab").rstrip(b"=").decode()
            ),
            id="committer-jwk-x-decodes-to-the-wrong-length",
        ),
        pytest.param(
            lambda p: p["slot"].__setitem__("signature", "not valid base64url!!"),
            id="slot-signature-is-not-valid-base64url",
        ),
        pytest.param(
            lambda p: p["slot"].__setitem__(
                "signature", base64.urlsafe_b64encode(b"short").rstrip(b"=").decode()
            ),
            id="slot-signature-decodes-to-the-wrong-length",
        ),
        pytest.param(
            lambda p: p["binding"].__setitem__("signature", "not valid base64url!!"),
            id="binding-signature-is-not-valid-base64url",
        ),
        pytest.param(
            lambda p: p["committer_jwk"].__setitem__("kty", "RSA"),
            id="committer-jwk-is-not-the-supported-okp-ed25519-type",
        ),
        pytest.param(
            # Decodes to the right 32 bytes, with four extra characters outside the
            # base64url alphabet discarded along the way rather than rejected --
            # `base64.urlsafe_b64decode`'s own documented behavior.
            lambda p: p["committer_jwk"].__setitem__(
                "x", p["committer_jwk"]["x"][:-4] + "!!!!" + p["committer_jwk"]["x"][-4:]
            ),
            id="committer-jwk-x-has-stray-characters-spliced-in",
        ),
        pytest.param(
            # The same 32 bytes, spelled with the standard `+`/`/` alphabet in place
            # of base64url's `-`/`_` wherever the original uses one.
            lambda p: p["committer_jwk"].__setitem__(
                "x", p["committer_jwk"]["x"].replace("-", "+").replace("_", "/")
            ),
            id="committer-jwk-x-uses-the-standard-alphabet-not-base64url",
        ),
        pytest.param(
            # Decodes to the right 64 bytes; the extra padding is simply not part of
            # this wire format's unpadded convention.
            lambda p: p["slot"].__setitem__("signature", p["slot"]["signature"] + "=="),
            id="slot-signature-has-non-canonical-padding",
        ),
        pytest.param(
            # `_proof_is_usable` checks every required field, not every field. An
            # additional member elsewhere in `slot` is outside that gate, and a
            # non-finite float -- which `json.loads` admits as a legal extension,
            # the spec's wire format does not -- has no RFC 8785 form at all.
            lambda p: p["slot"].__setitem__("note", float("nan")),
            id="slot-has-an-additional-member-with-a-non-finite-value",
        ),
        pytest.param(
            lambda p: p["binding"].__setitem__("note", float("inf")),
            id="binding-has-an-additional-member-with-a-non-finite-value",
        ),
        pytest.param(
            # Nested well past the interpreter's recursion limit; `_canonical_bytes`
            # reports this the same way it reports every other value JCS has no form
            # for, not a bare `RecursionError`.
            lambda p: p["slot"].__setitem__(
                "note", functools.reduce(lambda inner, _: [inner], range(10_000), "x")
            ),
            id="slot-has-an-additional-member-nested-past-the-recursion-limit",
        ),
    ],
)
def test_a_held_but_unusable_proof_is_neither_absent_nor_a_contradiction(
    mutate: Callable[[dict], None],
) -> None:
    """Findings from the Nov 2/Nov 6 reviews of #595 (drk-ram, chernistry): a proof the
    verifier holds but cannot parse or interpret must not crash `_recompute` (a
    `KeyError`/`TypeError` is not a conformance outcome), must not be reported as
    `position-established` (an unrecognized `type` must not be silently accepted),
    and must not collapse into `position-absent` (case 03) -- the relying party did
    receive bytes, which is a different fact than receiving nothing."""
    record = _load("01-position-established.json")
    proof = copy.deepcopy(_load("proof-01.json"))
    mutate(proof)
    observed = _recompute(record, proof, RELYING_PARTY)
    assert observed["proof_held"] is True
    assert observed["verdict"] == "position-absent-proof-unusable"
    assert observed["commitment_recomputes"] is None, "nothing was recomputed"


def test_the_same_proof_on_another_record_fails_only_on_the_binding() -> None:
    """`02` carries `01`'s entry byte for byte and is handed `01`'s proof. The commitment
    recomputes, so a check that stopped at the slot would pass it; only the record
    digest the binding commits tells the two records apart."""
    first, second = _load("01-position-established.json"), _load("02-same-proof-other-record.json")
    assert first["references"] == second["references"]
    assert _jcs_sha256(first) != _jcs_sha256(second)
    proof = _load("proof-01.json")
    assert proof["binding"]["record_digest"] == _jcs_sha256(first)
    observed = _recompute(second, proof, RELYING_PARTY)
    assert observed["commitment_recomputes"] is True
    assert observed["binds_this_record"] is False


def test_the_altered_proof_differs_in_the_position_only() -> None:
    original, altered = _load("proof-04.json"), _load("proof-04-altered.json")
    assert original["binding"] == altered["binding"]
    changed = [k for k in original["slot"] if original["slot"][k] != altered["slot"][k]]
    assert changed == ["position"]
    assert altered["slot"]["position"] < original["slot"]["position"]
    # The unaltered proof establishes the position, so the alteration is the whole cause.
    record = _load("04-proof-altered.json")
    assert _recompute(record, original, RELYING_PARTY)["verdict"] == "position-established"


def test_a_self_supplied_key_is_consistency_not_ordering() -> None:
    """`05` checks out on every digest and both signatures under the key its proof
    carries. Handing the relying party that key would make it `position-established`,
    which is the step a verifier must not take on the proof's word."""
    record, proof = _load("05-committer-key-self-supplied.json"), _load("proof-05.json")
    assert proof["slot"]["committer_key_id"] not in RELYING_PARTY["committer_keys"]
    trusting = copy.deepcopy(RELYING_PARTY)
    trusting["committer_keys"][proof["slot"]["committer_key_id"]] = {
        "committer": proof["slot"]["committer"],
        **proof["committer_jwk"],
    }
    assert _recompute(record, proof, trusting)["verdict"] == "position-established"
    assert _recompute(record, proof, RELYING_PARTY)["verdict"] == (
        "position-consistent-not-established"
    )


def test_a_self_supplied_key_does_not_soften_a_sequence_mismatch() -> None:
    """A proof whose committer key is self-supplied (05) is `position-consistent-not-
    established` when its sequence value agrees with the relying party's own copy
    (`test_a_self_supplied_key_is_consistency_not_ordering`). It must not stay that
    verdict when the two disagree: the relying party's sequence is independent of
    whichever key signed the slot, and rule 3 never lets a disagreement with it be
    reported as a lesser outcome than a contradiction. Reproduces drk-ram's review of
    #595: change the relying party's value at position 8815 (05's position) and the
    verdict must move to `contradiction-sequence-mismatch`, not stay
    `position-consistent-not-established`."""
    record, proof = _load("05-committer-key-self-supplied.json"), _load("proof-05.json")
    position = str(proof["slot"]["position"])
    relying_party = copy.deepcopy(RELYING_PARTY)
    relying_party["sequence"]["positions"][position] = "sha256:" + "0" * 64
    observed = _recompute(record, proof, relying_party)
    assert observed["committer_key_independent"] is False
    assert observed["sequence_position_matches"] is False
    assert observed["verdict"] == "contradiction-sequence-mismatch"


def test_a_forged_slot_under_the_trusted_key_id_is_a_contradiction() -> None:
    """A proof that names the trusted committer's key id but carries its own key: the
    relying party checks against the key it holds, so the forgery does not verify."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agentrust_trace import key_to_jwk

    forger = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    kid = next(iter(RELYING_PARTY["committer_keys"]))
    proof = copy.deepcopy(_load("proof-01.json"))
    body = {k: v for k, v in proof["slot"].items() if k != "signature"}
    body["committer_key_id"] = kid
    proof["slot"] = {
        **body,
        "signature": base64.urlsafe_b64encode(forger.sign(rfc8785.dumps(body)))
        .rstrip(b"=")
        .decode(),
    }
    proof["committer_jwk"] = key_to_jwk(forger)
    record = copy.deepcopy(_load("01-position-established.json"))
    # Only the entry is under test here, so the record is not re-signed.
    record["references"][0]["id"] = _jcs_sha256(proof["slot"])
    proof["binding"]["slot_commitment"] = record["references"][0]["id"]
    proof["binding"]["record_digest"] = _jcs_sha256(record)
    observed = _recompute(record, proof, RELYING_PARTY)
    assert observed["committer_key_independent"] is True
    assert observed["signatures_verify"] is False
    assert observed["verdict"] == "contradiction-signature-invalid"


def test_sha384_commitment_establishes_the_position() -> None:
    """`06` exercises section 3.1.3's SHA-384 alternative end to end: the commitment,
    the record digest, and the binding's own copies of both all carry a `sha384:`
    prefix, and the position is established exactly as `01`'s SHA-256 case is."""
    record, proof = _load("06-sha384-commitment.json"), _load("proof-06.json")
    assert record["references"][0]["id"].startswith("sha384:")
    assert proof["binding"]["record_digest"].startswith("sha384:")
    observed = _recompute(record, proof, RELYING_PARTY)
    assert observed["commitment_recomputes"] is True
    assert observed["binds_this_record"] is True
    assert observed["verdict"] == "position-established"


def test_an_unsupported_digest_algorithm_is_not_retried_under_sha256() -> None:
    """Section 3.1.3: 'the digest algorithm named in the prefix MUST match the
    algorithm used, and a verifier MUST reject a record whose prefix names an
    algorithm it does not support rather than fall back to another.' A commitment
    whose prefix names an algorithm this verifier does not implement must therefore
    never match, even when the SHA-256 digest underneath it would have."""
    record = copy.deepcopy(_load("01-position-established.json"))
    proof = copy.deepcopy(_load("proof-01.json"))
    sha256_hex = record["references"][0]["id"].split(":", 1)[1]
    record["references"][0]["id"] = f"sha512:{sha256_hex}"
    observed = _recompute(record, proof, RELYING_PARTY)
    assert observed["commitment_recomputes"] is False
    assert observed["verdict"] == "contradiction-commitment-mismatch"


@pytest.mark.parametrize("position", [8812, 8812.0, 8.812e3])
def test_position_is_accepted_by_value_not_by_json_spelling(position: float) -> None:
    """Section 3.2.2, 'What counts as an integer': integer-by-value, not by JSON
    spelling. `8812`, `8812.0`, and `8.812e3` are the same integer, and RFC 8785
    canonicalizes all three to the identical `b'...8812...'` bytes -- confirmed
    directly below, not assumed. A structural gate that accepts only the first
    spelling disagrees with the spec it implements, the same way the first round's
    JWK fix was written to stop (review on the third round)."""
    assert rfc8785.dumps({"position": 8812}) == rfc8785.dumps({"position": position})
    proof = copy.deepcopy(_load("proof-01.json"))
    proof["slot"]["position"] = position
    assert _proof_is_usable(proof) is True


def test_an_integer_valued_float_position_establishes_the_same_position() -> None:
    """Carries the point above through the whole pipeline, not just the structural
    gate: because RFC 8785 canonicalizes `8812` and `8812.0` identically, the slot's
    existing signature -- computed over the canonical bytes, never the Python type --
    still verifies after this substitution, and the sequence lookup must key on the
    same normalized value the commitment digest already treats the two spellings as
    equal under."""
    record, proof = _load("01-position-established.json"), copy.deepcopy(_load("proof-01.json"))
    proof["slot"]["position"] = 8812.0
    observed = _recompute(record, proof, RELYING_PARTY)
    assert observed["verdict"] == "position-established"


def test_trusting_a_key_is_not_the_same_fact_as_trusting_who_holds_it() -> None:
    """`07` is validly signed by the one key `relying-party.json` independently
    trusts -- the signature and every digest check out -- but the signed `committer`
    field names a different identity than the one the relying party holds that key
    for. The registry requires both an identifier for the committing party and a
    reference to its verification key as independent facts; checking only the
    latter previously let a trusted key vouch for any identity a slot claimed under
    it. This is a contradiction, not the consistency-only outcome a self-supplied
    key gets, because the key here *is* independently trusted -- what fails is the
    identity it was asked to vouch for."""
    observed = _case("07-committer-identity-mismatch.json")
    assert observed["committer_key_independent"] is True
    assert observed["committer_identity_matches"] is False
    assert observed["verdict"] == "contradiction-committer-identity-mismatch"
    for name in ("01-position-established.json", "06-sha384-commitment.json"):
        established = _case(name)
        assert established["committer_key_independent"] is True
        assert established["committer_identity_matches"] is True


def test_a_slot_off_the_relying_partys_sequence_is_a_contradiction() -> None:
    """Under a trusted key, a slot whose sequence value is not the one the relying
    party's own copy holds at that position contradicts the sequence."""
    relying_party = copy.deepcopy(RELYING_PARTY)
    relying_party["sequence"]["positions"]["8812"] = "sha256:" + "0" * 64
    observed = _recompute(
        _load("01-position-established.json"), _load("proof-01.json"), relying_party
    )
    assert observed["sequence_position_matches"] is False
    assert observed["verdict"] == "contradiction-sequence-mismatch"


def test_the_record_signature_covers_the_entry() -> None:
    record = copy.deepcopy(_load("01-position-established.json"))
    commitment = record["references"][0]["id"]
    record["references"][0]["id"] = commitment[:-1] + ("0" if commitment[-1] != "0" else "1")
    with pytest.raises(InvalidSignature):
        _record_verifies(record)


def test_the_relying_party_supplies_its_own_trust() -> None:
    """The keys and the sequence come from relying-party.json, not from any proof."""
    for kid, jwk in RELYING_PARTY["committer_keys"].items():
        assert kid == _thumbprint(jwk)
    proofs = [_load(p.name) for p in DIR.glob("proof-*.json")]
    named = {p["slot"]["committer_key_id"] for p in proofs}
    assert named - set(RELYING_PARTY["committer_keys"]), "no case exercises an untrusted key"
    for p in proofs:
        assert _thumbprint(p["committer_jwk"]) == p["slot"]["committer_key_id"]


def test_the_generator_reproduces_the_committed_bytes(tmp_path: Path) -> None:
    subprocess.run(
        [sys.executable, str(GENERATOR), "--out", str(tmp_path)],
        check=True,
        capture_output=True,
    )
    produced = {p.name for p in tmp_path.iterdir()}
    committed = {p.name for p in DIR.iterdir() if p.suffix == ".json"}
    assert produced == committed
    for name in committed:
        assert (tmp_path / name).read_bytes() == (DIR / name).read_bytes(), name

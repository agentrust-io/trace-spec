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
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace.sign import _canonical_bytes

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
    "signatures_verify",
    "sequence_position_matches",
    "verdict",
)


def _load(name: str) -> dict:
    return json.loads((DIR / name).read_text(encoding="utf-8"))


def _jcs_sha256(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _thumbprint(jwk: dict) -> str:
    required = {k: jwk[k] for k in ("crv", "kty", "x")}
    raw = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()


def _signed_by(obj: dict, jwk: dict) -> bool:
    body = {k: v for k, v in obj.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"])).verify(
            _b64u_decode(obj["signature"]), rfc8785.dumps(body)
        )
    except InvalidSignature:
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
    """
    (entry,) = record["references"]
    assert entry["rel"] == "position-commitment"
    assert entry["validation"] == "recompute"
    assert "resolver" not in entry and "retention" not in entry
    result = dict.fromkeys(OUTCOME_KEYS)
    if proof is None:
        return {**result, "proof_held": False, "verdict": "position-absent"}
    result["proof_held"] = True
    slot, binding = proof["slot"], proof["binding"]

    result["commitment_recomputes"] = _jcs_sha256(slot) == entry["id"]
    if not result["commitment_recomputes"]:
        return {**result, "verdict": "contradiction-commitment-mismatch"}

    # Section 3.1.3's preimage: the complete record as published, signature included.
    result["binds_this_record"] = (
        binding["slot_commitment"] == entry["id"]
        and binding["record_digest"] == _jcs_sha256(record)
    )
    if not result["binds_this_record"]:
        return {**result, "verdict": "contradiction-commits-another-record"}

    kid = slot["committer_key_id"]
    independent = relying_party["committer_keys"].get(kid)
    result["committer_key_independent"] = independent is not None
    jwk = independent if independent is not None else proof["committer_jwk"]
    if _thumbprint(jwk) != kid or binding["committer_key_id"] != kid:
        return {**result, "signatures_verify": False, "verdict": "contradiction-signature-invalid"}
    result["signatures_verify"] = _signed_by(slot, jwk) and _signed_by(binding, jwk)
    if not result["signatures_verify"]:
        return {**result, "verdict": "contradiction-signature-invalid"}

    sequence = relying_party["sequence"]
    result["sequence_position_matches"] = (
        slot["sequence"] == sequence["id"]
        and sequence["positions"].get(str(slot["position"])) == slot["sequence_value"]
    )
    if not result["committer_key_independent"]:
        return {**result, "verdict": "position-consistent-not-established"}
    if not result["sequence_position_matches"]:
        return {**result, "verdict": "contradiction-sequence-mismatch"}
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
    trusting["committer_keys"][proof["slot"]["committer_key_id"]] = proof["committer_jwk"]
    assert _recompute(record, proof, trusting)["verdict"] == "position-established"
    assert _recompute(record, proof, RELYING_PARTY)["verdict"] == (
        "position-consistent-not-established"
    )


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

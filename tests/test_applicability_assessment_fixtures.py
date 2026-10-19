"""An assessor's statement of legal applicability as a TRACE `applicability-assessment` reference.

Re-verifies examples/applicability-assessment/ from the committed bytes. The generator
wrote expected.json alongside the vectors, and a generator's own summary of its output
is a claim, so every outcome here is recomputed with this repository's dependencies and
compared with expected.json, never read from it. The generator is deterministic, and
the last test re-runs it against the committed files.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace import verify_record

DIR = Path(__file__).resolve().parents[1] / "examples" / "applicability-assessment"
GENERATOR = DIR / "gen_applicability_assessment_vectors.py"
EXPECTED = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
OUTCOME_KEYS = (
    "reference_resolves",
    "digest_matches",
    "issuer_key_configured",
    "assessment_verifies",
    "outcome",
    "verdict",
)
REQUIRED_OBJECT_FACTS = (
    "type",
    "issuer",
    "issuer_key_id",
    "party",
    "jurisdiction",
    "provision",
    "basis",
    "outcome",
    "issued_at",
    "signature",
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


def _assessment_verifies(obj: dict, jwk: dict) -> bool:
    """The object's own check: Ed25519 over its RFC 8785 form without `signature`."""
    body = {k: v for k, v in obj.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"])).verify(
            _b64u_decode(obj["signature"]), rfc8785.dumps(body)
        )
    except InvalidSignature:
        return False
    return True


def _assess(record: dict, store: dict, issuer_keys: dict) -> dict:
    """What a relying party concludes about the assessment a record points at.

    Three separable findings: whether the reference resolves, whether the resolved bytes
    are the cited bytes, and whether the object verifies under its named issuer's key
    when the relying party holds that key. Each is reported in its own field. The verdict
    names the state of the referenced assessment, never whether a legal obligation
    applies or was met: an `applies` outcome is the assessor's claim and nothing more,
    and section 3.1.2 rule 3 makes identity the ceiling.
    """
    (reference,) = record["references"]
    assert reference["rel"] == "applicability-assessment"
    assert reference["resolver"] == store["resolver"] == EXPECTED["resolver"]
    obj = store["assessments"].get(reference["id"])
    if obj is None:
        return {
            "reference_resolves": False,
            "digest_matches": None,
            "issuer_key_configured": None,
            "assessment_verifies": None,
            "outcome": None,
            "verdict": "assessment-unresolved",
        }
    digest = reference.get("digest")
    digest_matches = _jcs_sha256(obj) == digest if digest is not None else None
    jwk = issuer_keys.get(obj["issuer_key_id"])
    configured = jwk is not None
    verifies = _assessment_verifies(obj, jwk) if configured else None
    if digest_matches is None:
        verdict = "assessment-digest-unavailable"
    elif not digest_matches:
        verdict = "assessment-digest-mismatch"
    elif not configured:
        verdict = "assessment-unverified"
    elif not verifies:
        verdict = "assessment-signature-invalid"
    else:
        verdict = "assessment-verified"
    return {
        "reference_resolves": True,
        "digest_matches": digest_matches,
        "issuer_key_configured": configured,
        "assessment_verifies": verifies,
        "outcome": obj["outcome"]["status"],
        "verdict": verdict,
    }


def test_the_committed_records_are_exactly_the_declared_cases() -> None:
    committed = {p.name for p in DIR.glob("0*.json")}
    assert committed == set(CASES)
    for case in EXPECTED["cases"].values():
        assert (DIR / case["store"]).is_file()


@pytest.mark.parametrize("name", CASES)
def test_every_case_verifies_as_a_trust_record(name: str) -> None:
    # Section 3.1.2 rule 3: what a reference resolves to never decides whether the
    # record verifies, so the mismatched, unverified and unresolved cases verify too.
    verify_record(_load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)
    assert EXPECTED["cases"][name]["trace_record_verifies"] is True


@pytest.mark.parametrize("name", CASES)
def test_the_outcome_is_recomputed_from_the_committed_bytes(name: str) -> None:
    case = EXPECTED["cases"][name]
    observed = _assess(_load(name), _load(case["store"]), EXPECTED["issuer_keys"])
    assert observed == {k: case[k] for k in OUTCOME_KEYS}


def test_applies_does_not_apply_and_undetermined_verify_identically() -> None:
    """The outcome never reaches validity. `01` cites `applies`, `03` cites
    `does-not-apply`, and `04` cites `undetermined`; the three records differ only in
    the reference they carry, all three verify, and the relying party's assessment
    differs only in the reported outcome."""
    store = _load("assessment-store.json")
    applies = _assess(_load("01-assessment-applies-verified.json"), store, EXPECTED["issuer_keys"])
    does_not_apply = _assess(
        _load("03-outcome-is-does-not-apply.json"), store, EXPECTED["issuer_keys"]
    )
    undetermined = _assess(
        _load("04-outcome-is-undetermined.json"), store, EXPECTED["issuer_keys"]
    )
    assert (
        applies["outcome"],
        does_not_apply["outcome"],
        undetermined["outcome"],
    ) == ("applies", "does-not-apply", "undetermined")
    strip_outcome = lambda d: {k: v for k, v in d.items() if k != "outcome"}  # noqa: E731
    assert strip_outcome(applies) == strip_outcome(does_not_apply) == strip_outcome(undetermined)

    names = (
        "01-assessment-applies-verified.json",
        "03-outcome-is-does-not-apply.json",
        "04-outcome-is-undetermined.json",
    )
    for name in names:
        verify_record(_load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)
    strip_record = lambda r: {  # noqa: E731
        k: v for k, v in r.items() if k not in ("references", "signature")
    }
    first, second, third = (_load(n) for n in names)
    assert strip_record(first) == strip_record(second) == strip_record(third)


def test_a_bad_signature_over_matching_bytes_is_its_own_verdict() -> None:
    """A corrupted issuer signature, with the reference digest recomputed over the
    corrupted object, matches on digest and fails on signature. The verdict says so and
    does not fold it into a digest mismatch."""
    store = copy.deepcopy(_load("assessment-store.json"))
    obj = store["assessments"]["assessment/1"]
    signature = _b64u_decode(obj["signature"])
    obj["signature"] = base64.urlsafe_b64encode(
        bytes([signature[0] ^ 1]) + signature[1:]
    ).rstrip(b"=").decode()
    record = copy.deepcopy(_load("01-assessment-applies-verified.json"))
    record["references"][0]["digest"] = _jcs_sha256(obj)
    observed = _assess(record, store, EXPECTED["issuer_keys"])
    assert observed["digest_matches"] is True
    assert observed["assessment_verifies"] is False
    assert observed["verdict"] == "assessment-signature-invalid"


def test_the_record_signature_covers_the_reference() -> None:
    record = copy.deepcopy(_load("01-assessment-applies-verified.json"))
    digest = record["references"][0]["digest"]
    record["references"][0]["digest"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    with pytest.raises(InvalidSignature):
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def test_every_assessment_object_carries_the_registered_facts() -> None:
    assessments = _load("assessment-store.json")["assessments"]
    statuses = {obj["outcome"]["status"] for obj in assessments.values()}
    assert statuses == {"applies", "does-not-apply", "undetermined"}
    for obj in assessments.values():
        assert set(REQUIRED_OBJECT_FACTS).issubset(obj)
        assert obj["type"] == "applicability-assessment"
        assert set(obj["party"]) == {"id", "role"}
        assert obj["party"]["id"] and obj["party"]["role"]
        assert obj["jurisdiction"] == "EU"
        assert set(obj["provision"]) == {"instrument", "article", "text_as_of"}
        assert obj["basis"] and all(isinstance(item, str) and item for item in obj["basis"])
        assert obj["outcome"]["status"] in obj["outcome"]["vocabulary"]


def test_every_issuer_key_id_is_the_thumbprint_of_the_key_it_names() -> None:
    for kid, jwk in EXPECTED["issuer_keys"].items():
        assert kid == _thumbprint(jwk)
    held = set(EXPECTED["issuer_keys"])
    named = {
        obj["issuer_key_id"] for obj in _load("assessment-store.json")["assessments"].values()
    }
    assert named - held, "no case exercises an issuer whose key the relying party does not hold"


def test_the_altered_store_differs_in_one_field_only() -> None:
    original, altered = _load("assessment-store.json"), _load("assessment-store-altered.json")
    assert original["resolver"] == altered["resolver"]
    assert set(original["assessments"]) == set(altered["assessments"])
    changed = [
        (id_, member)
        for id_ in original["assessments"]
        for member in original["assessments"][id_]
        if original["assessments"][id_][member] != altered["assessments"][id_][member]
    ]
    assert changed == [("assessment/2", "outcome")]
    assert original["assessments"]["assessment/2"]["outcome"]["status"] == "does-not-apply"
    assert altered["assessments"]["assessment/2"]["outcome"]["status"] == "applies"


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


def test_missing_optional_digest_does_not_claim_cited_byte_identity() -> None:
    record = copy.deepcopy(_load("01-assessment-applies-verified.json"))
    # This exercises only the external-object helper, not the modified record
    # signature. It makes no assertion that the edited TRACE record verifies.
    del record["references"][0]["digest"]
    observed = _assess(record, _load("assessment-store.json"), EXPECTED["issuer_keys"])
    assert observed["reference_resolves"] is True
    assert observed["digest_matches"] is None
    assert observed["assessment_verifies"] is True
    assert observed["verdict"] == "assessment-digest-unavailable"


def test_valid_signature_does_not_hide_a_reference_digest_mismatch() -> None:
    record = copy.deepcopy(_load("01-assessment-applies-verified.json"))
    record["references"][0]["digest"] = "sha256:" + "0" * 64
    observed = _assess(record, _load("assessment-store.json"), EXPECTED["issuer_keys"])
    assert observed["digest_matches"] is False
    assert observed["assessment_verifies"] is True
    assert observed["verdict"] == "assessment-digest-mismatch"

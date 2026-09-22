"""An independent check's finding as a TRACE `condition-appraisal` reference.

Re-verifies examples/condition-appraisal/ from the committed bytes. The generator wrote
expected.json alongside the vectors, and a generator's own summary of its output is a
claim, so every outcome here is recomputed with this repository's dependencies and
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

DIR = Path(__file__).resolve().parents[1] / "examples" / "condition-appraisal"
GENERATOR = DIR / "gen_condition_appraisal_vectors.py"
EXPECTED = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
OUTCOME_KEYS = (
    "reference_resolves", "digest_matches", "issuer_key_configured",
    "appraisal_verifies", "outcome", "verdict",
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


def _appraisal_verifies(obj: dict, jwk: dict) -> bool:
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
    """What a relying party concludes about the appraisal a record points at.

    Three separable findings: whether the reference resolves, whether the resolved bytes
    are the cited bytes, and whether the object verifies under its named issuer's key
    when the relying party holds that key. The outcome is reported as the object states
    it and decides nothing here: section 3.1.2 rule 3 makes identity the ceiling.
    """
    (reference,) = record["references"]
    assert reference["rel"] == "condition-appraisal"
    assert reference["resolver"] == store["resolver"] == EXPECTED["resolver"]
    obj = store["appraisals"].get(reference["id"])
    if obj is None:
        return {"reference_resolves": False, "digest_matches": None, "issuer_key_configured": None,
                "appraisal_verifies": None, "outcome": None, "verdict": "appraisal-unconfirmed"}
    digest_matches = _jcs_sha256(obj) == reference["digest"]
    jwk = issuer_keys.get(obj["issuer_key_id"])
    configured = jwk is not None
    verifies = _appraisal_verifies(obj, jwk) if configured else None
    if not digest_matches:
        verdict = "appraisal-contradicted"
    elif not configured:
        verdict = "appraisal-unverified"
    elif not verifies:
        verdict = "appraisal-contradicted"
    else:
        verdict = "appraisal-confirmed"
    return {"reference_resolves": True, "digest_matches": digest_matches,
            "issuer_key_configured": configured, "appraisal_verifies": verifies,
            "outcome": obj["outcome"]["status"], "verdict": verdict}


def test_the_committed_records_are_exactly_the_declared_cases() -> None:
    committed = {p.name for p in DIR.glob("0*.json")}
    assert committed == set(CASES)
    for case in EXPECTED["cases"].values():
        assert (DIR / case["store"]).is_file()


@pytest.mark.parametrize("name", CASES)
def test_every_case_verifies_as_a_trust_record(name: str) -> None:
    # Section 3.1.2 rule 3: what a reference resolves to never decides whether the
    # record verifies, so the contradicted, unverified and unresolvable cases verify too.
    verify_record(_load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)
    assert EXPECTED["cases"][name]["trace_record_verifies"] is True


@pytest.mark.parametrize("name", CASES)
def test_the_outcome_is_recomputed_from_the_committed_bytes(name: str) -> None:
    case = EXPECTED["cases"][name]
    observed = _assess(_load(name), _load(case["store"]), EXPECTED["issuer_keys"])
    assert observed == {k: case[k] for k in OUTCOME_KEYS}


def test_a_pass_and_a_fail_verify_identically() -> None:
    """The outcome never reaches validity. `01` cites a pass and `03` a fail; the two
    records differ only in the reference they carry, both verify, and the relying
    party's assessment differs only in the reported outcome."""
    store = _load("appraisal-store.json")
    passing = _assess(_load("01-appraisal-confirmed.json"), store, EXPECTED["issuer_keys"])
    failing = _assess(_load("03-outcome-is-a-fail.json"), store, EXPECTED["issuer_keys"])
    assert (passing["outcome"], failing["outcome"]) == ("pass", "fail")
    assert {k: v for k, v in passing.items() if k != "outcome"} == \
        {k: v for k, v in failing.items() if k != "outcome"}
    for name in ("01-appraisal-confirmed.json", "03-outcome-is-a-fail.json"):
        verify_record(_load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)
    passing_record = _load("01-appraisal-confirmed.json")
    failing_record = _load("03-outcome-is-a-fail.json")
    strip = lambda r: {  # noqa: E731
        k: v for k, v in r.items() if k not in ("references", "signature")
    }
    assert strip(passing_record) == strip(failing_record)


def test_the_record_signature_covers_the_reference() -> None:
    record = copy.deepcopy(_load("01-appraisal-confirmed.json"))
    digest = record["references"][0]["digest"]
    record["references"][0]["digest"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    with pytest.raises(InvalidSignature):
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def test_the_condition_and_subject_digests_recompute_from_the_context() -> None:
    context = _load("context.json")
    for obj in _load("appraisal-store.json")["appraisals"].values():
        assert obj["condition"]["id"] == context["condition"]["id"]
        assert obj["condition"]["digest"] == _jcs_sha256(context["condition"])
        assert obj["subject"]["id"] == context["deliverable"]["id"]
        assert obj["subject"]["digest"] == _jcs_sha256(context["deliverable"])
        assert obj["outcome"]["status"] in obj["outcome"]["vocabulary"]


def test_every_issuer_key_id_is_the_thumbprint_of_the_key_it_names() -> None:
    for kid, jwk in EXPECTED["issuer_keys"].items():
        assert kid == _thumbprint(jwk)
    held = set(EXPECTED["issuer_keys"])
    named = {obj["issuer_key_id"] for obj in _load("appraisal-store.json")["appraisals"].values()}
    assert named - held, "no case exercises an issuer whose key the relying party does not hold"


def test_the_altered_store_differs_in_one_field_only() -> None:
    original, altered = _load("appraisal-store.json"), _load("appraisal-store-altered.json")
    assert original["resolver"] == altered["resolver"]
    assert set(original["appraisals"]) == set(altered["appraisals"])
    changed = [
        (id_, member)
        for id_ in original["appraisals"]
        for member in original["appraisals"][id_]
        if original["appraisals"][id_][member] != altered["appraisals"][id_][member]
    ]
    assert changed == [("appraisal/2", "outcome")]
    assert original["appraisals"]["appraisal/2"]["outcome"]["status"] == "fail"
    assert altered["appraisals"]["appraisal/2"]["outcome"]["status"] == "pass"


def test_the_generator_reproduces_the_committed_bytes(tmp_path: Path) -> None:
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True,
                   capture_output=True)
    produced = {p.name for p in tmp_path.iterdir()}
    committed = {p.name for p in DIR.iterdir() if p.suffix == ".json"}
    assert produced == committed
    for name in committed:
        assert (tmp_path / name).read_bytes() == (DIR / name).read_bytes(), name

"""An observed mutation interval as a TRACE `observed-effect` reference.

Re-verifies examples/observed-effect/ from the committed bytes. The generator wrote
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

DIR = Path(__file__).resolve().parents[1] / "examples" / "observed-effect"
GENERATOR = DIR / "gen_observed_effect_vectors.py"
EXPECTED = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
OUTCOME_KEYS = (
    "reference_resolves", "digest_matches", "observer_key_configured",
    "envelope_verifies", "dual_values", "verdict",
)


def _load(name: str) -> dict:
    return json.loads((DIR / name).read_text(encoding="utf-8"))


def _jcs_sha256(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type.encode(), len(payload), payload)


def _statement(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))


def _envelope_verifies(envelope: dict, jwk: dict) -> bool:
    """The object's own check: Ed25519 over the DSSE pre-authentication encoding."""
    (signature,) = envelope["signatures"]
    message = _pae(envelope["payloadType"], base64.b64decode(envelope["payload"]))
    try:
        Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"])).verify(
            base64.b64decode(signature["sig"]), message
        )
    except InvalidSignature:
        return False
    return True


def _dual_values(envelope: dict) -> str:
    rows = _statement(envelope)["predicate"].get("dualValues", [])
    return "disagree" if any(r["agreement"] == "disagree" for r in rows) else "agree"


def _assess(record: dict, store: dict, observer_keys: dict) -> dict:
    """What a relying party concludes about the object a record points at.

    Three separable findings: whether the reference resolves, whether the resolved bytes
    are the cited bytes, and whether the envelope verifies under its observer's key when
    the relying party holds that key. Each is reported in its own field. The verdict
    names the state of the referenced observation, never the effect it reports: a
    verified observation does not establish that the change occurred, and a digest
    mismatch does not establish that it did not. What the statement reports is carried
    as it states it and decides nothing here: section 3.1.2 rule 3 makes identity the
    ceiling.
    """
    (reference,) = record["references"]
    assert reference["rel"] == "observed-effect"
    assert reference["resolver"] == store["resolver"] == EXPECTED["resolver"]
    envelope = store["effects"].get(reference["id"])
    if envelope is None:
        return {"reference_resolves": False, "digest_matches": None,
                "observer_key_configured": None, "envelope_verifies": None,
                "dual_values": None, "verdict": "observation-unresolved"}
    digest_matches = _jcs_sha256(envelope) == reference["digest"]
    (signature,) = envelope["signatures"]
    jwk = observer_keys.get(signature["keyid"])
    configured = jwk is not None
    verifies = _envelope_verifies(envelope, jwk) if configured else None
    if not digest_matches:
        verdict = "observation-digest-mismatch"
    elif not configured:
        verdict = "observation-unverified"
    elif not verifies:
        verdict = "observation-signature-invalid"
    else:
        verdict = "observation-verified"
    return {"reference_resolves": True, "digest_matches": digest_matches,
            "observer_key_configured": configured, "envelope_verifies": verifies,
            "dual_values": _dual_values(envelope), "verdict": verdict}


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
    observed = _assess(_load(name), _load(case["store"]), EXPECTED["observer_keys"])
    assert observed == {k: case[k] for k in OUTCOME_KEYS}


def test_every_resolved_object_carries_the_registered_predicate_type() -> None:
    for store in ("effect-store.json", "effect-store-altered.json"):
        for envelope in _load(store)["effects"].values():
            assert envelope["payloadType"] == "application/vnd.in-toto+json"
            assert _statement(envelope)["predicateType"] == EXPECTED["predicate_type"]


def test_the_subject_digest_is_the_interval_after_root() -> None:
    """The statement binds its single subject to the state the interval ended in, so
    the reference identifies a state change, not only a document about one."""
    for envelope in _load("effect-store.json")["effects"].values():
        statement = _statement(envelope)
        (subject,) = statement["subject"]
        assert subject["digest"]["sha256"] == statement["predicate"]["interval"]["afterRoot"]


def test_an_agreement_and_a_disagreement_verify_identically() -> None:
    """What the statement reports never reaches validity. `01` cites an interval where
    the observer and the observed party agree and `03` one where they disagree; the two
    records differ only in the reference they carry, both verify, and the relying
    party's assessment differs only in what it reports."""
    store = _load("effect-store.json")
    agree = _assess(_load("01-observation-verified.json"), store, EXPECTED["observer_keys"])
    disagree = _assess(
        _load("03-observer-and-observed-disagree.json"), store, EXPECTED["observer_keys"]
    )
    assert (agree["dual_values"], disagree["dual_values"]) == ("agree", "disagree")
    assert {k: v for k, v in agree.items() if k != "dual_values"} == \
        {k: v for k, v in disagree.items() if k != "dual_values"}
    strip = lambda r: {  # noqa: E731
        k: v for k, v in r.items() if k not in ("references", "signature")
    }
    assert strip(_load("01-observation-verified.json")) == \
        strip(_load("03-observer-and-observed-disagree.json"))


def test_the_record_signature_covers_the_reference() -> None:
    record = copy.deepcopy(_load("01-observation-verified.json"))
    digest = record["references"][0]["digest"]
    record["references"][0]["digest"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    with pytest.raises(InvalidSignature):
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def test_every_observer_key_id_is_derived_from_the_key_it_names() -> None:
    for kid, jwk in EXPECTED["observer_keys"].items():
        assert kid == hashlib.sha256(_b64u_decode(jwk["x"])).hexdigest()[:32]
    held = set(EXPECTED["observer_keys"])
    named = {
        envelope["signatures"][0]["keyid"]
        for envelope in _load("effect-store.json")["effects"].values()
    }
    assert named - held, "no case exercises an observer whose key the relying party does not hold"


def test_the_altered_store_differs_in_one_payload_only() -> None:
    original, altered = _load("effect-store.json"), _load("effect-store-altered.json")
    assert original["resolver"] == altered["resolver"]
    assert set(original["effects"]) == set(altered["effects"])
    changed = [id_ for id_ in original["effects"]
               if original["effects"][id_] != altered["effects"][id_]]
    assert changed == ["interval/2"]
    before, after = original["effects"]["interval/2"], altered["effects"]["interval/2"]
    assert before["signatures"] == after["signatures"]
    assert (_dual_values(before), _dual_values(after)) == ("disagree", "agree")


def test_the_source_statements_are_the_corpus_members_they_name() -> None:
    for path in (DIR / "source").glob("*.json"):
        assert "v" + hashlib.sha256(path.read_bytes()).hexdigest()[:16] == path.stem


def test_the_generator_reproduces_the_committed_bytes(tmp_path: Path) -> None:
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True,
                   capture_output=True)
    produced = {p.name for p in tmp_path.iterdir()}
    committed = {p.name for p in DIR.iterdir() if p.suffix == ".json"}
    assert produced == committed
    for name in committed:
        assert (tmp_path / name).read_bytes() == (DIR / name).read_bytes(), name

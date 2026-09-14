"""CHAP review decisions as TRACE `approval-outcome` references.

Re-verifies examples/chap-approval-outcome/ without importing CHAP. The fixtures were
produced by chap-coordinator 0.2.13 through the generator in agentrust-io/integrations
(integrations/chap/examples/generate_trace_spec_fixtures.py), which also wrote
expected.json. A generator's own summary of its output is a claim, so every
outcome here is recomputed from the committed bytes with this repository's
dependencies and compared with expected.json, never read from it.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature

from agentrust_trace import verify_record

CHAP_DIR = Path(__file__).resolve().parents[1] / "examples" / "chap-approval-outcome"
EXPECTED = json.loads((CHAP_DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
ZERO_HASH = "sha256:" + "0" * 64
OUTCOME_KEYS = ("reference_resolves", "digest_matches", "decision", "chain_replays", "verdict")


def _load(name: str) -> dict:
    return json.loads((CHAP_DIR / name).read_text(encoding="utf-8"))


def _jcs_sha256(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _chain_replays(log: dict) -> bool:
    """CHAP audit-scitt/1.0 chain: link = sha256(JCS(envelope) || prev_hash).

    The final link has to equal the exported head as well as each entry matching its
    stored prev_hash. Without the head check the last entry is covered by nothing.
    """
    running = ZERO_HASH
    for entry in log["entries"]:
        if entry["prev_hash"] != running:
            return False
        running = "sha256:" + hashlib.sha256(
            rfc8785.dumps(entry["envelope"]) + running.encode("utf-8")
        ).hexdigest()
    return running == log["chain_head"]


def _assess(record: dict, log: dict) -> dict:
    """What a relying party concludes about the approval a record points at."""
    (reference,) = record["references"]
    assert reference["rel"] == "approval-outcome"
    assert reference["resolver"] == EXPECTED["resolver"]
    assert reference["id"].startswith("audit/")
    seq = int(reference["id"][len("audit/"):])
    entry = next((e for e in log["entries"] if e["seq"] == seq), None)
    chain = _chain_replays(log)
    if entry is None:
        return {"reference_resolves": False, "digest_matches": None, "decision": None,
                "chain_replays": chain, "verdict": "approval-unconfirmed"}
    digest_matches = _jcs_sha256(entry["envelope"]) == reference["digest"]
    decision = entry["envelope"].get("method")
    if not (digest_matches and chain):
        verdict = "approval-contradicted"
    elif decision != "decide.approve":
        verdict = "not-an-approval"
    else:
        verdict = "approval-confirmed"
    return {"reference_resolves": True, "digest_matches": digest_matches,
            "decision": decision, "chain_replays": chain, "verdict": verdict}


def test_the_committed_records_are_exactly_the_declared_cases() -> None:
    committed = {p.name for p in CHAP_DIR.glob("0*.json")}
    assert committed == set(CASES)
    for case in EXPECTED["cases"].values():
        assert (CHAP_DIR / case["log"]).is_file()


@pytest.mark.parametrize("name", CASES)
def test_every_case_verifies_as_a_trust_record(name: str) -> None:
    # Section 3.1.2 rule 3: what a reference resolves to never decides whether the
    # record verifies, so the unresolvable and contradicted cases verify too.
    verify_record(_load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)
    assert EXPECTED["cases"][name]["trace_record_verifies"] is True


@pytest.mark.parametrize("name", CASES)
def test_the_outcome_is_recomputed_from_the_committed_bytes(name: str) -> None:
    case = EXPECTED["cases"][name]
    assert _assess(_load(name), _load(case["log"])) == {k: case[k] for k in OUTCOME_KEYS}


def test_the_record_signature_covers_the_reference() -> None:
    record = copy.deepcopy(_load("01-approval-confirmed.json"))
    digest = record["references"][0]["digest"]
    record["references"][0]["digest"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    # verify_record documents InvalidSignature for a signature that does not verify.
    with pytest.raises(InvalidSignature):
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def test_rfc8785_replays_the_chain_chap_verified() -> None:
    """CHAP verified this chain with its own canonicalizer before export. Replaying it
    here with rfc8785 is the check that the two implementations agree byte for byte on
    every committed envelope, which is what makes a digest portable between them."""
    log = _load("chap-audit-log.json")
    assert log["chap_verify_chain"]["status"] == "verified"
    assert log["chap_verify_chain"]["chain_head"] == log["chain_head"]
    assert _chain_replays(log)


def test_the_altered_log_differs_in_one_field_only() -> None:
    original, altered = _load("chap-audit-log.json"), _load("chap-audit-log-altered.json")
    changed = [
        (a["seq"], key)
        for a, b in zip(original["entries"], altered["entries"], strict=True)
        for key in a["envelope"]["params"]
        if a["envelope"]["params"][key] != b["envelope"]["params"][key]
    ]
    assert len(changed) == 1
    seq, key = changed[0]
    assert key == "comment"
    (entry,) = [e for e in original["entries"] if e["seq"] == seq]
    assert entry["envelope"]["method"] == "decide.approve"
    assert altered["chain_head"] == original["chain_head"]


@pytest.mark.parametrize("method", ["decide.approve", "decide.reject"])
def test_each_decision_names_the_artefact_it_settled(method: str) -> None:
    """CHAP draft CEP-001: approved_artefact_digest binds a decision to the artefact
    under review. Recomputed from the review.request that opened the same task."""
    entries = [e["envelope"] for e in _load("chap-audit-log.json")["entries"]]
    (decision,) = [e for e in entries if e.get("method") == method]
    (request,) = [e for e in entries if e.get("method") == "review.request"
                  and e["params"]["task_id"] == decision["params"]["task_id"]]
    artefact_digest = _jcs_sha256(request["params"]["artefact"])
    assert decision["params"]["approved_artefact_digest"] == artefact_digest

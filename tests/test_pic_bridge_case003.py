"""Only case 003 and its direct counterexamples are reconciled in this review."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agentrust_trace import intent_bridge

CORPUS = Path(__file__).resolve().parents[1] / "examples/pic-trace-bridge-v1"
sys.path.insert(0, str(CORPUS))
import case003_independent as independent  # noqa: E402
import case003_runner as runner  # noqa: E402
import gen_bridge_vectors as generator  # noqa: E402
from verify_bridge_independent import verify_case  # noqa: E402


def case(suffix=""):
    return json.loads(next(CORPUS.glob(f"003{suffix}-*.json")).read_text(encoding="utf-8"))


def test_four_declared_targets_agree():
    report = runner.run()
    assert report["passed"], report
    assert report["review_vectors"] == 4
    assert report["full_corpus_certification"] == "held"
    assert report["original_empty_after_positive_credit"] == "withdrawn"


def test_missing_fields_is_the_first_failure_and_has_no_outcome():
    vector = case("a")
    with pytest.raises(
        intent_bridge.AuthorizationMismatch,
        match=(
            r"^transcript.after is missing successor fields: "
            r"\['observation', 'observed_at', 'observer'\]$"
        ),
    ):
        intent_bridge.verify_bridge(**vector["inputs"])
    result = runner.reference(vector)
    assert result["codes"] == ["transcript_after_invalid"]
    assert result["pic_authorization_bound"] is True
    assert result["successor_envelope_bound"] is False
    assert result["successor_outcome"] is None


def test_empty_after_binding_guard_is_load_bearing(monkeypatch):
    vector = case("a")
    monkeypatch.setattr(intent_bridge, "_bind_successor_observation", lambda after, digest: after)
    # All earlier prerequisites are valid; bypassing only the successor guard
    # changes the bridge refusal into acceptance.
    assert intent_bridge.verify_bridge(**vector["inputs"])["authorization_id"] == "auth-206"


def test_empty_after_independent_guard_is_load_bearing(monkeypatch):
    from verify_bridge_independent import verify_bridge_independent

    vector = case("a")
    monkeypatch.setattr(independent, "binding", lambda after, expected: None)
    result = verify_bridge_independent(**vector["inputs"], case003=True)
    assert result["classification"] == "accepted"


@pytest.mark.parametrize("suffix", ["b", "c"])
def test_insufficiency_is_not_positive_or_contradiction(suffix):
    result = runner.reference(case(suffix))
    assert result == verify_case(case(suffix))
    assert result["successor_envelope_bound"] is True
    assert result["successor_outcome"] == "not-established"
    assert result["successor_reason"] == "successor_predicate_undecidable"


@pytest.mark.parametrize("suffix", ["b", "c"])
def test_turning_undecidable_into_success_is_detected(suffix, monkeypatch):
    vector = case(suffix)
    monkeypatch.setattr(runner, "predicate", lambda inputs: lambda observation: True)
    assert runner.reference(vector) != vector["expected"]["conformant_runtime"]
    original = independent.outcome

    def promote(after, policy, inputs):
        status, reason = original(after, policy, inputs)
        return (
            ("established", "successor_predicate_satisfied")
            if status == "not-established"
            else (status, reason)
        )

    monkeypatch.setattr(independent, "outcome", promote)
    assert verify_case(vector) != vector["expected"]["conformant_runtime"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("observation", {"invoice_id": "INV-8", "status": "sent"}),
        ("observer", "relabelled"),
        ("observed_at", 148),
    ],
)
def test_exact_envelope_is_bound(field, value):
    vector = case()
    vector["inputs"]["transcript"]["after"][field] = value
    result = runner.reference(vector)
    assert result == verify_case(vector)
    assert result["codes"] == ["successor_envelope_digest_mismatch"]
    assert result["successor_outcome"] is None


def test_unsigned_digest_substitution_cannot_repair_tampering():
    vector = case()
    inputs = vector["inputs"]
    inputs["transcript"]["after"]["observation"] = {"unrelated": True}
    inputs["bridge"]["authorization"]["successor_observation_digest"] = generator._digest(
        inputs["transcript"]["after"]
    )
    assert runner.reference(vector) == verify_case(vector)
    assert runner.reference(vector)["codes"] == ["authorization_unverifiable"]
    assert runner.reference(vector)["pic_authorization_bound"] is None


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"trusted_observers": []}, "successor_observer_untrusted"),
        ({"max_age_seconds": 0}, "successor_observation_stale"),
        ({"executor_id": "invoice-observer"}, "successor_observer_not_independent"),
    ],
)
def test_policy_remains_separate(change, reason):
    vector = case()
    vector["successor_policy"].update(change)
    result = runner.reference(vector)
    assert result == verify_case(vector)
    assert result["successor_envelope_bound"] is True
    assert result["successor_outcome"] == "not-established"
    assert result["successor_reason"] == reason


def test_contradiction_requires_affirmative_relevant_evidence():
    vector = case()
    inputs = vector["inputs"]
    inputs["transcript"]["after"]["observation"]["status"] = "failed"
    inputs["bridge"]["authorization"]["successor_observation_digest"] = generator._digest(
        inputs["transcript"]["after"]
    )
    generator._resign(inputs)
    assert runner.reference(vector) == verify_case(vector)
    assert runner.reference(vector)["successor_outcome"] == "contradicted"


def test_old_boolean_is_not_accepted_by_the_new_contract():
    import jsonschema

    vector = case()
    vector["expected"]["conformant_runtime"]["result"]["transcript_bound"] = True
    schema = json.loads((CORPUS / "contract/case003-v1.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(vector, schema)


def test_other_101_vectors_are_byte_identical():
    hashes = json.loads((CORPUS / "contract/frozen-other-cases.sha256.json").read_text())
    assert len(hashes) == 101
    for name, digest in hashes.items():
        assert hashlib.sha256((CORPUS / name).read_bytes()).hexdigest() == digest, name


def test_all_generated_files_reproduce_without_existing_fixtures(tmp_path):
    target = tmp_path / "corpus"
    shutil.copytree(CORPUS, target, ignore=shutil.ignore_patterns("__pycache__"))
    expected = {p.name: p.read_bytes() for p in target.glob("*.json")}
    for path in target.glob("*.json"):
        path.unlink()
    subprocess.run([sys.executable, str(target / "gen_bridge_vectors.py")], check=True)
    actual = {p.name: p.read_bytes() for p in target.glob("*.json")}
    assert actual == expected


def test_unmapped_reference_signals_fail_loudly(monkeypatch):
    def unexpected(**kwargs):
        raise RuntimeError("unexpected verifier failure")

    monkeypatch.setattr(intent_bridge, "verify_bridge", unexpected)
    with pytest.raises(runner.ReferenceSignalError, match="unmapped reference signal"):
        runner.reference(case())


def test_expectations_do_not_drive_either_verifier():
    vector = case("c")
    before = (runner.reference(vector), verify_case(vector))
    vector["expected"] = {"invented": "accepted"}
    assert (runner.reference(vector), verify_case(vector)) == before


def test_full_corpus_certification_is_not_inferred():
    import run_bridge_vectors

    with pytest.raises(RuntimeError, match="certification remains held"):
        run_bridge_vectors.run_corpus()

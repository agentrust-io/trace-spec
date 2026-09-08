"""Execute the draft rules with the external verifier and genuine captured quotes.

Run explicitly in the runtime-evidence CI job; the ordinary TRACE test suite does
not depend on agent-manifest. Missing verifier code or captures fail this job instead
of silently skipping the evidence checks. No hardware verification is mocked.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import generate as rules

VECTOR_DIR = Path(__file__).resolve().parent / "vectors"
VECTORS = sorted(VECTOR_DIR.glob("*.json"))
REJECTION_REASONS = {
    "reject-collateral-required": "collateral 'required' disagrees with tdx-quote-v4",
    "reject-forged-quote": "evidence signature or PCK chain did not verify",
    "reject-measurement-mismatch": "runtime.measurement .* is not the MRTD",
    "reject-evidence-swapped-after-signing": "record envelope failed: InvalidSignature",
    "reject-platform-not-the-evidence": "platform 'amd-sev-snp' is not what this evidence roots",
}


def _record(name: str) -> dict:
    return json.loads((VECTOR_DIR / f"{name}.json").read_text(encoding="utf-8"))["record"]


@pytest.mark.parametrize("path", VECTORS, ids=lambda path: path.stem)
def test_appraisal_matches_committed_expectation(path: Path) -> None:
    vector = json.loads(path.read_text(encoding="utf-8"))
    record, expected = vector["record"], vector["expected"]
    if expected["grade"] == "reject":
        with pytest.raises(rules.Reject, match=REJECTION_REASONS[path.stem]):
            rules.appraise(record)
        return
    grade = rules.appraise(record)
    assert grade == expected["grade"]
    assert rules.grade_model_claim(record, grade) == expected["model_claim"]


@pytest.mark.parametrize(
    "name", ["downgrade-evidence-by-reference", "downgrade-unsupported-format"]
)
def test_collateral_does_not_override_unverified_evidence(name: str) -> None:
    record = _record(name)
    record["runtime"]["evidence"]["collateral"] = "required"
    key = Ed25519PrivateKey.from_private_bytes(rules.PUBLISHED_TEST_KEY)
    record = rules.sign_record(rules._unsigned(record), key)
    assert rules.appraise(record) == "unattested"


def test_matching_commitment_uses_the_unchanged_genuine_quote() -> None:
    accept = _record("accept-real-quote-platform-attested")
    record = _record("commitment-cannot-attest-model")
    quote = record["runtime"]["evidence"]["quote"]
    assert quote == accept["runtime"]["evidence"]["quote"]
    assert record["model"]["weights_digest"] == (
        "sha256:" + rules.parse_tdx_quote(rules.unb64u(quote)).report_data[:32].hex()
    )
    grade = rules.appraise(record)
    assert grade == "platform-attested"
    assert rules.grade_model_claim(record, grade) == "model claim: self-reported"


@pytest.mark.parametrize("grade", ["unattested", "platform-attested", "attested"])
def test_model_claim_does_not_inherit_the_record_grade(grade: str) -> None:
    # This checks the claim-grading policy with a supplied record grade. It does not
    # claim a captured quote reaches `attested`; no capture here binds the cnf key.
    record = _record("commitment-cannot-attest-model")
    assert rules.grade_model_claim(record, grade) == "model claim: self-reported"
    absent = copy.deepcopy(record)
    del absent["model"]["weights_digest"]
    assert rules.grade_model_claim(absent, grade) == "model claim: absent"


def test_regeneration_matches_committed_vectors(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(Path(rules.__file__)), "--out", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    generated = sorted(tmp_path.glob("*.json"))
    assert {path.name for path in generated} == {path.name for path in VECTORS}
    for path in generated:
        assert path.read_bytes() == (VECTOR_DIR / path.name).read_bytes(), path.name

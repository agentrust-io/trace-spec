"""The reproducibility-claim vectors, held to what they say. Spec section 3.1.4.

`examples/reproducibility-claim/` pins the shape rules the schema holds for the claim
and its result. Three things are asserted here on every vector: both validators, the
schema and the reference model, return the verdict the vector expects; a rejected vector
fails where its code says it does and nowhere else, so a rejection for an unrelated
reason cannot pass as coverage of the rule; and the signature verifies, rejected records
included, because the subject of each rejection is the schema and not the signature.

The digests that can be recomputed are recomputed: `transcript_digest` and every closure
`digest` against the values carried under `context`, and vector 03's `observed_digest`
against the transcript that differs. That is the preimage rule the section fixes, and a
set that carried digests nothing checked would be a set of placeholders all the way down.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest
import rfc8785
from pydantic import ValidationError

from agentrust_trace import TrustRecord, iter_errors
from agentrust_trace.sign import _canonical_bytes, _pubkey_from_jwk

VECTOR_DIR = pathlib.Path(__file__).resolve().parents[1] / "examples" / "reproducibility-claim"
VECTORS = sorted(VECTOR_DIR.glob("*.json"))
IDS = [p.stem for p in VECTORS]

#: Where each code's rejection is reported: the path an error must sit at, and the
#: prefix every error must sit under. A vector whose errors include one outside the
#: prefix is rejected for something other than its rule.
LOCUS: dict[str, tuple[str, str]] = {
    "re_execution_without_method": ("appraisal", "appraisal"),
    "method_without_re_execution": ("appraisal", "appraisal"),
    "diverged_without_observed_digest": ("appraisal.re_execution", "appraisal.re_execution"),
    "not_attempted_without_reason": ("appraisal.re_execution", "appraisal.re_execution"),
    "closure_entry_incomplete": ("reproducibility.input_closure", "reproducibility.input_closure"),
    "unknown_method": ("appraisal.method", "appraisal"),
    "unknown_outcome": ("appraisal.re_execution.outcome", "appraisal.re_execution.outcome"),
    "claim_incomplete": ("reproducibility", "reproducibility"),
}


def _load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def test_the_corpus_did_not_shrink() -> None:
    """Pinned, so deleting an awkward vector is a visible act rather than a quiet one."""
    assert len(VECTORS) == 21


def test_every_code_is_carried_by_two_vectors() -> None:
    """#124's margin, stated here as well as measured in the adequacy suite, so this
    file says what the set promises rather than leaving it to the reader."""
    by_code: dict[str, list[str]] = {}
    for path in VECTORS:
        for code in _load(path)["expected"]["codes"]:
            by_code.setdefault(code, []).append(path.stem)
    assert set(by_code) == set(LOCUS), "a code without a locus, or a locus without a code"
    thin = {code: names for code, names in by_code.items() if len(names) < 2}
    assert not thin, f"codes carried by one vector: {thin}"


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_the_schema_returns_the_expected_verdict(path: pathlib.Path) -> None:
    doc = _load(path)
    errors = iter_errors(doc["record"])
    if doc["expected"]["outcome"] == "accept":
        assert not errors, [e.message for e in errors]
        return
    assert errors, "the schema accepts a record the vector says it refuses"
    (code,) = doc["expected"]["codes"]
    at, under = LOCUS[code]
    paths = {".".join(str(k) for k in e.absolute_path) for e in errors}
    assert any(p == at or p.startswith(at + ".") for p in paths), (
        f"{code} is reported at {at}; the schema reported at {sorted(paths)}")
    outside = sorted(p for p in paths if not (p == under or p.startswith(under + ".")))
    assert not outside, (
        f"{path.stem} is also rejected at {outside}, outside {under}: the vector fails "
        "for something other than its rule")


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_the_model_returns_the_same_verdict(path: pathlib.Path) -> None:
    """The reference model is the other artifact a producer builds against; a record
    it accepts and the schema refuses is one no other implementation validates."""
    doc = _load(path)
    if doc["expected"]["outcome"] == "accept":
        parsed = TrustRecord.model_validate(doc["record"])
        # The round trip is identity: absent optionals stay absent, so the bytes the
        # model writes are the bytes the signature was taken over.
        assert parsed.model_dump() == doc["record"]
        return
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(doc["record"])


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_the_signature_verifies(path: pathlib.Path) -> None:
    record = _load(path)["record"]
    encoded = record["signature"]
    signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    _pubkey_from_jwk(record["cnf"]["jwk"]).verify(signature, body)


WITH_CONTEXT = [p for p in VECTORS if "context" in _load(p)]


@pytest.mark.parametrize("path", WITH_CONTEXT, ids=[p.stem for p in WITH_CONTEXT])
def test_the_digests_recompute_from_the_context(path: pathlib.Path) -> None:
    """The preimage is RFC 8785 over a JSON value, the one canonicalisation section
    3.2.2 already requires, so a verifier carries exactly one."""
    doc = _load(path)
    claim, context = doc["record"]["reproducibility"], doc["context"]
    assert claim["transcript_digest"] == _digest(context["transcript"])
    entries = {entry["id"]: entry["digest"] for entry in claim["input_closure"]}
    assert entries == {name: _digest(blob) for name, blob in context["closure"].items()}


def test_the_diverged_vector_observed_a_different_transcript() -> None:
    doc = _load(VECTOR_DIR / "03-diverged-carries-the-observed-digest.json")
    observed = doc["record"]["appraisal"]["re_execution"]["observed_digest"]
    assert observed == _digest(doc["context"]["observed_transcript"])
    assert observed != doc["record"]["reproducibility"]["transcript_digest"], (
        "a diverged result whose digest equals the claim's is not a divergence")


def test_the_claim_does_not_move_the_platform() -> None:
    """Section 3.1.4 rule 2, on the accepting vectors: every record carrying the claim
    is software-only, with the all-zero measurement a dev-mode record carries. The
    claim is not attestation and the set does not let a record read as if it were."""
    for path in VECTORS:
        record = _load(path)["record"]
        assert record["runtime"]["platform"] == "software-only", path.stem

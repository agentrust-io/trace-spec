"""The runtime-evidence corpus, measured as far as this repository honestly can.

`docs/rfcs/runtime-evidence-profile.md` proposes that a record carry its attestation
evidence, and its own §8 says TRACE must not become an attestation verifier: `format`
selects someone else's. That commitment decides what this file can assert.

**In scope here**, and asserted unconditionally on every vector: the committed records
are schema-valid against the draft schema, their signatures verify over the RFC 8785
canonical form, the evidence member is shaped as the profile describes, and each vector
carries the expectation the corpus grades it against.

**Out of scope here**, deliberately: whether a quote verifies. That needs a TDX
verifier, this project does not ship one, and the proposal argues it should not start.
`examples/runtime-evidence/generate.py` performs that half against `agent-manifest`'s
verifier and reports 9/9.

The split is stated rather than hidden because a test that quietly skipped the
hardware half would look like coverage and be none, which is the defect the profile is
about. What is measured here is measured on every run; what is not is named.
"""

from __future__ import annotations

import base64
import json
import pathlib

import jsonschema
import pytest
from cryptography.exceptions import InvalidSignature

from agentrust_trace.sign import _canonical_bytes, _pubkey_from_jwk

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTOR_DIR = REPO_ROOT / "examples" / "runtime-evidence" / "vectors"
DRAFT_SCHEMA = json.loads(
    (REPO_ROOT / "schema" / "trace-claim-v0.3-draft.json").read_text(encoding="utf-8")
)

GRADES = {"unattested", "platform-attested", "attested"}


def _vectors() -> list[pathlib.Path]:
    found = sorted(VECTOR_DIR.glob("*.json"))
    assert found, "no vectors on disk; this file would be measuring nothing"
    return found


VECTORS = _vectors()
IDS = [p.stem for p in VECTORS]


def _load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_corpus_did_not_shrink() -> None:
    """Pinned, so deleting an awkward vector is a visible act rather than a quiet one.

    The count is the whole assertion: which vectors exist is the generator's business,
    but a set that can silently lose its inconvenient members measures nothing.
    """
    assert len(VECTORS) == 10


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_vector_carries_its_expectation(path: pathlib.Path) -> None:
    expected = _load(path)["expected"]
    assert expected["grade"] in GRADES | {"reject"}
    # A rejected record has no model claim to grade, and a graded one always does.
    if expected["grade"] == "reject":
        assert expected["model_claim"] is None
    else:
        assert expected["model_claim"] is not None


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_record_is_valid_against_the_draft_schema(path: pathlib.Path) -> None:
    """Every vector, including the ones the profile rejects.

    A record the rules refuse must still be a well-formed record, or the vector is
    testing the schema instead of the rule it was written for. The one exception is
    the record that is invalid on purpose, and there isn't one: every rejection in
    this corpus is a rejection on the evidence, not on the shape.
    """
    jsonschema.validate(_load(path)["record"], DRAFT_SCHEMA)


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_record_signature_verifies(path: pathlib.Path) -> None:
    """Except the one vector whose whole subject is a signature that must not verify."""
    record = _load(path)["record"]
    signature = base64.urlsafe_b64decode(
        record["signature"] + "=" * (-len(record["signature"]) % 4)
    )
    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    public_key = _pubkey_from_jwk(record["cnf"]["jwk"])

    if path.stem == "reject-evidence-swapped-after-signing":
        # Named, not blind: this vector's whole subject is that the substitution is
        # caught by the signature, so "something raised" is not the assertion. It has
        # to be the signature that failed.
        with pytest.raises(InvalidSignature):
            public_key.verify(signature, body)
        return
    public_key.verify(signature, body)


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_evidence_member_is_shaped_as_the_profile_describes(path: pathlib.Path) -> None:
    evidence = (_load(path)["record"].get("runtime") or {}).get("evidence")
    if evidence is None:
        assert path.stem == "downgrade-evidence-absent"
        return
    # §3: exactly one of the inline and by-reference forms, never both and never
    # neither. The schema says this too; asserting it here keeps the corpus honest if
    # the schema is ever loosened.
    assert ("quote" in evidence) != ("quote_digest" in evidence)


def test_the_accept_vector_does_not_claim_the_top_grade() -> None:
    """§7.2, pinned so it cannot drift without someone noticing.

    No capture this project holds binds a record-signing key, so `attested` is not
    reachable from any artifact here and the happy path grades `platform-attested`.
    The day a capture does bind one, this test fails and the claim in §7.2 gets
    rewritten deliberately rather than quietly going stale.
    """
    expected = _load(VECTOR_DIR / "accept-real-quote-platform-attested.json")["expected"]
    assert expected["grade"] == "platform-attested"
    assert expected["model_claim"] == "model claim: self-reported"


def test_no_vector_in_the_corpus_reaches_attested() -> None:
    grades = {_load(p)["expected"]["grade"] for p in VECTORS}
    assert "attested" not in grades, (
        "a vector now claims the top grade; §7.2 says it is unreachable from the "
        "captures this project holds, so either that changed or the vector is wrong"
    )

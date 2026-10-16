"""v0.3 draft fixtures for trace-spec#483: a signed record names the agent manifest it ran under.

No module implements the reference yet, so the draft rule is stated here as a small reference
checker. The record signature is verified first (§3.3 step 1); the manifest reference is then
appraised by recomputing sha256 over the bytes the resolver returns for ``manifest.id``. A
``manifest_verification_result`` the producer wrote is never read. Four wrong checkers must each
be caught by at least one fixture.
"""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VECTOR_DIR = Path(__file__).parent / "vectors" / "manifest-ref-v0.3-draft"
VECTORS = [
    json.loads(p.read_text(encoding="utf-8")) for p in sorted(VECTOR_DIR.glob("[0-9][0-9]-*.json"))
]
MUTANTS = (
    "trusts_asserted_result",
    "unresolved_is_pass",
    "manifest_before_signature",
    "rejects_record_on_unresolved",
)


def _b64u(s: str) -> bytes:
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(b).rstrip(b"=").decode() != s:
        raise ValueError("non-canonical base64url")
    return b


def _signature_ok(rec: dict) -> bool:
    try:
        jwk = rec["cnf"]["jwk"]
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return False
        body = {k: v for k, v in rec.items() if k != "signature"}
        Ed25519PublicKey.from_public_bytes(_b64u(jwk["x"])).verify(
            _b64u(rec["signature"]), rfc8785.dumps(body)
        )
        return True
    except Exception:
        return False


def check(vector: dict, mutant: str | None = None) -> dict:
    rec, store = vector["record"], vector["resolver"]
    if mutant != "manifest_before_signature" and not _signature_ok(rec):
        return {"record": "signature-invalid", "manifest": "not-evaluated"}
    ref = rec.get("manifest")
    if ref is None:
        return {"record": "valid", "manifest": "no-manifest-named"}
    if mutant == "trusts_asserted_result" and rec.get("manifest_verification_result") == "verified":
        return {"record": "valid", "manifest": "established"}
    if ref.get("id") not in store:
        if mutant == "unresolved_is_pass":
            return {"record": "valid", "manifest": "established"}
        if mutant == "rejects_record_on_unresolved":
            return {"record": "manifest-unresolved", "manifest": "not-evaluated"}
        return {"record": "valid", "manifest": "manifest-unresolved"}
    got = "sha256:" + hashlib.sha256(store[ref["id"]].encode("utf-8")).hexdigest()
    return {
        "record": "valid",
        "manifest": "established" if got == ref.get("digest") else "manifest-digest-mismatch",
    }


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_manifest_reference_vector(vector):
    assert check(vector) == vector["expected"]


@pytest.mark.parametrize("mutant", MUTANTS)
def test_each_wrong_checker_is_caught(mutant):
    assert any(check(v, mutant) != v["expected"] for v in VECTORS)


def test_editing_the_signed_digest_fails_the_signature():
    rec = copy.deepcopy(VECTORS[0]["record"])
    d = rec["manifest"]["digest"]
    rec["manifest"]["digest"] = d[:-1] + ("0" if d[-1] != "0" else "1")
    assert not _signature_ok(rec)


def test_fixtures_are_reproducible():
    spec = importlib.util.spec_from_file_location(
        "manifest_ref_generator", VECTOR_DIR / "generate.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.vectors() == VECTORS

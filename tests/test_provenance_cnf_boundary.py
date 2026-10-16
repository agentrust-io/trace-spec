from __future__ import annotations

import base64

import pytest

from agentrust_trace.provenance import ProvenanceError, build_record, verify_record
from agentrust_trace.sign import _canonical_bytes, generate_key, key_to_jwk

TOOLS = [
    {
        "name": "search",
        "description": "search the docs",
        "input_schema": {"type": "object"},
    }
]
ARTIFACT = {
    "package": "pkg:npm/%40acme/mcp-search@2.1.0",
    "digest": "sha256:" + "a" * 64,
}
_MISSING = object()


def _signed_with_cnf(cnf: object = _MISSING):
    key = generate_key()
    record = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=TOOLS,
        artifact=ARTIFACT,
    )
    if cnf is not _MISSING:
        record["cnf"] = cnf
    body = _canonical_bytes(record)
    signature = base64.urlsafe_b64encode(key.sign(body)).rstrip(b"=").decode()
    return {**record, "signature": signature}, key_to_jwk(key)


@pytest.mark.parametrize(
    "bad_cnf",
    [
        "not-an-object",
        ["unexpected"],
        1,
        True,
        "",
        [],
        0,
        False,
    ],
)
def test_non_object_cnf_is_refused_through_provenance_error(bad_cnf) -> None:
    record, trusted = _signed_with_cnf(bad_cnf)
    with pytest.raises(ProvenanceError, match="cnf must be an object"):
        verify_record(record, trusted)


@pytest.mark.parametrize("cnf", [_MISSING, None, {}, {"jwk": None}, {"jwk": {}}])
def test_missing_or_empty_cnf_jwk_is_refused(cnf) -> None:
    record, trusted = _signed_with_cnf(cnf)
    with pytest.raises(ProvenanceError, match="no cnf.jwk"):
        verify_record(record, trusted)


def test_valid_embedded_cnf_jwk_still_verifies() -> None:
    key = generate_key()
    trusted = key_to_jwk(key)
    record = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=TOOLS,
        artifact=ARTIFACT,
    )
    record["cnf"] = {"jwk": trusted}
    body = _canonical_bytes(record)
    record["signature"] = base64.urlsafe_b64encode(key.sign(body)).rstrip(b"=").decode()

    verify_record(record, trusted)


# ---------------------------------------------------------------------------
# GHSA-vc4p-h84j-7qxj: cnf.jwk accepted private key material, so a record could
# publish the key that signed it.
#
# RFC 8747 defines cnf as a confirmation key: the public half, present so a
# verifier can bind the record to the key that signed it. models.TrustRecord
# already refused d/p/q/dp/dq/qi/k, but the verification path validates against
# the schema rather than the model, and the schema's jwk block carried no
# constraint on private members. No attacker is involved; this is a producer
# mistake the format did not defend against, and the consequence is durable:
# the record is signed, self-authenticating and typically anchored, so the only
# remedy after the fact is to revoke the identity.
# ---------------------------------------------------------------------------

_PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k"]


def _jwk_schema():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schema" / "trace-claim.json").read_text(encoding="utf-8"))
    return schema["properties"]["cnf"]["properties"]["jwk"]


@pytest.mark.parametrize("member", _PRIVATE_JWK_MEMBERS)
def test_schema_refuses_private_key_material_in_cnf_jwk(member: str) -> None:
    import jsonschema

    validator = jsonschema.Draft202012Validator(_jwk_schema())
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "abc", member: "SECRET"}

    assert not validator.is_valid(jwk)


def test_schema_still_accepts_an_ordinary_public_jwk() -> None:
    import jsonschema

    validator = jsonschema.Draft202012Validator(_jwk_schema())

    assert validator.is_valid({"kty": "OKP", "crv": "Ed25519", "x": "abc"})
    assert validator.is_valid({"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"})


def test_the_two_schema_copies_stay_in_step() -> None:
    """schema/ is the published artifact, src/ is what the package ships."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    published = (root / "schema" / "trace-claim.json").read_bytes()
    packaged = (root / "src" / "agentrust_trace" / "schema" / "trace-v0.2.json").read_bytes()

    assert published == packaged

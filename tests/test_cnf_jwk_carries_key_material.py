"""A confirmation key that names a key type has to carry that type's key material.

`schema/trace-claim.json` says of the confirmation key: *"Keys must carry actual key
material"*. It enforced that for `OKP` and `EC` and for nothing else, so a `cnf.jwk` of
`{"kty": "RSA"}` with no `n` and no `e` validated, and the record then failed inside the
verifier with `jwk_thumbprint`'s "missing required thumbprint member 'e'". Nothing was
accepted that should have been refused, since every path downstream fails closed. What was
wrong is which instrument spoke: the schema is the artifact an implementation in any
language validates against, and it was not the thing that told the producer the key was
unusable.

`RSA` is added here rather than a `kty` enum. `sign.jwk_thumbprint` already knows the three
types this now covers, and requiring their members states what the schema already claims.
Narrowing `kty` to a fixed set would be a different act: section 3.2.1 states signing
algorithms per envelope context and fixes no set for the embedded-signature form of section
3.2.2, so a schema-level enum would add a constraint the specification does not make, which
is a normative question and not a schema fix.

`models.JWK` carried the same `OKP`/`EC`-only table and is corrected with it. The schema is
what another language validates against and the model is what a Python caller reaches, so
the last test here checks the two against each other on every case rather than trusting that
a fix applied to one of them reached the other.
"""

from __future__ import annotations

import copy
import json
import pathlib
from typing import Any

import jsonschema
import pydantic
import pytest

from agentrust_trace.models import TrustRecord

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "trace-claim.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)

BASE: dict[str, Any] = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1750000000,
    "subject": "spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://agt.example.org/verifier"},
    "cnf": {
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }
    },
}


def _with_jwk(jwk: dict[str, Any]) -> dict[str, Any]:
    record = copy.deepcopy(BASE)
    record["cnf"]["jwk"] = jwk
    return record


def test_the_base_record_is_valid() -> None:
    """Without this the refusals below would prove nothing about the key."""
    VALIDATOR.validate(BASE)


@pytest.mark.parametrize(
    "jwk",
    [
        pytest.param({"kty": "RSA"}, id="rsa-with-no-material"),
        pytest.param({"kty": "RSA", "n": "0vx7ag"}, id="rsa-with-no-exponent"),
        pytest.param({"kty": "RSA", "e": "AQAB"}, id="rsa-with-no-modulus"),
    ],
)
def test_an_rsa_confirmation_key_without_its_material_is_refused(jwk: dict[str, Any]) -> None:
    with pytest.raises(jsonschema.ValidationError) as caught:
        VALIDATOR.validate(_with_jwk(jwk))
    assert "is a required property" in str(caught.value)


def test_the_rsa_members_have_to_be_strings() -> None:
    """The `n` and `e` declarations are load-bearing, not decoration.

    Without them a modulus reaches `additionalProperties`, which admits any
    canonicalizable value, so `{"n": 123}` would validate and carry an integer where
    base64url was meant. Deleting them from the schema has to fail something.
    """
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(_with_jwk({"kty": "RSA", "n": 123, "e": "AQAB"}))


def test_a_complete_rsa_confirmation_key_validates() -> None:
    """The rule is about missing material, not about refusing the key type."""
    VALIDATOR.validate(_with_jwk({"kty": "RSA", "n": "0vx7ag", "e": "AQAB"}))


@pytest.mark.parametrize(
    "jwk,missing",
    [
        pytest.param({"kty": "OKP"}, "crv", id="okp"),
        pytest.param({"kty": "EC", "crv": "P-256", "x": "f83OJ3D2"}, "y", id="ec"),
    ],
)
def test_the_two_types_that_were_already_covered_still_are(
    jwk: dict[str, Any], missing: str
) -> None:
    with pytest.raises(jsonschema.ValidationError) as caught:
        VALIDATOR.validate(_with_jwk(jwk))
    assert missing in str(caught.value)


def test_the_packaged_schema_is_the_same_bytes() -> None:
    """Two copies ship. A fix applied to one of them is not a fix."""
    published = (ROOT / "schema" / "trace-claim.json").read_bytes()
    packaged = (ROOT / "src" / "agentrust_trace" / "schema" / "trace-v0.2.json").read_bytes()
    assert published == packaged


JWK_CASES = [
    pytest.param(BASE["cnf"]["jwk"], True, id="okp-complete"),
    pytest.param({"kty": "OKP"}, False, id="okp-bare"),
    pytest.param({"kty": "OKP", "crv": "Ed25519"}, False, id="okp-without-x"),
    pytest.param(
        {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2", "y": "x_FEzRu9"}, True, id="ec-complete"
    ),
    pytest.param({"kty": "EC", "crv": "P-256", "x": "f83OJ3D2"}, False, id="ec-without-y"),
    pytest.param({"kty": "RSA", "n": "0vx7ag", "e": "AQAB"}, True, id="rsa-complete"),
    pytest.param({"kty": "RSA"}, False, id="rsa-bare"),
    pytest.param({"kty": "RSA", "n": "0vx7ag"}, False, id="rsa-without-e"),
    pytest.param({"kty": "RSA", "e": "AQAB"}, False, id="rsa-without-n"),
    pytest.param({"kty": "RSA", "n": 123, "e": "AQAB"}, False, id="rsa-with-a-non-string-modulus"),
    pytest.param({"kty": "AKP", "pub": "x"}, True, id="a-kty-neither-artifact-names"),
]


@pytest.mark.parametrize("jwk,accepted", JWK_CASES)
def test_the_schema_and_the_model_agree_on_every_case(jwk: dict[str, Any], accepted: bool) -> None:
    """Two artifacts decide whether a confirmation key is usable, and they must agree.

    `schema/trace-claim.json` is what an implementation in another language validates
    against; `models.JWK` is what a Python caller reaches, and it is exported. A producer
    meets them in an order nobody controls, so a key one takes and the other refuses fails
    somewhere unpredictable. Half of this fix was exactly that state: the schema required
    `n` and `e` and the model still did not, which is the disagreement
    `test_all_three_layers_draw_the_line_in_the_same_place` was written for on a different
    field. This is the same instrument for this one.

    The last case is the deliberate open end. Neither artifact holds a `kty` it does not
    name to a key-material rule, because section 3.2.1 fixes no set for the
    embedded-signature form of section 3.2.2. They agree on that too.
    """
    record = _with_jwk(jwk)
    schema_ok = not list(VALIDATOR.iter_errors(record))
    try:
        TrustRecord.model_validate(record)
        model_ok = True
    except pydantic.ValidationError:
        model_ok = False
    assert schema_ok == model_ok == accepted, (
        f"schema={schema_ok} model={model_ok}, expected {accepted}. A confirmation key one "
        "artifact takes and the other refuses fails somewhere the producer did not choose."
    )

"""`TrustRecord.model_validate(record).model_dump()` has to give the record back.

`sign_record`'s docstring points a caller at exactly this round trip: pass the returned
dict to `TrustRecord.model_validate()` to confirm structural validity before writing. A
caller who then wrote the model out wrote a different record. Pydantic serializes every
unset optional as an explicit `null`, the schema permits `null` for no named field, and
the added members change the RFC 8785 canonical bytes the signature is taken over. So:

    validate_json(TrustRecord.model_validate(record).model_dump())
    ValueError: ... None is not of type 'string'

    verify_record(TrustRecord.model_validate(record).model_dump(), jwk)
    InvalidSignature

Two artifacts of this package disagreeing about one record, and neither the validator nor
the signature check runs at the moment the damage is done: the caller has a model in hand
and a `model_dump` that looks like a record.

The fix omits absent optionals. It has to omit only *declared* ones: `JWK` sets
`extra="allow"` and the schema's `canonicalizableValue` permits a null there, so a null
inside `cnf.jwk` is data. A first version filtered the whole serialized dict and removed
it, which is the same defect one level down.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from agentrust_trace import (TrustRecord, generate_key, key_to_jwk, sign_record,
                             validate_json, verify_record)

KEY = generate_key()
JWK = key_to_jwk(KEY)

#: The optional members pydantic used to write as `null`. Named rather than counted, so
#: this says what it prevents.
ABSENT_OPTIONALS = ("transparency", "tool_transcript", "delegation", "origin", "references")


def _record(**over: Any) -> dict[str, Any]:
    base = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": 1750000000,
        "subject": "did:mesh:spiffe://factory.example/agent/payments/prod",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
        "data_class": "confidential",
        "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
        "appraisal": {"status": "affirming", "verifier": "https://agt.example.org/verifier"},
    }
    base.update(over)
    return sign_record(base, KEY)


def test_the_starting_record_is_valid_and_verifies() -> None:
    """The control. Everything below compares against this, and a fixture that was
    already broken would make each comparison a comparison of two failures."""
    record = _record()
    validate_json(record)
    verify_record(record, JWK, max_age_seconds=None)


@pytest.mark.parametrize("dump", ["model_dump", "model_dump_json"])
def test_the_round_trip_returns_the_same_record(dump: str) -> None:
    record = _record()

    model = TrustRecord.model_validate(record)
    out = model.model_dump() if dump == "model_dump" else json.loads(model.model_dump_json())

    assert out == record, (
        f"{dump}() did not give the record back. Added: "
        f"{sorted(set(out) - set(record))}; dropped: {sorted(set(record) - set(out))}"
    )


@pytest.mark.parametrize("dump", ["model_dump", "model_dump_json"])
def test_the_round_trip_still_validates_and_still_verifies(dump: str) -> None:
    """Asserted separately from identity, because a serialization could differ from the
    input in some harmless way and still be a record. These are the two properties that
    actually matter to a caller, and they were both false."""
    model = TrustRecord.model_validate(_record())
    out = model.model_dump() if dump == "model_dump" else json.loads(model.model_dump_json())

    validate_json(out)
    verify_record(out, JWK, max_age_seconds=None)


@pytest.mark.parametrize("field", ABSENT_OPTIONALS)
def test_an_absent_optional_is_absent_and_not_null(field: str) -> None:
    out = TrustRecord.model_validate(_record()).model_dump()

    assert field not in out, (
        f"{field} was written as {out[field]!r}. The schema types it non-nullable, so a "
        "record carrying it as null is rejected by every implementation validating "
        "against the published schema, including this package's own validate_json."
    )


def test_an_optional_that_is_present_survives() -> None:
    """Without this, a serializer that dropped every optional would pass everything
    above."""
    record = _record(transparency="https://rekor.example/api/v1/log/entries/x")

    out = TrustRecord.model_validate(record).model_dump()

    assert out["transparency"] == "https://rekor.example/api/v1/log/entries/x"


def test_a_null_a_caller_put_in_cnf_jwk_is_data_and_survives() -> None:
    """`JWK` allows extra members and the schema's `canonicalizableValue` permits a null
    among them, so this one is not an unset field and must not be filtered.

    The signature is not asserted here: the extra is added after signing, which changes
    the record, so a mismatch would be the fixture's doing rather than the serializer's.
    Identity and schema validity are the properties in question.
    """
    record = _record()
    record["cnf"]["jwk"]["x5t#S256"] = None
    validate_json(record)

    out = TrustRecord.model_validate(record).model_dump()

    assert out == record, "a null extra in cnf.jwk was filtered as though it were unset"

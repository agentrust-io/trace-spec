"""`SCHEMA` is handed to callers. Mutating it must not reconfigure the verifier.

`validate.py` exposes it with the comment "exposed for downstream tooling that needs the
raw dict", and `_schema()` is `lru_cache(maxsize=1)` with `_validator()` built over
whatever it returns. So the exported name *was* the live object, and the ordinary thing to
do with a dict you were handed to adapt, mutate it, silently reconfigured `validate_json`,
`iter_errors`, and the structural gate inside `sign.verify_record`, for every later call in
the process.

Nothing about the call site looks wrong. `s = SCHEMA` then `s["properties"][...] = ...` is
what a caller building a variant writes.
"""
from __future__ import annotations

import copy
from typing import Any

import jsonschema
import pytest

from agentrust_trace import SCHEMA, validate_json
from agentrust_trace.validate import _schema

RECORD: dict[str, Any] = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1750000000,
    "subject": "did:mesh:spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://agt.example.org/verifier"},
    "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519",
                    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
}


def test_the_record_is_valid_and_a_1970_one_is_not() -> None:
    """The control, and the thing the mutation below tries to change."""
    validate_json(RECORD)
    with pytest.raises(jsonschema.ValidationError):
        validate_json(dict(RECORD, iat=1))


def test_the_export_is_not_the_object_the_validator_reads() -> None:
    assert SCHEMA is not _schema(), (
        "SCHEMA is the live cached schema. A caller adapting it reconfigures the "
        "verifier for the whole process."
    )
    assert SCHEMA == _schema(), "the copy has drifted from the schema it copies"


def test_mutating_the_export_does_not_weaken_validation() -> None:
    """The behaviour, not only the identity. Two objects that are `is not` each other can
    still share nested dicts, and a shallow copy would pass the test above."""
    original = copy.deepcopy(SCHEMA)
    try:
        SCHEMA["properties"]["iat"]["minimum"] = 0

        with pytest.raises(jsonschema.ValidationError):
            validate_json(dict(RECORD, iat=1))
    finally:
        SCHEMA.clear()
        SCHEMA.update(original)


def test_deleting_from_the_export_does_not_weaken_validation() -> None:
    """Removal, not only alteration: dropping `required` is the widest single edit."""
    original = copy.deepcopy(SCHEMA)
    try:
        SCHEMA.pop("required", None)

        with pytest.raises(jsonschema.ValidationError):
            validate_json({"eat_profile": "tag:agentrust-io.com,2026:trace-v0.2"})
    finally:
        SCHEMA.clear()
        SCHEMA.update(original)


def test_the_export_still_carries_the_whole_schema() -> None:
    """Without this, exporting an empty dict would pass everything above."""
    assert SCHEMA["properties"]["iat"]["minimum"] == 1700000000
    assert "build_provenance" in SCHEMA["required"]
    assert len(SCHEMA["properties"]) >= 12

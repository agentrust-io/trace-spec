"""validate_json and iter_errors against canonical examples."""

import json
from pathlib import Path

import pytest

from agentrust_trace import SCHEMA, iter_errors, validate_json

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def _load(name: str) -> dict:
    # Examples must validate exactly as published: no preprocessing.
    return json.loads((EXAMPLES_DIR / name).read_text())


@pytest.mark.parametrize(
    "filename",
    ["intel-tdx.json", "amd-sev-snp.json", "nvidia-h100.json", "agent-bound-tdx.json"],
)
def test_examples_pass_json_schema(filename: str) -> None:
    validate_json(_load(filename))


def test_iter_errors_empty_on_valid() -> None:
    assert iter_errors(_load("intel-tdx.json")) == []


def test_invalid_eat_profile_fails() -> None:
    data = _load("intel-tdx.json")
    data["eat_profile"] = "wrong-profile"
    errors = iter_errors(data)
    assert errors, "expected at least one schema error"


def test_missing_required_field_fails() -> None:
    data = _load("intel-tdx.json")
    del data["subject"]
    errors = iter_errors(data)
    assert errors


def test_schema_is_dict() -> None:
    assert isinstance(SCHEMA, dict)
    assert SCHEMA.get("title") == "TRACE Trust Record"


def test_comment_key_fails() -> None:
    """additionalProperties is false: a _comment key must be rejected, including in examples."""
    data = _load("intel-tdx.json")
    data["_comment"] = "human note"
    errors = iter_errors(data)
    assert errors


def test_okp_jwk_without_key_material_fails() -> None:
    """cnf.jwk must carry key material: OKP requires crv and x."""
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {"kty": "OKP"}
    errors = iter_errors(data)
    assert errors


def test_ec_jwk_without_y_fails() -> None:
    """cnf.jwk must carry key material: EC requires crv, x, and y."""
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {"kty": "EC", "crv": "P-256", "x": "dGVzdA"}
    errors = iter_errors(data)
    assert errors


def test_okp_jwk_with_key_material_passes() -> None:
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }
    assert iter_errors(data) == []

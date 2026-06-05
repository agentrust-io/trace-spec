"""validate_json and iter_errors against canonical examples."""

import json
from pathlib import Path

import pytest

from agentrust_trace import SCHEMA, iter_errors, validate_json

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def _load(name: str) -> dict:
    data = json.loads((EXAMPLES_DIR / name).read_text())
    data.pop("_comment", None)
    return data


@pytest.mark.parametrize("filename", ["intel-tdx.json", "amd-sev-snp.json", "nvidia-h100.json"])
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

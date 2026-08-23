"""validate_json and iter_errors against canonical examples."""

import json
from pathlib import Path

import pytest

from agentrust_trace import SCHEMA, iter_errors, validate_json

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def _load(name: str) -> dict:
    # Examples must validate exactly as published: no preprocessing.
    return json.loads((EXAMPLES_DIR / name).read_text())


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


def test_delegation_passes_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["delegation"] = {
        "parent_record_hash": "sha256:" + "a" * 64,
        "credential_id": "cred-abc",
    }
    assert iter_errors(data) == []


def test_delegation_bad_digest_fails_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["delegation"] = {"parent_record_hash": "nope", "credential_id": "c"}
    assert iter_errors(data)


def test_origin_self_passes_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["origin"] = {"kind": "self", "producer": "cmcp/0.4.0"}
    assert iter_errors(data) == []


def test_origin_third_party_on_software_only_passes_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["runtime"]["platform"] = "software-only"
    data["origin"] = {
        "kind": "third-party-control-plane",
        "producer": "vendor-gateway/2.1",
        "source_event_id": "evt-7f3a",
        "ingested_at": 1760000000,
    }
    assert iter_errors(data) == []


def test_origin_third_party_with_hardware_fails_json_schema() -> None:
    """The cross-field rule has to hold for a validator that never sees the Python model."""
    data = _load("intel-tdx.json")
    data["origin"] = {"kind": "third-party-control-plane", "producer": "vendor-gateway/2.1"}
    assert iter_errors(data)


def test_origin_unknown_kind_fails_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["runtime"]["platform"] = "software-only"
    data["origin"] = {"kind": "vendor-asserted", "producer": "vendor/1.0"}
    assert iter_errors(data)


def test_packaged_schema_matches_the_normative_schema() -> None:
    """The packaged copy must say the same thing as ``schema/trace-claim.json``.

    ``validate_json`` loads the packaged copy, while the spec, README and
    CONTRIBUTING all point a reader at the root file as the normative one. When the
    two drift, the schema someone reads is not the schema their record is checked
    against, and nothing fails: both files are individually valid.

    Compared as parsed JSON rather than as bytes, because the two files differ in
    line endings by long-standing accident (the root file is CRLF, the packaged one
    LF) and that changes nothing about how either validates a record.
    """
    repo_root = Path(__file__).parent.parent
    normative = json.loads((repo_root / "schema" / "trace-claim.json").read_text(encoding="utf-8"))
    packaged = json.loads(
        (repo_root / "src" / "agentrust_trace" / "schema" / "trace-v0.2.json").read_text(
            encoding="utf-8"
        )
    )
    assert packaged == normative, (
        "src/agentrust_trace/schema/trace-v0.2.json has drifted from the normative "
        "schema/trace-claim.json"
    )
    assert SCHEMA == normative, "the schema loaded at runtime is not the normative one"


@pytest.mark.parametrize(
    "subject",
    [
        "spiffe://trust.example.org/agent/payments-processor",
        "did:web:example.org:agent:payments-processor",
    ],
)
def test_both_subject_forms_pass_validate_json(subject: str) -> None:
    """The subject pattern the model and the normative schema accept, checked at runtime.

    This is the concrete shape the drift above took: the root file and ``models.py``
    accepted a DID subject, the packaged copy still required ``spiffe://``, so a record
    the specification permits was rejected by the reference validator.
    """
    data = _load("intel-tdx.json")
    data["subject"] = subject
    assert iter_errors(data) == []


def test_declared_enforcement_mode_passes_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["policy"]["enforcement_mode"] = "declared"
    assert iter_errors(data) == []


def test_unknown_enforcement_mode_fails_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["policy"]["enforcement_mode"] = "monitor"
    assert iter_errors(data)

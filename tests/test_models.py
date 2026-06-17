"""Parse all three canonical examples through TrustRecord."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentrust_trace import TrustRecord

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def _load(name: str) -> dict:
    # Examples must validate exactly as published: no preprocessing.
    return json.loads((EXAMPLES_DIR / name).read_text())


@pytest.mark.parametrize(
    "filename",
    ["intel-tdx.json", "amd-sev-snp.json", "nvidia-h100.json", "agent-bound-tdx.json"],
)
def test_example_parses(filename: str) -> None:
    record = TrustRecord.model_validate(_load(filename))
    assert record.eat_profile == "tag:agentrust.io,2026:trace-v0.1"
    assert record.subject.startswith(("spiffe://", "did:"))


def test_intel_tdx_fields() -> None:
    record = TrustRecord.model_validate(_load("intel-tdx.json"))
    assert record.runtime.platform == "intel-tdx"
    assert record.policy.enforcement_mode == "enforce"
    assert record.appraisal.status == "affirming"
    assert record.tool_transcript is not None
    assert record.tool_transcript.call_count == 7


def test_extra_fields_rejected() -> None:
    data = _load("intel-tdx.json")
    data["unknown_field"] = "should fail"
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_missing_required_field_rejected() -> None:
    data = _load("intel-tdx.json")
    del data["cnf"]
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_bad_digest_rejected() -> None:
    data = _load("intel-tdx.json")
    data["runtime"]["measurement"] = "not-a-digest"
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_bad_platform_rejected() -> None:
    data = _load("intel-tdx.json")
    data["runtime"]["platform"] = "unknown-cloud"
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


# CRYPTO-008 / CRYPTO-009: DigestStr regex enforcement

def test_digest_uppercase_rejected() -> None:
    """CRYPTO-008: uppercase hex must be rejected (sha256: is lowercase-only)."""
    data = _load("intel-tdx.json")
    data["runtime"]["measurement"] = "sha256:" + "A" * 64
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_digest_sha256_too_short_rejected() -> None:
    """CRYPTO-008/009: sha256 digest shorter than 64 chars must be rejected."""
    data = _load("intel-tdx.json")
    data["runtime"]["measurement"] = "sha256:" + "a" * 63
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_digest_sha256_exact_length_accepted() -> None:
    """sha256 digest with exactly 64 lowercase hex chars must be accepted."""
    data = _load("intel-tdx.json")
    data["runtime"]["measurement"] = "sha256:" + "a" * 64
    record = TrustRecord.model_validate(data)
    assert record.runtime.measurement == "sha256:" + "a" * 64


def test_digest_sha384_exact_length_accepted() -> None:
    """sha384 digest with exactly 96 lowercase hex chars must be accepted."""
    data = _load("intel-tdx.json")
    data["runtime"]["measurement"] = "sha384:" + "b" * 96
    record = TrustRecord.model_validate(data)
    assert record.runtime.measurement == "sha384:" + "b" * 96


def test_digest_sha512_rejected() -> None:
    """CRYPTO-009: unsupported algorithm sha512 must be rejected."""
    data = _load("intel-tdx.json")
    data["runtime"]["measurement"] = "sha512:" + "a" * 128
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


# cnf.jwk key material enforcement


def test_subject_accepts_did_uri() -> None:
    data = _load("intel-tdx.json")
    data["subject"] = "did:key:z6MkhaXgBZDvotzL8oCYaXeFuJArwvX6mDMsKTJVjtN7R"
    record = TrustRecord.model_validate(data)
    assert record.subject.startswith("did:")


def test_subject_accepts_did_web() -> None:
    data = _load("intel-tdx.json")
    data["subject"] = "did:web:example.org:agents:payments-processor"
    record = TrustRecord.model_validate(data)
    assert record.subject.startswith("did:")


def test_subject_rejects_http_scheme() -> None:
    data = _load("intel-tdx.json")
    data["subject"] = "https://example.org/agent"
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


# Optional agent-identity block (spec §3.1.1, issue #33)


def test_agent_block_absent_is_valid() -> None:
    """Records without an agent block remain valid (backward compatible)."""
    record = TrustRecord.model_validate(_load("intel-tdx.json"))
    assert record.agent is None


def test_agent_block_present_parses() -> None:
    data = _load("intel-tdx.json")
    data["agent"] = {
        "agent_id": "spiffe://factory.example/agent/material-movement/dev",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "binding": "svid-matched",
    }
    record = TrustRecord.model_validate(data)
    assert record.agent is not None
    assert record.agent.agent_id.startswith("spiffe://")
    assert record.agent.manifest_id == "0197739a-8c00-7000-8000-000000000001"
    assert record.agent.binding == "svid-matched"


def test_agent_id_rejects_http_scheme() -> None:
    data = _load("intel-tdx.json")
    data["agent"] = {"agent_id": "https://example.org/agent", "manifest_id": "abc"}
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_agent_block_extra_field_rejected() -> None:
    data = _load("intel-tdx.json")
    data["agent"] = {
        "agent_id": "spiffe://factory.example/agent/x",
        "manifest_id": "abc",
        "unexpected": "x",
    }
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_agent_block_requires_agent_id_and_manifest_id() -> None:
    """A present agent block must carry both binding fields; partial is rejected (#33)."""
    base = _load("intel-tdx.json")
    partials = (
        {},
        {"binding": "svid-matched"},
        {"agent_id": "spiffe://x/a"},
        {"manifest_id": "abc"},
    )
    for partial in partials:
        data = {**base, "agent": partial}
        with pytest.raises(ValidationError):
            TrustRecord.model_validate(data)


def test_agent_id_may_equal_subject() -> None:
    """The spec permits subject == agent.agent_id; it must not be rejected (#33)."""
    data = _load("intel-tdx.json")
    data["agent"] = {
        "agent_id": data["subject"],
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
    }
    record = TrustRecord.model_validate(data)
    assert record.agent.agent_id == record.subject


def test_agent_id_accepts_did_uri() -> None:
    """agent_id accepts a DID URI, not only SPIFFE (#33)."""
    data = _load("intel-tdx.json")
    data["agent"] = {
        "agent_id": "did:web:factory.example",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
    }
    record = TrustRecord.model_validate(data)
    assert record.agent.agent_id.startswith("did:")


def test_agent_block_binding_optional() -> None:
    """binding is optional; agent_id + manifest_id alone is valid (#33)."""
    data = _load("intel-tdx.json")
    data["agent"] = {
        "agent_id": "spiffe://factory.example/agent/x",
        "manifest_id": "abc",
    }
    record = TrustRecord.model_validate(data)
    assert record.agent.binding is None


def test_okp_jwk_without_key_material_rejected() -> None:
    """An OKP confirmation key with no crv/x carries no key material and binds nothing."""
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {"kty": "OKP"}
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_ec_jwk_without_y_rejected() -> None:
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {"kty": "EC", "crv": "P-256", "x": "dGVzdA"}
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_okp_jwk_with_key_material_accepted() -> None:
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }
    record = TrustRecord.model_validate(data)
    assert record.cnf.jwk.x is not None

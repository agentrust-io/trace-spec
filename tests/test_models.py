"""Parse all three canonical examples through TrustRecord."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentrust_trace import TrustRecord

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def _load(name: str) -> dict:
    data = json.loads((EXAMPLES_DIR / name).read_text())
    data.pop("_comment", None)  # examples carry a human note; not part of the schema
    return data


@pytest.mark.parametrize("filename", ["intel-tdx.json", "amd-sev-snp.json", "nvidia-h100.json"])
def test_example_parses(filename: str) -> None:
    record = TrustRecord.model_validate(_load(filename))
    assert record.eat_profile == "tag:agentrust.io,2026:trace-v0.1"
    assert record.subject.startswith("spiffe://")


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

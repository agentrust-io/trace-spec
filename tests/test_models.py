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


@pytest.mark.parametrize("filename", ["intel-tdx.json", "amd-sev-snp.json", "nvidia-h100.json"])
def test_example_parses(filename: str) -> None:
    record = TrustRecord.model_validate(_load(filename))
    assert record.eat_profile == "tag:agentrust-io.com,2026:trace-v0.2"
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


def test_jwk_with_private_key_material_rejected() -> None:
    """A cnf.jwk is a public key; private params (d, p, q, ...) must be rejected (#70)."""
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",  # private scalar: must not be stored
    }
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_delegation_block_parses() -> None:
    data = _load("intel-tdx.json")
    data["delegation"] = {
        "parent_record_hash": "sha256:" + "a" * 64,
        "credential_id": "cred-abc",
    }
    record = TrustRecord.model_validate(data)
    assert record.delegation is not None
    assert record.delegation.credential_id == "cred-abc"


def test_record_without_delegation_is_valid() -> None:
    record = TrustRecord.model_validate(_load("intel-tdx.json"))
    assert record.delegation is None


def test_delegation_bad_digest_rejected() -> None:
    data = _load("intel-tdx.json")
    data["delegation"] = {"parent_record_hash": "not-a-digest", "credential_id": "c"}
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_delegation_empty_credential_id_rejected() -> None:
    data = _load("intel-tdx.json")
    data["delegation"] = {"parent_record_hash": "sha256:" + "a" * 64, "credential_id": ""}
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_delegation_extra_field_rejected() -> None:
    data = _load("intel-tdx.json")
    data["delegation"] = {
        "parent_record_hash": "sha256:" + "a" * 64,
        "credential_id": "c",
        "foo": "bar",
    }
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_transparency_optional_for_unanchored_records() -> None:
    """A Level 0/1 record has no receipt to name, so its absence must be representable.

    Conformance requires `transparency` at Level 2, where TR-ANC runs. Requiring a
    non-empty value in the model regardless of level made it stricter than both the
    conformance suite and schema/trace-claim.json, and left an unanchored record
    unrepresentable.
    """
    data = _load("intel-tdx.json")
    data.pop("transparency", None)
    assert TrustRecord.model_validate(data).transparency is None

    data = _load("intel-tdx.json")
    data["transparency"] = None
    assert TrustRecord.model_validate(data).transparency is None


def test_transparency_rejects_empty_string() -> None:
    """`None` means unanchored; `""` is a URI-shaped lie and stays rejected."""
    data = _load("intel-tdx.json")
    data["transparency"] = ""
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


# --- origin block ---------------------------------------------------------
#
# The block exists to disambiguate runtime.platform == "software-only", which is
# the honest value both for a dev-mode record and for one transcribed from a
# third party's control plane. These tests pin the part that makes it worth
# having: a record cannot claim someone else's evidence AND a hardware root.


def test_record_without_origin_is_valid() -> None:
    """Absence means self. Every hardware profile in the spec omits the block."""
    record = TrustRecord.model_validate(_load("intel-tdx.json"))
    assert record.origin is None


def test_origin_self_may_carry_a_hardware_platform() -> None:
    data = _load("intel-tdx.json")
    data["origin"] = {"kind": "self", "producer": "cmcp/0.4.0"}
    record = TrustRecord.model_validate(data)
    assert record.origin is not None
    assert record.origin.kind == "self"
    assert record.runtime.platform == "intel-tdx"


def test_third_party_origin_with_hardware_platform_rejected() -> None:
    """The failure mode this block is for: a hardware example with the fields edited.

    An importer holding a vendor's log has no quote to present, so a hardware
    platform value here is untrue rather than stronger.
    """
    data = _load("intel-tdx.json")
    data["origin"] = {"kind": "third-party-control-plane", "producer": "vendor-gateway/2.1"}
    with pytest.raises(ValidationError, match="software-only"):
        TrustRecord.model_validate(data)


def test_log_import_origin_with_hardware_platform_rejected() -> None:
    data = _load("intel-tdx.json")
    data["origin"] = {"kind": "log-import", "producer": "siem-export/1.0"}
    with pytest.raises(ValidationError, match="software-only"):
        TrustRecord.model_validate(data)


def test_third_party_origin_on_software_only_parses() -> None:
    data = _load("intel-tdx.json")
    data["runtime"]["platform"] = "software-only"
    data["origin"] = {
        "kind": "third-party-control-plane",
        "producer": "vendor-gateway/2.1",
        "source_event_id": "evt-7f3a",
        "ingested_at": 1760000000,
    }
    record = TrustRecord.model_validate(data)
    assert record.origin is not None
    assert record.origin.producer == "vendor-gateway/2.1"
    assert record.origin.source_event_id == "evt-7f3a"


def test_origin_kind_is_closed() -> None:
    """Free text would defeat the point: a verifier has to be able to key on it."""
    data = _load("intel-tdx.json")
    data["runtime"]["platform"] = "software-only"
    data["origin"] = {"kind": "vendor-asserted", "producer": "vendor/1.0"}
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_origin_requires_a_producer() -> None:
    data = _load("intel-tdx.json")
    data["runtime"]["platform"] = "software-only"
    data["origin"] = {"kind": "log-import"}
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_origin_rejects_unknown_fields() -> None:
    data = _load("intel-tdx.json")
    data["runtime"]["platform"] = "software-only"
    data["origin"] = {"kind": "log-import", "producer": "x/1.0", "assurance": "operator-asserted"}
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


# --- enforcement_mode: declared -------------------------------------------


def test_declared_enforcement_mode_parses() -> None:
    """The honest value for a producer with no policy engine."""
    data = _load("intel-tdx.json")
    data["policy"]["enforcement_mode"] = "declared"
    record = TrustRecord.model_validate(data)
    assert record.policy.enforcement_mode == "declared"


def test_enforcement_mode_stays_closed() -> None:
    """Adding a value must not turn the field into free text."""
    data = _load("intel-tdx.json")
    data["policy"]["enforcement_mode"] = "monitor"
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(data)


def test_the_three_evaluating_modes_still_parse() -> None:
    for mode in ("enforce", "advisory", "silent"):
        data = _load("intel-tdx.json")
        data["policy"]["enforcement_mode"] = mode
        assert TrustRecord.model_validate(data).policy.enforcement_mode == mode

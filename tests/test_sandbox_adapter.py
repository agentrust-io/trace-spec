"""Unit tests for TraceSandboxAdapter, SandboxSessionResult and SandboxAttestation."""

from __future__ import annotations

import hashlib
import json
from typing import Any, get_args

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from agentrust_trace import (
    RuntimeInfo,
    TrustRecord,
    generate_key,
    key_to_jwk,
    sign_record,
    validate_json,
    verify_record,
)
from agentrust_trace.adapters import (
    SandboxAttestation,
    SandboxSessionResult,
    TraceSandboxAdapter,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SANDBOX_ID = "spiffe://runtime.example.org/sandbox/build-7f2a"
IMAGE_DIGEST = "sha256:" + "a" * 64
BUNDLE_BYTES = b"network:\n  egress: deny-all\nfilesystem:\n  write: /work\n"
DECISIONS: list[dict[str, Any]] = [
    {"tool": "fs.read", "path": "/work/src", "decision": "permit"},
    {"tool": "net.connect", "host": "api.example.org", "decision": "deny"},
]
TPM_MEASUREMENT = "sha256:" + "b" * 64
TRANSPARENCY = "https://registry.agentrust-io.com/claim/sandbox-abc123"


def _make_adapter(**overrides: Any) -> TraceSandboxAdapter:
    defaults: dict[str, Any] = {
        "model_provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
        "model_version": "20251001",
        "data_class": "confidential",
    }
    defaults.update(overrides)
    return TraceSandboxAdapter(**defaults)


def _make_session(**overrides: Any) -> SandboxSessionResult:
    defaults: dict[str, Any] = {
        "sandbox_id": SANDBOX_ID,
        "image_digest": IMAGE_DIGEST,
        "policy_bundle_bytes": BUNDLE_BYTES,
        "decisions": DECISIONS,
    }
    defaults.update(overrides)
    return SandboxSessionResult(**defaults)


# ---------------------------------------------------------------------------
# 1. Structural validity
# ---------------------------------------------------------------------------

def test_build_produces_a_structurally_valid_record() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    TrustRecord.model_validate(record)


def test_record_carries_the_session_identity_and_image() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    assert record["subject"] == SANDBOX_ID
    assert record["build_provenance"]["digest"] == IMAGE_DIGEST


def test_signed_record_verifies_against_the_trusted_key() -> None:
    key = generate_key()
    record = sign_record(_make_adapter().build_trust_record(_make_session()), key)
    verify_record(record, key_to_jwk(key))
    TrustRecord.model_validate(record)


def test_a_tampered_record_fails_verification() -> None:
    """The point of signing: editing the policy hash after the fact must not verify."""
    key = generate_key()
    record = sign_record(_make_adapter().build_trust_record(_make_session()), key)
    record["policy"]["bundle_hash"] = "sha256:" + "f" * 64
    with pytest.raises(InvalidSignature):
        verify_record(record, key_to_jwk(key))


# ---------------------------------------------------------------------------
# 2. Level 0: no attestation
# ---------------------------------------------------------------------------

def test_without_attestation_the_record_is_software_only() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    assert record["runtime"]["platform"] == "software-only"


def test_software_measurement_binds_image_and_policy() -> None:
    """The Level 0 measurement must be reproducible from its two named inputs."""
    record = _make_adapter().build_trust_record(_make_session())
    bundle_hash = TraceSandboxAdapter.bundle_hash(BUNDLE_BYTES)
    expected = (
        "sha256:"
        + hashlib.sha256(f"{IMAGE_DIGEST}\n{bundle_hash}".encode()).hexdigest()
    )
    assert record["runtime"]["measurement"] == expected


def test_software_measurement_changes_with_the_policy() -> None:
    """Editing the policy must move the measurement, or it is not binding anything."""
    a = _make_adapter().build_trust_record(_make_session())
    b = _make_adapter().build_trust_record(
        _make_session(policy_bundle_bytes=BUNDLE_BYTES + b"  extra: true\n")
    )
    assert a["runtime"]["measurement"] != b["runtime"]["measurement"]
    assert a["policy"]["bundle_hash"] != b["policy"]["bundle_hash"]


def test_software_measurement_changes_with_the_image() -> None:
    a = _make_adapter().build_trust_record(_make_session())
    b = _make_adapter().build_trust_record(
        _make_session(image_digest="sha256:" + "c" * 64)
    )
    assert a["runtime"]["measurement"] != b["runtime"]["measurement"]


# ---------------------------------------------------------------------------
# 3. Level 1: attestation supplied
# ---------------------------------------------------------------------------

def test_attestation_sets_platform_and_measurement_verbatim() -> None:
    session = _make_session(
        attestation=SandboxAttestation(platform="tpm2", measurement=TPM_MEASUREMENT)
    )
    record = _make_adapter().build_trust_record(session)
    assert record["runtime"]["platform"] == "tpm2"
    assert record["runtime"]["measurement"] == TPM_MEASUREMENT
    TrustRecord.model_validate(record)


def test_attestation_optional_fields_reach_the_record() -> None:
    session = _make_session(
        attestation=SandboxAttestation(
            platform="amd-sev-snp",
            measurement=TPM_MEASUREMENT,
            rim_uri="https://example.org/rim/1",
            firmware_version="1.55",
            nonce="bm9uY2U",
        )
    )
    runtime = _make_adapter().build_trust_record(session)["runtime"]
    assert runtime["rim_uri"] == "https://example.org/rim/1"
    assert runtime["firmware_version"] == "1.55"
    assert runtime["nonce"] == "bm9uY2U"


def test_the_same_session_is_level_0_or_level_1_by_attestation_alone() -> None:
    """One code path spans both levels. Only the attestation differs."""
    adapter = _make_adapter()
    level0 = adapter.build_trust_record(_make_session())
    level1 = adapter.build_trust_record(
        _make_session(attestation=SandboxAttestation("tpm2", TPM_MEASUREMENT))
    )
    assert level0["policy"] == level1["policy"]
    assert level0["tool_transcript"] == level1["tool_transcript"]
    assert level0["runtime"]["platform"] != level1["runtime"]["platform"]


# ---------------------------------------------------------------------------
# 4. A caller cannot misname unattested evidence (shape validation only)
# ---------------------------------------------------------------------------

def test_attestation_rejects_software_only_as_a_platform() -> None:
    with pytest.raises(ValueError, match="must not be 'software-only'"):
        SandboxAttestation(platform="software-only", measurement=TPM_MEASUREMENT)


def test_attestation_rejects_an_unknown_platform() -> None:
    with pytest.raises(ValueError, match="is not an accepted platform"):
        SandboxAttestation(platform="totally-secure-enclave", measurement=TPM_MEASUREMENT)


@pytest.mark.parametrize(
    "measurement",
    ["not-a-digest", "sha256:short", "", "md5:" + "a" * 32, "sha256:" + "A" * 64],
)
def test_attestation_rejects_a_measurement_that_is_not_a_digest(measurement: str) -> None:
    with pytest.raises(ValueError, match="is not a sha256: or sha384: digest"):
        SandboxAttestation(platform="tpm2", measurement=measurement)


# ---------------------------------------------------------------------------
# 4b. Shape validation is not evidence verification, and must not be mistaken
#     for it: SandboxAttestation/TraceSandboxAdapter do not, and cannot from
#     this input alone, verify that a measurement was ever produced by the
#     named platform. A digest-shaped, enum-valid attestation is accepted
#     verbatim even when the caller invented every byte of it. Pinning this
#     documents the actual contract (docs/trust-levels.md's Level 1 boundary:
#     "agentrust_trace.verify_record does not itself appraise hardware
#     quotes") rather than letting it silently regress into a false sense of
#     verification, or silently regress into the adapter starting to reject
#     input it has never had grounds to trust or distrust.
# ---------------------------------------------------------------------------

def test_a_fabricated_but_well_shaped_attestation_is_accepted_verbatim() -> None:
    """Documents the boundary: shape validation, not cryptographic appraisal.

    Nothing in ``SandboxAttestation`` or ``TraceSandboxAdapter`` checks a quote, a
    signature, or a nonce. A caller who never touched real hardware can build an
    attestation entirely from invented values, as long as they are shaped like real
    evidence, and the adapter reproduces them in the signed record unchanged. Verifying
    that a measurement actually came from the named platform is the responsibility of
    the caller's own attestation verifier, run *before* constructing the
    ``SandboxAttestation`` -- see the sandbox.py module docstring and
    docs/integration/sandbox-runtime.md.
    """
    fabricated = SandboxAttestation(
        platform="amd-sev-snp",
        measurement="sha256:" + "0" * 64,
    )
    record = _make_adapter().build_trust_record(_make_session(attestation=fabricated))
    assert record["runtime"]["platform"] == "amd-sev-snp"
    assert record["runtime"]["measurement"] == "sha256:" + "0" * 64
    # Structurally valid, and signable, despite carrying no actual hardware evidence.
    TrustRecord.model_validate(record)
    key = generate_key()
    signed = sign_record(record, key)
    verify_record(signed, key_to_jwk(key))


def test_genuinely_verified_evidence_is_still_not_bound_to_the_signing_key() -> None:
    """Documents a second, separate gap from the fabricated-evidence one above.

    Even a caller who *did* independently verify genuine hardware evidence before
    constructing a ``SandboxAttestation`` -- doing everything the module docstring now
    asks of them -- still cannot get real Level 1 assurance out of this adapter, because
    nothing here binds that evidence to the specific key the record ends up signed
    with. ``nonce`` is carried through verbatim and is never checked against
    ``cnf.jwk`` or against the signing key passed to ``sign_record``. A verifier can
    compare it against a value it chose, via ``verify_record(expected_nonce=...)``,
    which establishes freshness rather than key binding. Two records built from the
    identical (hypothetically genuine) attestation but signed with unrelated keys both verify
    successfully; nothing distinguishes "the verified key" from "any key the caller
    felt like using afterwards". Per docs/trust-levels.md, Level 1 requires
    "authenticated evidence binding the record-signing key to the expected
    environment"; per docs/verification.md, defining that binding is this producing
    profile's job, and it does not define one.
    """
    same_attestation = SandboxAttestation(
        platform="tpm2",
        measurement=TPM_MEASUREMENT,
        # A caller following the module's own advice: a nonce that claims to bind a
        # challenge to *some* key. Nothing checks that it binds to the key used below.
        nonce="claimed-binding-to-key-A",
    )
    record_a = _make_adapter().build_trust_record(_make_session(attestation=same_attestation))
    record_b = _make_adapter().build_trust_record(_make_session(attestation=same_attestation))

    key_a = generate_key()
    key_b = generate_key()  # Unrelated to whatever "claimed-binding-to-key-A" meant.

    signed_a = sign_record(record_a, key_a)
    signed_b = sign_record(record_b, key_b)

    # Both verify: the adapter and sign_record() accept the same "verified" evidence
    # bound to a nonce string regardless of which key actually signs the record.
    verify_record(signed_a, key_to_jwk(key_a))
    verify_record(signed_b, key_to_jwk(key_b))
    # The nonce, and therefore the claimed binding, is identical in both -- yet the
    # embedded confirmation keys differ. Nothing here or in sign_record/verify_record
    # detects that the "binding" is meaningless.
    assert signed_a["runtime"]["nonce"] == signed_b["runtime"]["nonce"]
    assert signed_a["cnf"]["jwk"]["x"] != signed_b["cnf"]["jwk"]["x"]


def test_accepted_platforms_are_read_from_the_model() -> None:
    """Guards against a hand-maintained copy drifting from RuntimeInfo."""
    from agentrust_trace.adapters.sandbox import _PLATFORMS

    assert _PLATFORMS == frozenset(
        get_args(RuntimeInfo.model_fields["platform"].annotation)
    )
    assert "software-only" in _PLATFORMS  # accepted by the model, refused by attestation


# ---------------------------------------------------------------------------
# 5. Session input validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "sandbox_id",
    ["build-7f2a", "https://example.org/sandbox/1", "spiffe://example.org", "", "did:x"],
)
def test_sandbox_id_must_be_a_spiffe_uri_or_did(sandbox_id: str) -> None:
    with pytest.raises(ValueError, match="must be a SPIFFE URI"):
        _make_session(sandbox_id=sandbox_id)


@pytest.mark.parametrize("sandbox_id", [SANDBOX_ID, "did:web:example.org:sandbox:1"])
def test_valid_sandbox_ids_are_accepted(sandbox_id: str) -> None:
    assert _make_session(sandbox_id=sandbox_id).sandbox_id == sandbox_id


def test_image_digest_must_be_a_digest() -> None:
    with pytest.raises(ValueError, match="must be a sha256: or sha384: digest"):
        _make_session(image_digest="latest")


def test_a_bad_sandbox_id_fails_at_the_adapter_not_at_model_validate() -> None:
    """The error names the field, rather than surfacing several steps later."""
    with pytest.raises(ValueError, match="sandbox_id"):
        _make_session(sandbox_id="build-7f2a")


# ---------------------------------------------------------------------------
# 6. Transcript hashing uses JCS
# ---------------------------------------------------------------------------

def test_transcript_hash_is_jcs_over_the_decision_log() -> None:
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(DECISIONS)).hexdigest()
    assert TraceSandboxAdapter.transcript_hash(DECISIONS) == expected


def test_transcript_hash_diverges_from_naive_sorted_json_on_non_ascii() -> None:
    """The reason JCS is used rather than json.dumps(sort_keys=True).

    A decision log carries user-controlled strings. json.dumps with ensure_ascii escapes
    non-ASCII to \\uXXXX; JCS emits raw UTF-8. Two implementations that disagree here
    produce different transcript hashes for the same log, and cross-language verification
    breaks.
    """
    decisions = [{"tool": "fs.read", "path": "/work/café", "decision": "permit"}]
    naive = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                decisions, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        ).hexdigest()
    )
    assert TraceSandboxAdapter.transcript_hash(decisions) != naive


def test_transcript_hash_is_stable_under_key_order() -> None:
    a = [{"tool": "fs.read", "decision": "permit"}]
    b = [{"decision": "permit", "tool": "fs.read"}]
    assert TraceSandboxAdapter.transcript_hash(a) == TraceSandboxAdapter.transcript_hash(b)


def test_call_count_defaults_to_the_decision_count_and_can_be_overridden() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    assert record["tool_transcript"]["call_count"] == len(DECISIONS)

    record = _make_adapter().build_trust_record(_make_session(call_count=99))
    assert record["tool_transcript"]["call_count"] == 99


def test_an_empty_decision_log_is_representable() -> None:
    record = _make_adapter().build_trust_record(_make_session(decisions=[]))
    assert record["tool_transcript"]["call_count"] == 0
    TrustRecord.model_validate(record)


# ---------------------------------------------------------------------------
# 7. Appraisal is not claimed by default
# ---------------------------------------------------------------------------

def test_appraisal_status_defaults_to_none() -> None:
    """Building a record does not appraise it, so the field must not say it did."""
    record = _make_adapter().build_trust_record(_make_session())
    assert record["appraisal"]["status"] == "none"


def test_appraisal_status_is_configurable_when_one_actually_happened() -> None:
    record = _make_adapter(appraisal_status="affirming").build_trust_record(
        _make_session()
    )
    assert record["appraisal"]["status"] == "affirming"


def test_slsa_level_defaults_to_zero() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    assert record["build_provenance"]["slsa_level"] == 0


# ---------------------------------------------------------------------------
# 8. Transparency
# ---------------------------------------------------------------------------

def test_transparency_is_absent_when_unanchored() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    assert "transparency" not in record


def test_transparency_is_present_when_configured() -> None:
    record = _make_adapter(transparency=TRANSPARENCY).build_trust_record(_make_session())
    assert record["transparency"] == TRANSPARENCY
    validate_json(record)


def test_an_anchored_record_passes_the_published_json_schema() -> None:
    record = _make_adapter(transparency=TRANSPARENCY).build_trust_record(
        _make_session(attestation=SandboxAttestation("tpm2", TPM_MEASUREMENT))
    )
    validate_json(sign_record(record, generate_key()))


def test_unanchored_record_is_model_and_schema_valid() -> None:
    """Level 0/1 records are unanchored, so transparency is optional everywhere."""
    record = _make_adapter().build_trust_record(_make_session())
    TrustRecord.model_validate(record)
    validate_json(record)


# ---------------------------------------------------------------------------
# 9. Determinism
# ---------------------------------------------------------------------------

def test_the_same_session_builds_the_same_record() -> None:
    adapter = _make_adapter()
    session = _make_session(iat=1800000000)
    assert adapter.build_trust_record(session) == adapter.build_trust_record(session)


def test_enforcement_mode_reaches_the_record() -> None:
    record = _make_adapter(enforcement_mode="advisory").build_trust_record(
        _make_session()
    )
    assert record["policy"]["enforcement_mode"] == "advisory"


def test_an_invalid_enforcement_mode_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_adapter(enforcement_mode="whatever").build_trust_record(_make_session())

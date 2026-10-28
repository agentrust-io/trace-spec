"""Unit tests for TraceSandboxAdapter, SandboxSessionResult and SandboxAttestation."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import inspect
import json
from pathlib import Path
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
from agentrust_trace.adapters.sandbox import TRACE_MIN_IAT
from agentrust_trace.models import JCS_SAFE_INTEGER

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "trace-claim.json"

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
        "model_provider": "example-provider",
        "model_id": "example-model",
        "model_version": "20251001",
        "data_class": "confidential",
        "enforcement_mode": "enforce",
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


@pytest.mark.parametrize(
    "iat",
    ["1800000000", True, False, -5, 0, 1, 1699999999, 1.5, 2**60, JCS_SAFE_INTEGER + 1],
)
def test_iat_must_be_within_the_trace_v0_2_range(iat) -> None:
    """Every other field here reaches the record through a models.py pydantic
    constructor, which coerces or refuses a bad type before it is dumped. `iat`
    used to reach build_trust_record's top-level "iat" key untouched, so a
    numeric string or a bool survived to the signed wire form: model_validate()
    reported it valid (pydantic's lax mode coerces on the way in) while the wire
    bytes stayed the original, schema-invalid type. Same failure mode as
    provenance.build_record's pre-#320 issued_at coercion."""
    with pytest.raises(ValueError, match="iat must be an integer Unix timestamp"):
        _make_session(iat=iat)


def test_valid_iat_round_trips_as_an_int_on_the_wire() -> None:
    record = _make_adapter().build_trust_record(_make_session(iat=1800000000))
    assert record["iat"] == 1800000000
    assert isinstance(record["iat"], int)


@pytest.mark.parametrize("iat", [1700000000, JCS_SAFE_INTEGER])
def test_boundary_iat_values_reach_the_wire_and_validate(iat) -> None:
    """The exact contract bounds must survive to the record, not merely construct.

    Constructing the session says nothing about the value that gets signed, which
    is what this file's iat tests are about, so the assertion is on the wire form
    and on the schema."""
    record = _make_adapter().build_trust_record(_make_session(iat=iat))
    assert record["iat"] == iat
    assert isinstance(record["iat"], int) and not isinstance(record["iat"], bool)
    validate_json(record)



@pytest.mark.parametrize("iat", ["1800000000", 1, 1699999999, JCS_SAFE_INTEGER + 1])
def test_a_checked_iat_cannot_be_replaced_before_the_record_is_built(iat) -> None:
    """Passing __post_init__ has to be a property of the value that gets signed.

    While the session was a mutable dataclass it was not: one assignment between
    construction and build_trust_record put any of these on the wire, where the
    schema then rejected the record. #320 settled the same point for
    provenance.build_record, which is why its check sits at the point of use."""
    with pytest.raises(FrozenInstanceError):
        _make_session().iat = iat
    # frozen=True guards __setattr__ and nothing else. Each of these reaches the
    # field, so the check that decides what gets signed is the one in
    # build_trust_record. A fresh session per route, or the second assertion would
    # pass on damage the first one did.
    for reach in (lambda s: vars(s).__setitem__("iat", iat),
                  lambda s: object.__setattr__(s, "iat", iat)):
        session = _make_session()
        reach(session)
        assert session.iat == iat
        with pytest.raises(ValueError, match="iat must be an integer Unix timestamp"):
            _make_adapter().build_trust_record(session)


def test_the_adapter_floor_is_the_one_the_record_contract_carries() -> None:
    """TRACE_MIN_IAT is a literal here and in models.py. If they ever diverge the
    adapter refuses records the schema accepts, or emits ones it rejects."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["iat"]["minimum"] == TRACE_MIN_IAT
    assert schema["properties"]["iat"]["maximum"] == JCS_SAFE_INTEGER
    bound = next(
        m for m in TrustRecord.model_fields["iat"].metadata if getattr(m, "ge", None) is not None
    )
    assert bound.ge == TRACE_MIN_IAT

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


def test_enforcement_mode_has_no_default() -> None:
    # Spec section 4.3: `declared` MUST NOT be a default, and an `enforce` default
    # would claim an evaluation the adapter never observed (#416, #417).
    with pytest.raises(TypeError, match="enforcement_mode"):
        TraceSandboxAdapter(model_provider="example-provider", model_id="example-model")


@pytest.mark.parametrize("mode", ["enforce", "advisory", "silent", "declared"])
def test_enforcement_mode_reaches_the_record(mode: str) -> None:
    record = _make_adapter(enforcement_mode=mode).build_trust_record(
        _make_session()
    )
    assert record["policy"]["enforcement_mode"] == mode
    TrustRecord.model_validate(record)


def test_an_invalid_enforcement_mode_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_adapter(enforcement_mode="whatever").build_trust_record(_make_session())


# ---------------------------------------------------------------------------
# 10. Issue #615: data_class, enum/SLSA fields, URI format, and UTF-8 validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "data_class",
    ["", "\ud800", 123, None, True, False, ["confidential"], {"data_class": "confidential"}],
    ids=repr,
)
def test_data_class_rejects_empty_non_string_and_surrogate_values(data_class: Any) -> None:
    with pytest.raises(ValueError, match="data_class"):
        _make_adapter(data_class=data_class)

    adapter = _make_adapter()
    adapter._data_class = data_class
    with pytest.raises(ValueError, match="data_class"):
        adapter.build_trust_record(_make_session())


@pytest.mark.parametrize(
    ("field_name", "attr_name", "bad_value"),
    [
        ("enforcement_mode", "_enforcement_mode", "whatever"),
        ("enforcement_mode", "_enforcement_mode", ""),
        ("enforcement_mode", "_enforcement_mode", 123),
        ("enforcement_mode", "_enforcement_mode", None),
        ("appraisal_status", "_appraisal_status", "whatever"),
        ("appraisal_status", "_appraisal_status", ""),
        ("appraisal_status", "_appraisal_status", 123),
        ("appraisal_status", "_appraisal_status", None),
        ("build_provenance_slsa_level", "_slsa_level", -1),
        ("build_provenance_slsa_level", "_slsa_level", 4),
        ("build_provenance_slsa_level", "_slsa_level", True),
        ("build_provenance_slsa_level", "_slsa_level", "2"),
        ("build_provenance_slsa_level", "_slsa_level", 1.5),
    ],
    ids=lambda x: f"{x!r}",
)
def test_invalid_enum_and_slsa_level_fields_raise_at_init_and_build(
    field_name: str, attr_name: str, bad_value: Any
) -> None:
    with pytest.raises(ValidationError):
        _make_adapter(**{field_name: bad_value})

    adapter = _make_adapter()
    setattr(adapter, attr_name, bad_value)
    with pytest.raises(ValidationError):
        adapter.build_trust_record(_make_session())


@pytest.mark.parametrize(
    ("field_name", "attr_name"),
    [
        ("transparency", "_transparency"),
        ("appraisal_verifier", "_appraisal_verifier"),
        ("appraisal_policy_ref", "_appraisal_policy_ref"),
        ("build_provenance_uri", "_provenance_uri"),
        ("policy_uri", "_policy_uri"),
    ],
    ids=lambda x: x,
)
@pytest.mark.parametrize(
    "bad_uri",
    [
        "not a uri",
        "",
        "   ",
        "https://example.org/a\n",
        "https://example.org/a\r",
        "https://example.org/a\u2028",
        "https://example.org/a\u2029",
        "http://[::1",
        "https://[::1.2.3.04]/",
        "https://example.org/\ud800",
        123,
        True,
        ["https://example.org"],
    ],
    ids=repr,
)
def test_uri_fields_reject_malformed_uris_at_init_and_build(
    field_name: str, attr_name: str, bad_uri: Any
) -> None:
    with pytest.raises(ValueError, match=field_name):
        _make_adapter(**{field_name: bad_uri})

    adapter = _make_adapter()
    setattr(adapter, attr_name, bad_uri)
    with pytest.raises(ValueError, match=field_name):
        adapter.build_trust_record(_make_session())


def test_appraisal_verifier_rejects_none_while_optional_uris_accept_none() -> None:
    with pytest.raises(ValueError, match="appraisal_verifier"):
        _make_adapter(appraisal_verifier=None)

    record = _make_adapter(
        transparency=None,
        appraisal_policy_ref=None,
        build_provenance_uri=None,
        policy_uri=None,
    ).build_trust_record(_make_session())
    assert "transparency" not in record
    assert "policy_ref" not in record["appraisal"]
    assert "provenance_uri" not in record["build_provenance"]
    assert "policy_uri" not in record["policy"]
    validate_json(record)


@pytest.mark.parametrize(
    "field_name",
    [
        "transparency",
        "appraisal_verifier",
        "appraisal_policy_ref",
        "build_provenance_uri",
        "policy_uri",
    ],
)
@pytest.mark.parametrize(
    "good_uri",
    [
        "https://example.org/a",
        "urn:example:a",
        "did:web:example.org",
        "https://[::1.2.3.4]/",
        "https://[v1.example:future]/",
        "https://example.org/a%0A",
    ],
)
def test_uri_fields_accept_valid_uris_and_pass_validate_json(
    field_name: str, good_uri: str
) -> None:
    record = _make_adapter(**{field_name: good_uri}).build_trust_record(_make_session())
    validate_json(record)


@pytest.mark.parametrize(
    "bad_uri",
    [
        "not a uri",
        "",
        "   ",
        "https://example.org/a\n",
        "https://example.org/a\r",
        "https://example.org/a\u2028",
        "https://example.org/a\u2029",
        "http://[::1",
        "https://[::1.2.3.04]/",
        "https://example.org/\ud800",
        123,
        True,
        ["https://example.org"],
    ],
    ids=repr,
)
def test_attestation_rim_uri_rejects_malformed_uris(bad_uri: Any) -> None:
    with pytest.raises(ValueError, match="SandboxAttestation.rim_uri"):
        SandboxAttestation(
            platform="tpm2",
            measurement=TPM_MEASUREMENT,
            rim_uri=bad_uri,
        )

    attestation = SandboxAttestation(platform="tpm2", measurement=TPM_MEASUREMENT)
    session = _make_session(attestation=attestation)
    object.__setattr__(attestation, "rim_uri", bad_uri)
    with pytest.raises(ValueError, match="SandboxAttestation.rim_uri"):
        _make_adapter().build_trust_record(session)


@pytest.mark.parametrize("field_name", ["firmware_version", "nonce"])
@pytest.mark.parametrize("bad_value", ["", "\ud800", 123, True, ["v"]], ids=repr)
def test_attestation_optional_strings_reject_empty_non_string_and_surrogates(
    field_name: str, bad_value: Any
) -> None:
    with pytest.raises(ValueError, match=f"SandboxAttestation.{field_name}"):
        SandboxAttestation(
            platform="tpm2",
            measurement=TPM_MEASUREMENT,
            **{field_name: bad_value},
        )

    attestation = SandboxAttestation(platform="tpm2", measurement=TPM_MEASUREMENT)
    session = _make_session(attestation=attestation)
    object.__setattr__(attestation, field_name, bad_value)
    with pytest.raises(ValueError, match=f"SandboxAttestation.{field_name}"):
        _make_adapter().build_trust_record(session)


@pytest.mark.parametrize(
    ("field_name", "bad_value"),
    [
        ("model_provider", ""),
        ("model_provider", "\ud800"),
        ("model_provider", 123),
        ("model_provider", None),
        ("model_provider", True),
        ("model_id", ""),
        ("model_id", "\ud800"),
        ("model_id", 123),
        ("model_id", None),
        ("model_id", True),
        ("model_version", ""),
        ("model_version", "\ud800"),
        ("model_version", 123),
        ("model_version", True),
        ("policy_version", ""),
        ("policy_version", "\ud800"),
        ("policy_version", 123),
        ("policy_version", True),
        ("build_provenance_builder", ""),
        ("build_provenance_builder", "\ud800"),
        ("build_provenance_builder", 123),
        ("build_provenance_builder", True),
    ],
    ids=lambda x: f"{x!r}",
)
def test_sandbox_string_fields_reject_empty_non_string_and_lone_surrogates(
    field_name: str, bad_value: Any
) -> None:
    with pytest.raises(ValueError, match=field_name):
        _make_adapter(**{field_name: bad_value})


@pytest.mark.parametrize(
    "surrogate_id",
    ["did:web:\ud800", "spiffe://example.org/\ud800"],
    ids=repr,
)
def test_sandbox_id_rejects_lone_surrogates(surrogate_id: str) -> None:
    with pytest.raises(ValueError, match="sandbox_id"):
        _make_session(sandbox_id=surrogate_id)


def test_sandbox_build_trust_record_revalidates_mutated_adapter_fields() -> None:
    session = _make_session()

    adapter = _make_adapter()
    adapter._model.provider = ""
    with pytest.raises(ValueError, match="model_provider"):
        adapter.build_trust_record(session)


def test_sandbox_build_trust_record_rejects_non_model_attribute_with_value_error() -> None:
    session = _make_session()

    adapter = _make_adapter()
    adapter._model = "not-a-model"  # type: ignore[assignment]
    with pytest.raises(ValueError, match="model must be a ModelInfo"):
        adapter.build_trust_record(session)


_JUNK_AND_BAD_URIS: tuple[Any, ...] = (
    "a-string",
    123,
    None,
    [1, 2],
    True,
    False,
    0,
    {},
    "",
    b"bytes",
    10**20,
    float("nan"),
    float("inf"),
    "\ud800",
    {"a": 1},
    [{}],
    1.5,
    "not a uri",
    "   ",
    "https://example.org/a\n",
    "https://[::1.2.3.04]/",
    "http://[::1",
)


@pytest.mark.parametrize(
    "param",
    sorted(inspect.signature(TraceSandboxAdapter.__init__).parameters.keys() - {"self"}),
)
def test_what_sandbox_adapter_accepts_passes_validate_json_and_verify_record(
    param: str,
) -> None:
    key = generate_key()
    jwk = key_to_jwk(key)
    session = _make_session(iat=1785000000)
    for value in _JUNK_AND_BAD_URIS:
        try:
            adapter = _make_adapter(**{param: value})
            record = adapter.build_trust_record(session)
        except (ValueError, ValidationError):
            continue
        validate_json(record)
        verify_record(sign_record(record, key), jwk, now=session.iat)



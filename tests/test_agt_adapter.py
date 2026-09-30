"""Unit tests for TraceAGTAdapter and AGTSessionResult."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import hashlib
import rfc8785

import pytest
from pydantic import ValidationError

from agentrust_trace import TrustRecord, sign_record, generate_key, key_to_jwk, verify_record
from agentrust_trace.adapters import AGTSessionResult, TraceAGTAdapter
from agentrust_trace.adapters.agt import TRACE_MIN_IAT
from agentrust_trace.models import JCS_SAFE_INTEGER
from agentrust_trace.validate import validate_json

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "trace-claim.json"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BUNDLE_BYTES = b'permit(principal, action, resource);'
CHAIN_TIP = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
AUDIT_ENTRIES: list[dict] = [
    {"entry_id": 1, "tool": "crm.get_customer", "decision": "permit"},
    {"entry_id": 2, "tool": "support.create_ticket", "decision": "permit"},
]
AGENT_DID = "spiffe://trust.example.org/agent/test-agent/prod"
TRANSPARENCY = "https://registry.agentrust-io.com/claim/test-abc123"


def _make_adapter(**overrides) -> TraceAGTAdapter:
    defaults = {
        "model_provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
        "model_version": "20251001",
        "data_class": "confidential",
        "build_provenance_slsa_level": 2,
        "build_provenance_digest": "sha256:" + "a" * 64,
        "transparency": TRANSPARENCY,
        "enforcement_mode": "enforce",
    }
    defaults.update(overrides)
    return TraceAGTAdapter(**defaults)


def _make_session(**overrides) -> AGTSessionResult:
    defaults = {
        "agent_did": AGENT_DID,
        "policy_bundle_bytes": BUNDLE_BYTES,
        "audit_entries": AUDIT_ENTRIES,
        "merkle_chain_tip": CHAIN_TIP,
    }
    defaults.update(overrides)
    return AGTSessionResult(**defaults)


# ---------------------------------------------------------------------------
# 1. build_trust_record produces a structurally valid TrustRecord
# ---------------------------------------------------------------------------

def test_build_produces_valid_trust_record() -> None:
    adapter = _make_adapter()
    session = _make_session()
    record = adapter.build_trust_record(session)
    # Must parse without ValidationError
    tr = TrustRecord.model_validate(record)
    assert tr.eat_profile == "tag:agentrust-io.com,2026:trace-v0.2"


# ---------------------------------------------------------------------------
# 2. runtime.platform is always software-only
# ---------------------------------------------------------------------------

def test_runtime_platform_is_software_only() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    assert record["runtime"]["platform"] == "software-only"


# ---------------------------------------------------------------------------
# 3. policy.bundle_hash is SHA-256 of policy_bundle_bytes
# ---------------------------------------------------------------------------

def test_policy_bundle_hash_correct() -> None:
    expected = "sha256:" + hashlib.sha256(BUNDLE_BYTES).hexdigest()
    record = _make_adapter().build_trust_record(_make_session())
    assert record["policy"]["bundle_hash"] == expected


# ---------------------------------------------------------------------------
# 4. tool_transcript.hash is SHA-256 of canonical JSON of audit_entries
# ---------------------------------------------------------------------------

def test_transcript_hash_correct() -> None:
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(AUDIT_ENTRIES)).hexdigest()
    record = _make_adapter().build_trust_record(_make_session())
    assert record["tool_transcript"]["hash"] == expected


def test_transcript_hash_matches_sandbox_adapter_canonicalization() -> None:
    """The two adapters must hash the same field the same way.

    Before this fix, TraceAGTAdapter used the registry-anchor sorted-key format
    and TraceSandboxAdapter used JCS for what is structurally the same
    `tool_transcript.hash` field -- so the "same" AGT session, re-emitted
    through the sandbox adapter's hashing rule, produced a different digest.
    """
    from agentrust_trace.adapters import TraceSandboxAdapter

    agt_hash = _make_adapter().build_trust_record(_make_session())["tool_transcript"]["hash"]
    assert agt_hash == TraceSandboxAdapter.transcript_hash(AUDIT_ENTRIES)


def test_transcript_hash_handles_audit_entries_with_floats() -> None:
    """A real Cedar/AGT audit entry routinely carries a float (a timestamp with
    fractional seconds, a decision latency, a risk score). The registry-anchor
    format used before this fix rejects any non-integer number outright
    (`UnanchorableValue`), so building a record from such a session raised
    instead of producing a Trust Record. JCS has no such restriction.
    """
    session = _make_session(
        audit_entries=[
            {"entry_id": 1, "tool": "crm.get_customer", "decision": "permit",
             "decided_at": 1750000000.482, "risk_score": 0.13},
        ]
    )
    record = _make_adapter().build_trust_record(session)  # must not raise
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(session.audit_entries)).hexdigest()
    assert record["tool_transcript"]["hash"] == expected


# ---------------------------------------------------------------------------
# 5. runtime.measurement is SHA-256 of merkle_chain_tip string
# ---------------------------------------------------------------------------

def test_measurement_is_sha256_of_chain_tip() -> None:
    expected = "sha256:" + hashlib.sha256(CHAIN_TIP.encode()).hexdigest()
    record = _make_adapter().build_trust_record(_make_session())
    assert record["runtime"]["measurement"] == expected


# ---------------------------------------------------------------------------
# 6. call_count defaults to len(audit_entries); explicit override is respected
# ---------------------------------------------------------------------------

def test_call_count_defaults_to_entries_length() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    assert record["tool_transcript"]["call_count"] == len(AUDIT_ENTRIES)


def test_call_count_override_respected() -> None:
    session = _make_session(call_count=99)
    record = _make_adapter().build_trust_record(session)
    assert record["tool_transcript"]["call_count"] == 99


# ---------------------------------------------------------------------------
# 7. subject matches agent_did verbatim
# ---------------------------------------------------------------------------

def test_subject_matches_agent_did() -> None:
    record = _make_adapter().build_trust_record(_make_session())
    assert record["subject"] == AGENT_DID


def test_did_web_subject_accepted() -> None:
    session = _make_session(agent_did="did:web:example.org:agents:my-agent")
    record = _make_adapter().build_trust_record(session)
    tr = TrustRecord.model_validate(record)
    assert tr.subject.startswith("did:")


# ---------------------------------------------------------------------------
# 8. build_trust_record output survives sign_record + verify_record round-trip
# ---------------------------------------------------------------------------

def test_sign_and_verify_round_trip() -> None:
    adapter = _make_adapter()
    session = _make_session()
    record = adapter.build_trust_record(session)
    key = generate_key()
    signed = sign_record(record, key)
    # Must not raise: verify against the trusted signing key.
    verify_record(signed, key_to_jwk(key))
    # Structural validation of signed record
    TrustRecord.model_validate(signed)


# ---------------------------------------------------------------------------
# 9. enforcement_mode propagates from adapter config
# ---------------------------------------------------------------------------

def test_enforcement_mode_has_no_default() -> None:
    # Spec section 4.3: `declared` MUST NOT be a default, and an `enforce` default
    # would claim an evaluation the adapter never observed (#416, #417).
    kwargs = {
        "model_provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
        "build_provenance_digest": "sha256:" + "a" * 64,
        "transparency": TRANSPARENCY,
    }
    with pytest.raises(TypeError, match="enforcement_mode"):
        TraceAGTAdapter(**kwargs)


@pytest.mark.parametrize("mode", ["enforce", "advisory", "silent", "declared"])
def test_enforcement_mode_propagates(mode: str) -> None:
    adapter = _make_adapter(enforcement_mode=mode)
    record = adapter.build_trust_record(_make_session())
    assert record["policy"]["enforcement_mode"] == mode
    TrustRecord.model_validate(record)


# ---------------------------------------------------------------------------
# 10. empty audit_entries produces valid record with call_count=0
# ---------------------------------------------------------------------------

def test_empty_audit_entries() -> None:
    session = _make_session(audit_entries=[])
    record = _make_adapter().build_trust_record(session)
    TrustRecord.model_validate(record)
    assert record["tool_transcript"]["call_count"] == 0


# ---------------------------------------------------------------------------
# 11. iat propagates from session
# ---------------------------------------------------------------------------

def test_iat_propagates_from_session() -> None:
    fixed_ts = 1750000000
    session = AGTSessionResult(
        agent_did=AGENT_DID,
        policy_bundle_bytes=BUNDLE_BYTES,
        audit_entries=AUDIT_ENTRIES,
        merkle_chain_tip=CHAIN_TIP,
        iat=fixed_ts,
    )
    record = _make_adapter().build_trust_record(session)
    assert record["iat"] == fixed_ts
    assert record["appraisal"]["timestamp"] == fixed_ts


# ---------------------------------------------------------------------------
# 12. invalid build_provenance_digest raises at adapter construction
# ---------------------------------------------------------------------------

def test_invalid_build_provenance_digest_raises() -> None:
    with pytest.raises(ValidationError):
        _make_adapter(build_provenance_digest="not-a-digest")


# ---------------------------------------------------------------------------
# 13. different policy bundles produce different bundle hashes
# ---------------------------------------------------------------------------

def test_different_bundles_produce_different_hashes() -> None:
    s1 = _make_session(policy_bundle_bytes=b"bundle-alpha")
    s2 = _make_session(policy_bundle_bytes=b"bundle-beta")
    adapter = _make_adapter()
    h1 = adapter.build_trust_record(s1)["policy"]["bundle_hash"]
    h2 = adapter.build_trust_record(s2)["policy"]["bundle_hash"]
    assert h1 != h2


# ---------------------------------------------------------------------------
# 14. different chain tips produce different measurements
# ---------------------------------------------------------------------------

def test_different_chain_tips_produce_different_measurements() -> None:
    s1 = _make_session(merkle_chain_tip="aaa" + "0" * 61)
    s2 = _make_session(merkle_chain_tip="bbb" + "0" * 61)
    adapter = _make_adapter()
    m1 = adapter.build_trust_record(s1)["runtime"]["measurement"]
    m2 = adapter.build_trust_record(s2)["runtime"]["measurement"]
    assert m1 != m2


# ---------------------------------------------------------------------------
# appraisal.status is verifier-owned (#331)
# ---------------------------------------------------------------------------

def test_appraisal_status_defaults_to_none() -> None:
    """`appraisal.status` was hardcoded to `affirming` with no way to change it, so every
    record this adapter produced claimed an appraisal that had not happened. Spec section
    3.3.1 makes the field the verifier's: building a record is not appraising it."""
    record = _make_adapter().build_trust_record(_make_session())
    assert record["appraisal"]["status"] == "none"


def test_appraisal_status_is_configurable_when_one_actually_happened() -> None:
    record = _make_adapter(appraisal_status="affirming").build_trust_record(_make_session())
    assert record["appraisal"]["status"] == "affirming"


@pytest.mark.parametrize("status", ["affirming", "warning", "contraindicated", "none"])
def test_every_appraisal_status_the_model_allows_reaches_the_record(status: str) -> None:
    record = _make_adapter(appraisal_status=status).build_trust_record(_make_session())
    assert record["appraisal"]["status"] == status
    TrustRecord.model_validate(record)


def test_an_unappraised_record_still_signs_and_verifies() -> None:
    """The default must not cost a caller a valid record; `none` is a legitimate value."""
    record = _make_adapter().build_trust_record(_make_session())
    key = generate_key()
    signed = sign_record(record, key)
    assert verify_record(signed, public_key_or_jwk=key_to_jwk(key)) is not None
    assert signed["appraisal"]["status"] == "none"


# ---------------------------------------------------------------------------
# iat reaches the record untouched (same failure mode as #320)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "iat",
    ["1800000000", True, False, -5, 0, 1, 1699999999, 1.5, 2**60, JCS_SAFE_INTEGER + 1],
)
def test_iat_must_be_within_the_trace_v0_2_range(iat) -> None:
    """Every other field here reaches the record through a models.py pydantic
    constructor, which coerces or refuses a bad type before it is dumped. `iat`
    used to reach build_trust_record's top-level "iat" key untouched, with
    AGTSessionResult performing no validation of any field at all: a numeric
    string or a bool survived to the signed wire form, and TrustRecord.model_validate()
    reported it valid (pydantic's lax mode coerces on the way in) while the wire
    bytes stayed the original, schema-invalid type. Same failure mode as
    provenance.build_record's pre-#320 issued_at coercion."""
    with pytest.raises(
        ValueError, match="iat must be an integer Unix timestamp within the TRACE v0.2 range"
    ):
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

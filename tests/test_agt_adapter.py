"""Unit tests for TraceAGTAdapter and AGTSessionResult."""

from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from agentrust_trace import TrustRecord, sign_record, generate_key, key_to_jwk, verify_record
from agentrust_trace.adapters import AGTSessionResult, TraceAGTAdapter

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
TRANSPARENCY = "https://registry.agentrust.io/claim/test-abc123"


def _make_adapter(**overrides) -> TraceAGTAdapter:
    defaults = {
        "model_provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
        "model_version": "20251001",
        "data_class": "confidential",
        "build_provenance_slsa_level": 2,
        "build_provenance_digest": "sha256:" + "a" * 64,
        "transparency": TRANSPARENCY,
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
    assert tr.eat_profile == "tag:agentrust.io,2026:trace-v0.1"


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
    canonical = json.dumps(AUDIT_ENTRIES, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    expected = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    record = _make_adapter().build_trust_record(_make_session())
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
    # Must not raise — verify against the trusted signing key.
    verify_record(signed, key_to_jwk(key))
    # Structural validation of signed record
    TrustRecord.model_validate(signed)


# ---------------------------------------------------------------------------
# 9. enforcement_mode propagates from adapter config
# ---------------------------------------------------------------------------

def test_enforcement_mode_propagates() -> None:
    adapter = _make_adapter(enforcement_mode="advisory")
    record = adapter.build_trust_record(_make_session())
    assert record["policy"]["enforcement_mode"] == "advisory"


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

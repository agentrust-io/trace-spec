"""Regression tests for sandbox adapter required-string primitive boundaries."""

from __future__ import annotations

from typing import Any

import pytest

from agentrust_trace.adapters.sandbox import (
    SandboxAttestation,
    SandboxSessionResult,
    TraceSandboxAdapter,
)
from agentrust_trace.models import JCS_SAFE_INTEGER

DIGEST = "sha256:" + "a" * 64
BAD_VALUES: tuple[Any, ...] = (True, 1, [1], {"x": 1})


@pytest.mark.parametrize("platform", BAD_VALUES, ids=repr)
def test_attestation_platform_refuses_non_string_values(platform: Any) -> None:
    with pytest.raises(ValueError, match="SandboxAttestation.platform"):
        SandboxAttestation(platform=platform, measurement=DIGEST)


@pytest.mark.parametrize("measurement", BAD_VALUES, ids=repr)
def test_attestation_measurement_refuses_non_string_values(measurement: Any) -> None:
    with pytest.raises(ValueError, match="SandboxAttestation.measurement"):
        SandboxAttestation(platform="tpm2", measurement=measurement)


@pytest.mark.parametrize("sandbox_id", BAD_VALUES, ids=repr)
def test_session_sandbox_id_refuses_non_string_values(sandbox_id: Any) -> None:
    with pytest.raises(ValueError, match="sandbox_id"):
        SandboxSessionResult(
            sandbox_id=sandbox_id,
            image_digest=DIGEST,
            policy_bundle_bytes=b"policy",
            decisions=[],
        )


@pytest.mark.parametrize("image_digest", BAD_VALUES, ids=repr)
def test_session_image_digest_refuses_non_string_values(image_digest: Any) -> None:
    with pytest.raises(ValueError, match="image_digest"):
        SandboxSessionResult(
            sandbox_id="spiffe://runtime.example.org/sandbox/test",
            image_digest=image_digest,
            policy_bundle_bytes=b"policy",
            decisions=[],
        )


def test_textual_controls_still_construct() -> None:
    attestation = SandboxAttestation(platform="tpm2", measurement=DIGEST)
    session = SandboxSessionResult(
        sandbox_id="spiffe://runtime.example.org/sandbox/test",
        image_digest=DIGEST,
        policy_bundle_bytes=b"policy",
        decisions=[],
        attestation=attestation,
    )
    assert attestation.platform == "tpm2"
    assert session.sandbox_id.startswith("spiffe://")


@pytest.mark.parametrize(
    "policy_bundle_bytes",
    ("policy", 123, None, True, [1, 2], {"x": 1}),
    ids=repr,
)
def test_session_policy_bundle_bytes_refuses_non_bytes(
    policy_bundle_bytes: Any,
) -> None:
    with pytest.raises(ValueError, match="policy_bundle_bytes"):
        SandboxSessionResult(
            sandbox_id="spiffe://runtime.example.org/sandbox/test",
            image_digest=DIGEST,
            policy_bundle_bytes=policy_bundle_bytes,
            decisions=[],
        )
    with pytest.raises(ValueError, match="policy_bundle_bytes"):
        TraceSandboxAdapter.bundle_hash(policy_bundle_bytes)


@pytest.mark.parametrize(
    "decisions",
    (
        "a-string",
        {"tool": "x", "decision": "permit"},
        [1, 2],
        ["entry"],
        [None],
        123,
        None,
        True,
    ),
    ids=repr,
)
def test_session_decisions_refuses_non_list_or_non_dict_entries(
    decisions: Any,
) -> None:
    with pytest.raises(ValueError, match="decisions"):
        SandboxSessionResult(
            sandbox_id="spiffe://runtime.example.org/sandbox/test",
            image_digest=DIGEST,
            policy_bundle_bytes=b"policy",
            decisions=decisions,
        )
    with pytest.raises(ValueError, match="decisions"):
        TraceSandboxAdapter.transcript_hash(decisions)


@pytest.mark.parametrize(
    "call_count",
    (True, False, -1, "1", 1.5, JCS_SAFE_INTEGER + 1),
    ids=repr,
)
def test_session_call_count_refuses_invalid_values(call_count: Any) -> None:
    with pytest.raises(ValueError, match="call_count"):
        SandboxSessionResult(
            sandbox_id="spiffe://runtime.example.org/sandbox/test",
            image_digest=DIGEST,
            policy_bundle_bytes=b"policy",
            decisions=[],
            call_count=call_count,
        )


@pytest.mark.parametrize(
    "transparency",
    ("", 123, True, [1], {"x": 1}),
    ids=repr,
)
def test_adapter_transparency_refuses_empty_or_non_string(
    transparency: Any,
) -> None:
    with pytest.raises(ValueError, match="transparency"):
        TraceSandboxAdapter(
            model_provider="example-provider",
            model_id="example-model",
            enforcement_mode="declared",
            transparency=transparency,
        )


@pytest.mark.parametrize("attestation", ("tpm2", 123, True, [1], {"platform": "tpm2"}), ids=repr)
def test_session_attestation_refuses_non_attestation_values(attestation: Any) -> None:
    with pytest.raises(ValueError, match="attestation"):
        SandboxSessionResult(
            sandbox_id="spiffe://runtime.example.org/sandbox/test",
            image_digest=DIGEST,
            policy_bundle_bytes=b"policy",
            decisions=[],
            attestation=attestation,
        )


@pytest.mark.parametrize("bad_digest", ("not-a-digest", "", 123, None, True), ids=repr)
def test_software_measurement_refuses_invalid_digests(bad_digest: Any) -> None:
    with pytest.raises(ValueError, match="image_digest"):
        TraceSandboxAdapter.software_measurement(bad_digest, DIGEST)
    with pytest.raises(ValueError, match="bundle_hash"):
        TraceSandboxAdapter.software_measurement(DIGEST, bad_digest)


def test_sandbox_build_trust_record_revalidates_session_and_in_place_mutations() -> None:
    adapter = TraceSandboxAdapter(
        model_provider="example-provider",
        model_id="example-model",
        enforcement_mode="declared",
    )
    with pytest.raises(ValueError, match="session must be a SandboxSessionResult"):
        adapter.build_trust_record(None)  # type: ignore[arg-type]

    session = SandboxSessionResult(
        sandbox_id="spiffe://runtime.example.org/sandbox/test",
        image_digest=DIGEST,
        policy_bundle_bytes=b"policy",
        decisions=[{"tool": "fs.read", "decision": "permit"}],
    )
    session.decisions.append("not-a-dict")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="decisions"):
        adapter.build_trust_record(session)

    attestation = SandboxAttestation(platform="tpm2", measurement=DIGEST)
    tampered_session = SandboxSessionResult(
        sandbox_id="spiffe://runtime.example.org/sandbox/test",
        image_digest=DIGEST,
        policy_bundle_bytes=b"policy",
        decisions=[],
        attestation=attestation,
    )
    object.__setattr__(attestation, "platform", "software-only")
    with pytest.raises(ValueError, match="SandboxAttestation.platform"):
        adapter.build_trust_record(tampered_session)



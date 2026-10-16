"""Regression tests for sandbox adapter required-string primitive boundaries."""

from __future__ import annotations

from typing import Any

import pytest

from agentrust_trace.adapters.sandbox import SandboxAttestation, SandboxSessionResult

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

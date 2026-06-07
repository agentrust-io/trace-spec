from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

_DIGEST_RE = r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$"

DigestStr = Annotated[str, Field(pattern=_DIGEST_RE)]


class ModelInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    model_id: str
    version: str | None = None
    weights_digest: DigestStr | None = None
    aibom_uri: str | None = None


class RuntimeInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: Literal[
        "intel-tdx",
        "amd-sev-snp",
        "nvidia-h100",
        "nvidia-blackwell",
        "aws-nitro",
        "arm-cca",
        "google-confidential-space",
        "tpm2",
    ]
    measurement: DigestStr
    rim_uri: str | None = None
    nonce: str | None = None
    firmware_version: str | None = None


class PolicyInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_hash: DigestStr
    enforcement_mode: Literal["enforce", "advisory", "silent"]
    version: str | None = None
    policy_uri: str | None = None


class ToolTranscript(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hash: DigestStr
    call_count: Annotated[int, Field(ge=0)] | None = None
    transcript_uri: str | None = None


class BuildProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slsa_level: Annotated[int, Field(ge=1, le=3)]
    builder: str | None = None
    digest: DigestStr
    provenance_uri: str | None = None


class Appraisal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["affirming", "warning", "contraindicated", "none"]
    verifier: str
    policy_ref: str | None = None
    timestamp: int | None = None


class JWK(BaseModel):
    # JWK params vary by key type (EC, OKP, RSA) — allow unknown members per RFC 7517
    model_config = ConfigDict(extra="allow")

    kty: str
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    kid: str | None = None


class ConfirmationKey(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jwk: JWK


class TrustRecord(BaseModel):
    """TRACE v0.1 Trust Record — hardware-attested governance evidence for an AI agent execution."""

    model_config = ConfigDict(extra="forbid")

    eat_profile: Literal["tag:agentrust.io,2026:trace-v0.1"]
    iat: Annotated[int, Field(ge=1700000000)]
    subject: Annotated[str, Field(pattern=r"^spiffe://")]
    model: ModelInfo
    runtime: RuntimeInfo
    policy: PolicyInfo
    data_class: str
    tool_transcript: ToolTranscript | None = None
    build_provenance: BuildProvenance
    appraisal: Appraisal
    transparency: str
    cnf: ConfirmationKey

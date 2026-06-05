from __future__ import annotations

from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

_DIGEST_RE = r"^sha(256|384):[0-9a-f]+"

DigestStr = Annotated[str, Field(pattern=_DIGEST_RE)]


class ModelInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    model_id: str
    version: Optional[str] = None
    weights_digest: Optional[DigestStr] = None
    aibom_uri: Optional[str] = None


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
    rim_uri: Optional[str] = None
    nonce: Optional[str] = None
    firmware_version: Optional[str] = None


class PolicyInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_hash: DigestStr
    enforcement_mode: Literal["enforce", "advisory", "silent"]
    version: Optional[str] = None
    policy_uri: Optional[str] = None


class ToolTranscript(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hash: DigestStr
    call_count: Optional[Annotated[int, Field(ge=0)]] = None
    transcript_uri: Optional[str] = None


class BuildProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slsa_level: Annotated[int, Field(ge=1, le=3)]
    builder: Optional[str] = None
    digest: DigestStr
    provenance_uri: Optional[str] = None


class Appraisal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["affirming", "warning", "contraindicated", "none"]
    verifier: str
    policy_ref: Optional[str] = None
    timestamp: Optional[int] = None


class JWK(BaseModel):
    # JWK params vary by key type (EC, OKP, RSA) — allow unknown members per RFC 7517
    model_config = ConfigDict(extra="allow")

    kty: str
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None
    kid: Optional[str] = None


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
    tool_transcript: Optional[ToolTranscript] = None
    build_provenance: BuildProvenance
    appraisal: Appraisal
    transparency: str
    cnf: ConfirmationKey

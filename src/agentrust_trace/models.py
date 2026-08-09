from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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
        # Azure confidential VM: AMD SEV-SNP behind a Hyper-V paravisor. The SNP
        # report is read from the vTPM (the guest does not control REPORT_DATA),
        # so the runtime binding rides a vTPM AK-signed quote rather than the SNP
        # report_data. Distinct from amd-sev-snp so a consumer keying on
        # runtime.platform knows the binding is vTPM-rooted, not direct-silicon.
        "azure-cvm-sev-snp",
        "nvidia-h100",
        "nvidia-blackwell",
        "aws-nitro",
        "arm-cca",
        "google-confidential-space",
        "tpm2",
        # Development / non-attested mode. Distinct from tpm2 so a dev-mode
        # record can never be mistaken for hardware-backed evidence by a
        # consumer that only inspects runtime.platform.
        "software-only",
    ]
    measurement: DigestStr
    rim_uri: str | None = None
    nonce: str | None = None
    firmware_version: str | None = None


class PolicyInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_hash: DigestStr
    enforcement_mode: Literal["enforce", "advisory", "silent", "declared"]
    """How the policy named by ``bundle_hash`` related to this execution.

    The first three all assert that **something evaluated the policy**:
    ``enforce`` acted on the result, ``advisory`` did not, ``silent`` acted and
    suppressed the log lines. ``declared`` asserts less than any of them: the
    policy is named and bound into the signed record, and nothing evaluated it.

    That case is not hypothetical, it is the common one. An agent framework has
    no policy engine, so a record produced by observing a LangChain or LlamaIndex
    run has a policy the operator declares and no evaluation of it anywhere. With
    only three values, such a record had to overstate: ``advisory`` claims an
    evaluation that did not happen. The adapters refused to default the field and
    documented the overstatement, which is honest and leaves every framework
    record marginally untrue.

    ``declared`` is deliberately the weakest value and is never a default. A
    producer that evaluates policy must not use it, and a consumer must not read
    it as evidence that any rule was checked. It says only: this is the policy
    this deployment says it was operating under.
    """
    version: str | None = None
    policy_uri: str | None = None


class ToolTranscript(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hash: DigestStr
    call_count: Annotated[int, Field(ge=0)] | None = None
    transcript_uri: str | None = None


class Delegation(BaseModel):
    """A2A profile: links this record to the record of the delegating hop.

    Present when this execution acted on authority delegated by another agent.
    ``parent_record_hash`` is the digest of the parent hop's Trust Record and
    ``credential_id`` names the delegation credential this hop acted under, so a
    chain of records forms an offline-verifiable delegation DAG. Absent on a
    root (non-delegated) execution.
    """

    model_config = ConfigDict(extra="forbid")

    parent_record_hash: DigestStr
    credential_id: Annotated[str, Field(min_length=1)]


class Origin(BaseModel):
    """Where the evidence in this record came from, when that is not this runtime.

    Absent means the record was produced by the runtime whose execution it
    describes, which is the case a consumer assumes and the case every hardware
    profile is. Present means something else assembled the record from evidence
    it did not itself measure, and it names what.

    This exists because ``runtime.platform: "software-only"`` alone is ambiguous.
    It is the honest value for a dev-mode record *and* for a record transcribed
    from a third-party control plane's log, and those are not the same claim: the
    first is unattested because nothing attested it, the second is unattested
    because the party that asserted it also wrote the log. A consumer deciding
    how much weight to give a record needs to tell them apart, and it cannot from
    ``platform`` alone.

    ``kind`` is closed rather than free text, because the whole value of the field
    is that a verifier can key on it.

    - ``self``: the runtime produced its own record. Equivalent to omitting the
      block; allowed so a producer can state it rather than leave it inferred.
    - ``third-party-control-plane``: assembled from another vendor's runtime
      governance output. The evidence is asserted by the system that produced it,
      with no root outside that system.
    - ``log-import``: assembled from a log or export whose producer is not a
      control plane (a SIEM export, an audit trail, a batch job).

    Neither non-self kind can carry a hardware root, so a record with one of them
    and a hardware ``runtime.platform`` is a contradiction and is rejected.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["self", "third-party-control-plane", "log-import"]
    producer: Annotated[str, Field(min_length=1)]
    source_event_id: Annotated[str, Field(min_length=1)] | None = None
    ingested_at: Annotated[int, Field(ge=1700000000)] | None = None


class BuildProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slsa_level: Annotated[int, Field(ge=0, le=3)]
    builder: str | None = None
    digest: DigestStr
    provenance_uri: str | None = None


class Appraisal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["affirming", "warning", "contraindicated", "none"]
    verifier: str
    policy_ref: str | None = None
    timestamp: int | None = None


# Private/secret JWK members (RFC 7517 §4, RFC 7518 §6). A cnf.jwk is a public
# proof-of-possession key and must never carry these.
_JWK_PRIVATE_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})


class JWK(BaseModel):
    # JWK params vary by key type (EC, OKP, RSA) — allow unknown members per RFC 7517
    model_config = ConfigDict(extra="allow")

    kty: str
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    kid: str | None = None

    @model_validator(mode="after")
    def _require_key_material(self) -> JWK:
        """A confirmation key without key material binds nothing (RFC 7518 §6)."""
        required_by_kty = {"OKP": ("crv", "x"), "EC": ("crv", "x", "y")}
        required = required_by_kty.get(self.kty, ())
        missing = [name for name in required if getattr(self, name) is None]
        if missing:
            raise ValueError(
                f"jwk with kty={self.kty!r} must carry key material: missing {', '.join(missing)}"
            )
        # extra="allow" would otherwise silently store private key material. A cnf.jwk
        # is a public confirmation key, so reject any private/secret member.
        private = sorted(_JWK_PRIVATE_PARAMS.intersection(self.model_extra or {}))
        if private:
            raise ValueError(
                f"jwk must not contain private key material: found {', '.join(private)}. "
                "cnf.jwk is a public proof-of-possession key."
            )
        return self


class ConfirmationKey(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jwk: JWK


class TrustRecord(BaseModel):
    """TRACE v0.1 Trust Record — hardware-attested governance evidence for an AI agent execution."""

    model_config = ConfigDict(extra="forbid")

    eat_profile: Literal["tag:agentrust-io.com,2026:trace-v0.2"]
    iat: Annotated[int, Field(ge=1700000000)]
    subject: Annotated[str, Field(pattern=r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$")]
    model: ModelInfo
    runtime: RuntimeInfo
    policy: PolicyInfo
    data_class: str
    tool_transcript: ToolTranscript | None = None
    delegation: Delegation | None = None
    origin: Origin | None = None
    build_provenance: BuildProvenance
    appraisal: Appraisal
    transparency: Annotated[str, Field(min_length=1)] | None = None
    """SCITT receipt URI resolving to the inclusion proof on the transparency log.

    Optional in the model, and required by conformance at **Level 2**, where
    `TR-ANC` runs (`agentrust-trace-tests`). A Level 0 or Level 1 record is not
    anchored, so it has no receipt to name, and the model must be able to
    represent that. Enforcing a non-empty value here regardless of level made the
    model stricter than both the conformance suite and `schema/trace-claim.json`,
    which sets no minimum length.

    Use `None` for an unanchored record rather than an empty string: `""` is not a
    URI, and a field that looks populated but resolves to nothing is worse than an
    absent one.
    """
    cnf: ConfirmationKey
    signature: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")] | None = None
    """Optional embedded signature (base64url, no padding) by the cnf key over the
    canonical JSON form of the record with only this field absent. Every Trust Record must
    be signature-bound per spec section 3.2.2; enveloped profiles carry the signature
    outside the record instead of in this field."""

    @model_validator(mode="after")
    def _origin_cannot_claim_hardware(self) -> TrustRecord:
        """A record assembled from someone else's evidence cannot carry a hardware root.

        A hardware ``runtime.platform`` asserts that this runtime produced a quote
        rooted in silicon. An importer holding a vendor's log has no quote to
        present, so the combination is not a stricter claim, it is an untrue one,
        and it is exactly the shape an adapter would produce by copying a hardware
        example and editing the fields it understood.
        """
        if self.origin is None or self.origin.kind == "self":
            return self
        if self.runtime.platform != "software-only":
            raise ValueError(
                f"origin.kind={self.origin.kind!r} cannot carry "
                f"runtime.platform={self.runtime.platform!r}: evidence assembled from "
                "another party's output has no hardware root, so the platform must be "
                "'software-only'"
            )
        return self

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

_DIGEST_RE = r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$"

# A workload identity, not a namespace. A SPIFFE ID names a trust domain *and* a
# workload path within it, and a DID names a method and an identifier within that
# method, so neither is complete at its prefix: `spiffe://example.org` names a trust
# domain and no workload, and `did:` names nothing at all. The method name is held to
# lowercase because DID Core section 3.1 fixes `method-char` to `%x61-7A / DIGIT` and
# requires every DID to conform to that ABNF; the method-specific identifier is not
# constrained here, so `did:key:z6Mk...` keeps its case. Mirrored verbatim in
# `schema/trace-claim.json` and its copy, and held there by
# `tests/test_the_schema_and_the_models_agree.py`.
_SUBJECT_RE = r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$"
# ISO 8601 duration, spelled out by alternation rather than with a negative
# lookahead so that the same pattern string can be used here and in the JSON
# Schema: pydantic's default regex engine (Rust) has no look-around, so a
# lookahead form builds in JSON Schema and raises here, and the two files would
# have to disagree. What the alternation buys: at least one component ("P" and
# "PT" alone are rejected), components in order, and the week form standalone.
_DURATION_TIME = r"(\d+H(\d+M)?(\d+S)?|\d+M(\d+S)?|\d+S)"
_DURATION_DATE = r"(\d+Y(\d+M)?(\d+D)?|\d+M(\d+D)?|\d+D)"
_DURATION_RE = rf"^P(\d+W|{_DURATION_DATE}(T{_DURATION_TIME})?|T{_DURATION_TIME})$"

# The JCS safe-integer range, RFC 8785 Appendix B note 1, raised to a MUST by spec
# section 3.2.2. Mirrored here because these models are the other artifact a producer
# builds against, and a model that accepts what the schema rejects sends the failure
# downstream to whichever canonicalizer the producer happens to be using.
JCS_SAFE_INTEGER = 9007199254740991


def _not_a_boolean(value: Any) -> Any:
    """Reject ``True`` and ``False`` where JSON says integer.

    ``isinstance(True, int)`` is a Python fact and not a JSON one. JSON Schema's
    ``"type": "integer"`` does not match a boolean, so ``schema/trace-claim.json``
    rejects ``{"slsa_level": true}`` and these models accepted it, coercing it to
    ``1``. The record was then a claim of SLSA build level 1, assembled out of a
    boolean, that no other implementation would have validated.

    The two fields that did not have this hole, ``iat`` and ``origin.ingested_at``,
    were safe by accident rather than by design: their lower bound is above 1, so
    the coerced value failed the range check afterwards. ``appraisal.timestamp``
    allows 1 and turned ``true`` into 1 January 1970.
    """
    if isinstance(value, bool):
        raise ValueError(
            "expected an integer, got a boolean. JSON Schema type 'integer' does "
            "not match true or false, so a record carrying one is rejected by "
            "schema/trace-claim.json and by any implementation validating against it."
        )
    return value


#: An integer as JSON means it, rather than as Python's type hierarchy means it.
JsonInt = Annotated[int, BeforeValidator(_not_a_boolean)]

DigestStr = Annotated[str, Field(pattern=_DIGEST_RE)]


class _TraceModel(BaseModel):
    """A model whose serialization is a TRACE record, not a Python object dump.

    Pydantic writes every unset optional as an explicit ``null``. The schema permits
    ``null`` for no named field, so ``TrustRecord.model_validate(record).model_dump()``
    produced a record that `validate_json` rejects with "None is not of type 'string'",
    and whose signature no longer verifies, because the added members change the RFC 8785
    canonical bytes the signature is taken over.

    That is the round trip ``sign_record``'s own docstring points a caller at: pass the
    record to ``TrustRecord.model_validate()`` to confirm structural validity before
    writing. A caller who then wrote the model out wrote a broken record, and neither the
    validator nor the signature check runs at the moment the damage is done.

    Absent optional members are therefore omitted rather than nulled.

    Only *declared* fields are dropped. `JWK` sets ``extra="allow"`` and the schema's
    ``canonicalizableValue`` permits a null there, so ``cnf.jwk`` may legitimately carry
    one as data. A first version of this filtered the whole serialized dict and removed
    it, which is the same defect this exists to fix, moved one level down: the round trip
    stopped being identity and the signature stopped verifying, for a record the schema
    accepts. An extra member keeps whatever value it was given.
    """

    @model_serializer(mode="wrap")
    def _omit_absent_optionals(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        extras = self.__pydantic_extra__ or {}
        return {
            key: value
            for key, value in handler(self).items()
            if value is not None or key in extras
        }


class ModelInfo(_TraceModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    model_id: str
    version: str | None = None
    weights_digest: DigestStr | None = None
    aibom_uri: str | None = None


class RuntimeInfo(_TraceModel):
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


class PolicyInfo(_TraceModel):
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


class ToolTranscript(_TraceModel):
    model_config = ConfigDict(extra="forbid")

    hash: DigestStr
    call_count: Annotated[JsonInt, Field(ge=0, le=JCS_SAFE_INTEGER)] | None = None
    transcript_uri: str | None = None


class Delegation(_TraceModel):
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


class Origin(_TraceModel):
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
    ingested_at: Annotated[JsonInt, Field(ge=1700000000, le=JCS_SAFE_INTEGER)] | None = None


class Reference(_TraceModel):
    """A fact outside this record that the record points at. Spec section 3.1.2.

    ``origin`` records where evidence *came from* and can lower assurance.
    ``references`` records what a record *points at* and cannot. Before this
    block existed, a record that needed to name something external had to use
    ``origin`` and take ``runtime.platform: "software-only"`` with it, which said
    something untrue about how the evidence was obtained.

    An entry is a pointer, not evidence. What the signature attests is that this
    record points there, not the truth of what it points at. The pointer is
    produced inside the boundary that produced the record; the target is not.
    Two consequences the spec states as MUST NOT are verifier behaviour and so
    are not expressible here: a verifier does not reject a record because an
    entry cannot be resolved, and it does not treat a resolved entry as attested
    evidence. Both live in the conformance suite. This model fixes the shape.

    ``rel`` is open, unlike ``Origin.kind``. Section 3.1.1 says of ``kind`` that it
    is closed "because the value of the field is that a verifier can key on it";
    section 3.1.2 deliberately does not say that of ``rel``, and calls its values a
    registry. Closing it here would make every new relation a schema change and a
    spec change at once. The registered values are named in the schema description
    and in docs/schema.md, and are documented rather than enforced.

    ``resolver`` names the party obliged to resolve ``id``. The specification
    requires a producer that cannot name one to omit the entry rather than emit a
    self-asserted resolver, and whether an identifier is self-asserted is not
    decidable from the record, so the constraint here is presence and not value.

    ``retention`` states an undertaking that nothing in the specification
    enforces. It is validated as an ISO 8601 duration and nothing more.
    """

    model_config = ConfigDict(extra="forbid")

    rel: Annotated[str, Field(min_length=1)]
    id: Annotated[str, Field(min_length=1)]
    resolver: Annotated[str, Field(min_length=1)]
    retention: Annotated[str, Field(pattern=_DURATION_RE)] | None = None
    digest: DigestStr | None = None


class BuildProvenance(_TraceModel):
    model_config = ConfigDict(extra="forbid")

    slsa_level: Annotated[JsonInt, Field(ge=0, le=3)]
    builder: str | None = None
    digest: DigestStr
    provenance_uri: str | None = None
    # Absent means surface: the shallowest depth, so an existing record keeps its
    # meaning rather than becoming unverifiable at a depth nobody claimed.
    provenance_depth: Literal["surface", "builder", "transitive"] | None = None


class Appraisal(_TraceModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["affirming", "warning", "contraindicated", "none"]
    verifier: str
    policy_ref: str | None = None
    timestamp: Annotated[JsonInt, Field(ge=-JCS_SAFE_INTEGER, le=JCS_SAFE_INTEGER)] | None = None
    # What this verifier ran, not what the issuer claimed.
    provenance_depth_verified: Literal["surface", "builder", "transitive"] | None = None


# Private/secret JWK members (RFC 7517 §4, RFC 7518 §6). A cnf.jwk is a public
# proof-of-possession key and must never carry these.
_JWK_PRIVATE_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})


class JWK(_TraceModel):
    # JWK params vary by key type (EC, OKP, RSA): allow unknown members per RFC 7517
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


class ConfirmationKey(_TraceModel):
    model_config = ConfigDict(extra="forbid")

    jwk: JWK


class TrustRecord(_TraceModel):
    """TRACE v0.2 Trust Record: hardware-attested governance evidence for an AI agent execution."""

    model_config = ConfigDict(extra="forbid")

    eat_profile: Literal["tag:agentrust-io.com,2026:trace-v0.2"]
    iat: Annotated[JsonInt, Field(ge=1700000000, le=JCS_SAFE_INTEGER)]
    subject: Annotated[str, Field(pattern=_SUBJECT_RE)]
    model: ModelInfo
    runtime: RuntimeInfo
    policy: PolicyInfo
    data_class: str
    tool_transcript: ToolTranscript | None = None
    delegation: Delegation | None = None
    origin: Origin | None = None
    references: list[Reference] | None = None
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

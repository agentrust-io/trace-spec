"""RFC-0001/0002 local reference prototype, not a released TRACE profile.

The issuer appraises evidence. This consumer authenticates that issuer and
rederives combination results; it does not reappraise hardware reports.
Inputs called `requirements` come from authenticated manifest intent and/or
local policy. Extracting those inputs from a future manifest is an adapter
responsibility, not something a token is permitted to do for itself.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Annotated, Any, Final, Literal, ParamSpec, TypeVar

import cbor2
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

PROFILE: Final = "urn:agentrust:trace:verifier-token:experimental-v1"
PROOF_PROFILE: Final = "urn:agentrust:trace:holder-proof:experimental-v1"
RECEIPT_PROFILE: Final = "urn:agentrust:trace:decision-receipt:experimental-v1"
APPRAISAL_PROFILE: Final = "urn:agentrust:trace:component-appraisal:experimental-v1"
CONTENT_TYPE = "application/trace-verifier-token+json"
MEDIA_TYPES = {
    PROFILE: CONTENT_TYPE,
    PROOF_PROFILE: "application/trace-holder-proof+json",
    RECEIPT_PROFILE: "application/trace-decision-receipt+json",
    APPRAISAL_PROFILE: "application/trace-component-appraisal+json",
}
PROFILE_HEADER = "trace-profile"  # Private string label, no IANA registration claim.
LIMIT = 65536
Text = Annotated[str, Field(min_length=1, max_length=255)]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Time = Annotated[int, Field(ge=0, le=9007199254740991)]
Status = Literal[
    "affirming", "warning", "contraindicated", "unverifiable", "missing", "not-appraised"
]
Category = Literal[
    "identity",
    "code",
    "model",
    "policy",
    "runtime",
    "accelerator",
    "mcp-server",
    "tool-catalog",
    "guardrail",
    "data-state",
]
# Binding methods. same-evidence-v1 adds a shared evidence digest to same-instance-v1.
Method = Literal["same-instance-v1", "same-evidence-v1"]
# Unpadded base64url of a component-appraisal COSE_Sign1 envelope.
AppraisalText = Annotated[str, Field(min_length=1, max_length=16384, pattern=r"^[A-Za-z0-9_-]+$")]


class ProfileError(ValueError):
    """Stable safe reason code; no untrusted diagnostic content."""


_P = ParamSpec("_P")
_R = TypeVar("_R")


def _errors(function: Callable[_P, _R]) -> Callable[_P, _R]:
    """Normalize malformed direct inputs while retaining precise refusals."""
    from functools import wraps

    @wraps(function)
    def checked(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        try:
            return function(*args, **kwargs)
        except ProfileError:
            raise
        except (
            ValueError,
            TypeError,
            AttributeError,
            KeyError,
            IndexError,
            OverflowError,
            RecursionError,
        ) as exc:
            raise ProfileError("input_invalid") from exc

    return checked


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Policy(Closed):
    id: Text
    version: Text
    digest: Digest


class Requirement(Closed):
    component_id: Identifier
    component_type: Category
    required: bool
    accepted_profiles: Annotated[list[Text], Field(min_length=1, max_length=16)]
    accepted_authorities: Annotated[list[Text], Field(min_length=1, max_length=16)]
    maximum_age_seconds: Annotated[int, Field(ge=1, le=86400)]
    expected_observed_digest: Digest | None = None


class BindingRequirement(Closed):
    source: Identifier
    target: Identifier
    relationship: Literal["same-workload"]
    method: Method


class Requirements(Closed):
    components: Annotated[list[Requirement], Field(min_length=1, max_length=64)]
    bindings: Annotated[list[BindingRequirement], Field(max_length=128)]
    allow_warnings: bool

    @model_validator(mode="after")
    def check_ids(self) -> Requirements:
        ids = [c.component_id for c in self.components]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_requirement")
        triples = [(b.source, b.target, b.relationship, b.method) for b in self.bindings]
        if len(triples) != len(set(triples)):
            raise ValueError("duplicate_binding_requirement")
        if any(
            b.source not in ids or b.target not in ids or b.source == b.target
            for b in self.bindings
        ):
            raise ValueError("binding_endpoint")
        return self


class EvidenceRef(Closed):
    profile: Text
    media_type: Text
    digest: Digest
    resolver: Text | None = None


class Component(Closed):
    component_id: Identifier
    component_type: Category
    profile: Text
    authority: Text
    instance: Identifier
    status: Status
    appraised_at: Time
    fresh_until: Time
    evidence_refs: Annotated[list[EvidenceRef], Field(max_length=16)]
    observed_digest: Digest | None = None
    reasons: Annotated[list[Identifier], Field(max_length=16)]
    # Delegated appraisal envelope. Never null on the wire; absent means not carried.
    appraisal: AppraisalText = Field(default=None, exclude_if=lambda value: value is None)


class ComponentAppraisal(Closed):
    """Payload a delegated appraiser signs: its name and the component minus `appraisal`."""

    profile: Literal["urn:agentrust:trace:component-appraisal:experimental-v1"]
    iss: Text
    component: Component


class Binding(Closed):
    source: Identifier
    target: Identifier
    relationship: Literal["same-workload"]
    method: Method
    status: Status
    digest: Digest
    fresh_until: Time


class HolderKey(Closed):
    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]


class ManifestRef(Closed):
    id: Text
    media_type: Literal["application/agent-manifest+cose"]
    version: Literal["0.2"]
    digest: Digest


class Composite(Closed):
    status: Status
    required_components: Annotated[list[Identifier], Field(max_length=64)]
    policy: Policy
    fresh_until: Time


class Token(Closed):
    profile: Literal["urn:agentrust:trace:verifier-token:experimental-v1"]
    iss: Text
    sub: Identifier
    instance: Identifier
    iat: Time
    exp: Time
    jti: Identifier
    aud: Identifier
    cnf: HolderKey
    manifest: ManifestRef
    verification_context_hash: Digest
    appraisal_policy: Policy
    components: Annotated[list[Component], Field(max_length=64)]
    bindings: Annotated[list[Binding], Field(max_length=128)]
    composite_appraisal: Composite


class Proof(Closed):
    profile: Literal["urn:agentrust:trace:holder-proof:experimental-v1"]
    nonce: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
    token_digest: Digest
    token_id: Identifier
    audience: Identifier
    session_id: Identifier
    action_digest: Digest
    issued_at: Time
    expires_at: Time


class Receipt(Closed):
    profile: Literal["urn:agentrust:trace:decision-receipt:experimental-v1"]
    issuer: Identifier
    issued_at: Time
    session_id: Identifier
    call_id: Identifier
    trace_digest: Digest
    trace_jti: Identifier
    action_digest: Digest
    policy_digest: Digest
    decision: Literal["allow", "deny"]
    reason: Identifier
    previous_receipt_hash: Digest | None = None


@_errors
def digest(data: bytes) -> str:
    if type(data) is not bytes:
        raise ProfileError("bytes_required")
    return "sha256:" + hashlib.sha256(data).hexdigest()


@_errors
def canonical_digest(value: Any) -> str:
    return digest(rfc8785.dumps(value))


@_errors
def public_bytes(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


@_errors
def key_id(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    return hashlib.sha256(public_bytes(key)).digest()


@_errors
def holder_key(key: Ed25519PrivateKey | Ed25519PublicKey) -> HolderKey:
    return HolderKey(
        kty="OKP", crv="Ed25519", x=base64.urlsafe_b64encode(public_bytes(key)).decode().rstrip("=")
    )


@_errors
def holder_public(cnf: HolderKey) -> Ed25519PublicKey:
    try:
        raw = base64.urlsafe_b64decode(cnf.x + "=")
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != cnf.x:
            raise ValueError("noncanonical_key")
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ProfileError("holder_key_invalid") from exc


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ProfileError("duplicate_json_key")
        result[name] = value
    return result


def _canonical_cbor(data: bytes) -> Any:
    stream = io.BytesIO(data)
    value = cbor2.CBORDecoder(stream).decode()
    if stream.read(1) or cbor2.dumps(value, canonical=True) != data:
        raise ProfileError("noncanonical_cbor")
    return value


@_errors
def sign_payload(payload: Closed, key: Ed25519PrivateKey) -> bytes:
    """COSE_Sign1 tag 18, fully specified Ed25519 -19, JCS JSON payload."""
    raw = rfc8785.dumps(payload.model_dump(mode="json"))
    if len(raw) > LIMIT:
        raise ProfileError("payload_too_large")
    profile = payload.model_dump()["profile"]
    if profile not in MEDIA_TYPES:
        raise ProfileError("profile_unsupported")
    protected = cbor2.dumps(
        {
            1: -19,
            2: [PROFILE_HEADER],
            3: MEDIA_TYPES[profile],
            4: key_id(key),
            PROFILE_HEADER: profile,
        },
        canonical=True,
    )
    signature = key.sign(cbor2.dumps(["Signature1", protected, b"", raw], canonical=True))
    envelope = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, raw, signature]), canonical=True)
    if len(envelope) > LIMIT:
        raise ProfileError("envelope_size")
    return envelope


@_errors
def unpack(envelope: bytes, profile: str) -> tuple[bytes, bytes, bytes, bytes]:
    """Reject duplicates, trailing bytes, unprotected headers and routing ambiguity."""
    try:
        if profile not in MEDIA_TYPES:
            raise ProfileError("profile_unsupported")
        if not isinstance(envelope, bytes) or len(envelope) > LIMIT:
            raise ProfileError("envelope_size")
        tagged = _canonical_cbor(envelope)
        if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != 18:
            raise ProfileError("envelope_tag")
        body = tagged.value
        if not isinstance(body, (list, tuple)) or len(body) != 4:
            raise ProfileError("envelope_structure")
        protected, unprotected, raw, signature = body
        if unprotected != {} or not all(isinstance(x, bytes) for x in (protected, raw, signature)):
            raise ProfileError("envelope_structure")
        headers = _canonical_cbor(protected)
        if (
            not isinstance(headers, Mapping)
            or set(headers) != {1, 2, 3, 4, PROFILE_HEADER}
            or any(type(k) is not int for k in headers if k != PROFILE_HEADER)
            or headers[1] != -19
            or type(headers[1]) is not int
            or list(headers[2]) != [PROFILE_HEADER]
            or headers[3] != MEDIA_TYPES[profile]
            or headers[PROFILE_HEADER] != profile
            or not isinstance(headers[4], bytes)
            or len(headers[4]) != 32
            or len(signature) != 64
        ):
            raise ProfileError("protected_headers")
        return protected, raw, signature, headers[4]
    except ProfileError:
        raise
    except (ValueError, TypeError, RecursionError, IndexError) as exc:
        raise ProfileError("malformed_envelope") from exc


@_errors
def read_payload(raw: bytes, model: type[Closed]) -> Any:
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        if rfc8785.dumps(value) != raw:
            raise ProfileError("noncanonical_payload")
        return model.model_validate(value)
    except ProfileError:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProfileError("malformed_payload") from exc


@_errors
def authenticate(envelope: bytes, profile: str, key: Ed25519PublicKey, model: type[Closed]) -> Any:
    protected, raw, signature, kid = unpack(envelope, profile)
    if kid != key_id(key):
        raise ProfileError("key_id_mismatch")
    try:
        key.verify(signature, cbor2.dumps(["Signature1", protected, b"", raw], canonical=True))
    except InvalidSignature as exc:
        raise ProfileError("signature_invalid") from exc
    return read_payload(raw, model)


@_errors
def binding_digest(source: Component, target: Component, method: str) -> str:
    """Commit endpoint identity, instance, observations and exact evidence references.

    The preimage is each component exactly as signed: an optional member absent
    from the wire stays absent, so a verifier can recompute it from the payload.
    """
    return canonical_digest(
        {
            "method": method,
            "source": source.model_dump(mode="json", exclude_unset=True),
            "target": target.model_dump(mode="json", exclude_unset=True),
        }
    )


def _b64url(text: str) -> bytes:
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != text:
        raise ValueError("noncanonical_base64url")
    return raw


def _delegated(component: Component, token: Token, appraisers: Mapping[Any, Any], now: int) -> bool:
    """Whether a component from another authority carries a trusted, in-grant appraisal.

    Refusals: an appraisal on an issuer-appraised component, a malformed envelope,
    a bad signature under the configured appraiser key, or signed content that
    differs from the carried component. An absent appraisal, an unconfigured or
    out-of-window appraiser and an out-of-grant profile or type return False, which
    leaves the component unverifiable.
    """
    if component.appraisal is None:
        return False
    if component.authority == token.iss:
        raise ProfileError("component_appraisal_unexpected")
    try:
        appraisal_envelope = _b64url(component.appraisal)
        protected, raw, signature, kid = unpack(appraisal_envelope, APPRAISAL_PROFILE)
        signed: ComponentAppraisal = read_payload(raw, ComponentAppraisal)
    except (ProfileError, ValueError) as exc:
        raise ProfileError("component_appraisal_malformed") from exc
    appraiser = appraisers.get((component.authority, kid))
    if appraiser is None or not appraiser.valid_from <= now < appraiser.valid_until:
        return False
    try:
        appraiser.key.verify(
            signature, cbor2.dumps(["Signature1", protected, b"", raw], canonical=True)
        )
    except InvalidSignature as exc:
        raise ProfileError("component_appraisal_signature_invalid") from exc
    carried = component.model_dump(mode="json", exclude_unset=True)
    carried.pop("appraisal")
    signed_component = signed.component.model_dump(mode="json", exclude_unset=True)
    if signed.iss != component.authority or signed_component != carried:
        raise ProfileError("component_appraisal_mismatch")
    granted = component.component_type in appraiser.component_types
    return granted and component.profile in appraiser.profiles


@_errors
def derive_composite(
    token: Token,
    requirements: Requirements,
    policy: Policy,
    now: int,
    trusted_appraisers: Mapping[tuple[str, bytes], TrustedAppraiser] | None = None,
) -> tuple[Status, int, list[str]]:
    appraisers = {} if trusted_appraisers is None else trusted_appraisers
    if not isinstance(appraisers, Mapping):
        raise ProfileError("input_invalid")
    components = {c.component_id: c for c in token.components}
    if len(components) != len(token.components):
        raise ProfileError("duplicate_component")
    known = {r.component_id for r in requirements.components}
    if set(components) - known:
        raise ProfileError("undeclared_component")
    bindings = {(b.source, b.target, b.relationship, b.method): b for b in token.bindings}
    if len(bindings) != len(token.bindings):
        raise ProfileError("duplicate_binding")
    expected_bindings = {
        (b.source, b.target, b.relationship, b.method) for b in requirements.bindings
    }
    if set(bindings) - expected_bindings:
        raise ProfileError("undeclared_binding")
    statuses: list[Status] = []
    boundaries = [token.exp]
    binding_endpoints = {b.source for b in requirements.bindings} | {
        b.target for b in requirements.bindings
    }
    required = sorted(
        {r.component_id for r in requirements.components if r.required} | binding_endpoints
    )
    for requirement in requirements.components:
        component = components.get(requirement.component_id)
        if component is None:
            if requirement.component_id in required:
                statuses.append("missing")
            continue
        if component.component_type != requirement.component_type:
            raise ProfileError("component_type_mismatch")
        if (
            requirement.expected_observed_digest is not None
            and component.observed_digest != requirement.expected_observed_digest
        ):
            raise ProfileError("component_observation_mismatch")
        if component.instance != token.instance:
            raise ProfileError("mixed_instance")
        if component.appraised_at > token.iat or component.fresh_until <= component.appraised_at:
            raise ProfileError("component_interval")
        if component.fresh_until > component.appraised_at + requirement.maximum_age_seconds:
            raise ProfileError("component_age_bound")
        if component.status in ("affirming", "warning") and not component.evidence_refs:
            raise ProfileError("evidence_missing")
        if any(e.profile != component.profile for e in component.evidence_refs):
            raise ProfileError("evidence_profile_mismatch")
        delegated = _delegated(component, token, appraisers, now)
        status: Status = component.status
        if (
            component.profile not in requirement.accepted_profiles
            or component.authority not in requirement.accepted_authorities
            or (component.authority != token.iss and not delegated)
        ):
            status = "unverifiable"
        if requirement.component_id in required:
            boundaries.append(component.fresh_until)
            statuses.append(status)
    for binding_requirement in requirements.bindings:
        identity = (
            binding_requirement.source,
            binding_requirement.target,
            binding_requirement.relationship,
            binding_requirement.method,
        )
        binding = bindings.get(identity)
        source = components.get(binding_requirement.source)
        target = components.get(binding_requirement.target)
        if binding is None or source is None or target is None:
            statuses.append("missing")
            continue
        if binding.digest != binding_digest(source, target, binding.method):
            raise ProfileError("binding_digest_mismatch")
        if source.instance != target.instance or source.instance != token.instance:
            raise ProfileError("mixed_instance")
        if binding.fresh_until > min(source.fresh_until, target.fresh_until):
            raise ProfileError("binding_interval")
        shared = {e.digest for e in source.evidence_refs} & {e.digest for e in target.evidence_refs}
        if binding.method == "same-evidence-v1" and not shared:
            raise ProfileError("binding_evidence_disjoint")
        boundaries.append(binding.fresh_until)
        statuses.append(binding.status)
    fresh_until = min(boundaries)
    if token.exp > fresh_until:
        raise ProfileError("expiry_exceeds_evidence")
    if now >= fresh_until:
        raise ProfileError("component_expired")
    order: tuple[Status, ...] = ("contraindicated", "missing", "unverifiable", "not-appraised")
    overall: Status = next((s for s in order if s in statuses), "affirming")
    if overall == "affirming" and "warning" in statuses:
        overall = "warning" if requirements.allow_warnings else "contraindicated"
    composite = token.composite_appraisal
    if (
        composite.status != overall
        or composite.fresh_until != fresh_until
        or composite.required_components != required
        or composite.policy != policy
    ):
        raise ProfileError("composite_inconsistent")
    return overall, fresh_until, required


@dataclass(frozen=True)
class TrustedIssuer:
    issuer: str
    key: Ed25519PublicKey
    valid_from: int
    valid_until: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.key, Ed25519PublicKey)
            or not isinstance(self.issuer, str)
            or not self.issuer
            or type(self.valid_from) is not int
            or type(self.valid_until) is not int
            or not 0 <= self.valid_from < self.valid_until <= 9007199254740991
        ):
            raise ProfileError("issuer_configuration_invalid")


@dataclass(frozen=True)
class TrustedAppraiser:
    """A relying-party grant: `authority` may appraise these profiles and component types."""

    authority: str
    key: Ed25519PublicKey
    profiles: frozenset[str]
    component_types: frozenset[str]
    valid_from: int
    valid_until: int

    def __post_init__(self) -> None:
        try:
            if (
                not isinstance(self.key, Ed25519PublicKey)
                or type(self.profiles) is not frozenset
                or type(self.component_types) is not frozenset
                or not self.profiles
                or not self.component_types
                or type(self.valid_from) is not int
                or type(self.valid_until) is not int
                or not 0 <= self.valid_from < self.valid_until <= 9007199254740991
            ):
                raise ValueError("invalid appraiser")
            TypeAdapter(Text).validate_python(self.authority, strict=True)
            for profile in self.profiles:
                TypeAdapter(Text).validate_python(profile, strict=True)
            for component_type in self.component_types:
                TypeAdapter(Category).validate_python(component_type, strict=True)
        except (ValueError, TypeError) as exc:
            raise ProfileError("appraiser_configuration_invalid") from exc


@dataclass(frozen=True)
class VerificationContext:
    """Caller-controlled trust and independently verified manifest/policy inputs.

    Exact-byte matching does not verify a manifest signature, revocation, model
    state or hardware. The admission adapter supplies those checked inputs.
    `status_check` authenticates current issuer/holder/manifest/token status and
    fails closed if unavailable; no status comes from the token's own assertion.
    """

    audience: str
    subject: str
    instance: str
    manifest_bytes: bytes
    manifest_id: str
    manifest_valid_until: int
    question_digest: str
    policy: Policy
    requirements: Requirements
    trusted_issuers: Mapping[tuple[str, bytes], TrustedIssuer]
    status_check: Callable[[Token, int], bool]
    maximum_lifetime: int = 300
    # (authority, key ID) -> delegated component appraiser. Empty: issuer-only appraisal.
    trusted_appraisers: Mapping[tuple[str, bytes], TrustedAppraiser] = field(default_factory=dict)

    def __post_init__(self) -> None:
        try:
            for value in (self.audience, self.subject, self.instance):
                TypeAdapter(Identifier).validate_python(value, strict=True)
            TypeAdapter(Text).validate_python(self.manifest_id, strict=True)
            TypeAdapter(Digest).validate_python(self.question_digest, strict=True)
            TypeAdapter(Time).validate_python(self.manifest_valid_until, strict=True)
            if (
                type(self.manifest_bytes) is not bytes
                or not self.manifest_bytes
                or len(self.manifest_bytes) > 1048576
                or type(self.maximum_lifetime) is not int
                or not 1 <= self.maximum_lifetime <= 86400
                or not callable(self.status_check)
                or not isinstance(self.trusted_issuers, Mapping)
                or not isinstance(self.trusted_appraisers, Mapping)
            ):
                raise ValueError("invalid configured input")
            Policy.model_validate(self.policy.model_dump())
            Requirements.model_validate(self.requirements.model_dump())
            for identity, issuer in self.trusted_issuers.items():
                if (
                    type(identity) is not tuple
                    or len(identity) != 2
                    or identity[0] != issuer.issuer
                    or type(identity[1]) is not bytes
                    or len(identity[1]) != 32
                    or not isinstance(issuer.key, Ed25519PublicKey)
                    or key_id(issuer.key) != identity[1]
                ):
                    raise ValueError("invalid configured issuer mapping")
            for identity, appraiser in self.trusted_appraisers.items():
                if (
                    type(identity) is not tuple
                    or len(identity) != 2
                    or not isinstance(appraiser, TrustedAppraiser)
                    or identity[0] != appraiser.authority
                    or type(identity[1]) is not bytes
                    or len(identity[1]) != 32
                    or key_id(appraiser.key) != identity[1]
                ):
                    raise ValueError("invalid configured appraiser mapping")
        except (ValueError, TypeError, AttributeError) as exc:
            raise ProfileError("context_configuration_invalid") from exc


@_errors
def verify_token(envelope: bytes, context: VerificationContext, now: int) -> Token:
    """Authenticate issuer independently of cnf; enforce every configured binding."""
    if not isinstance(context, VerificationContext) or type(now) is not int or now < 0:
        raise ProfileError("verification_inputs_invalid")
    protected, raw, signature, kid = unpack(envelope, PROFILE)
    token: Token = read_payload(raw, Token)
    trusted = context.trusted_issuers.get((token.iss, kid))
    if trusted is None or trusted.issuer != token.iss:
        raise ProfileError("issuer_untrusted")
    if not trusted.valid_from <= now < trusted.valid_until:
        raise ProfileError("issuer_expired")
    try:
        trusted.key.verify(
            signature, cbor2.dumps(["Signature1", protected, b"", raw], canonical=True)
        )
    except InvalidSignature as exc:
        raise ProfileError("signature_invalid") from exc
    if key_id(trusted.key) != kid:
        raise ProfileError("key_id_mismatch")
    if public_bytes(holder_public(token.cnf)) == public_bytes(trusted.key):
        raise ProfileError("issuer_holder_same_key")
    if type(now) is not int or not token.iat <= now < token.exp:
        raise ProfileError("token_expired_or_future")
    if token.exp <= token.iat or token.exp - token.iat > context.maximum_lifetime:
        raise ProfileError("token_lifetime")
    if token.exp > min(trusted.valid_until, context.manifest_valid_until):
        raise ProfileError("expiry_exceeds_credential")
    if token.aud != context.audience:
        raise ProfileError("audience_mismatch")
    if token.sub != context.subject or token.instance != context.instance:
        raise ProfileError("subject_or_instance_mismatch")
    if (
        token.manifest.digest != digest(context.manifest_bytes)
        or token.manifest.id != context.manifest_id
    ):
        raise ProfileError("manifest_mismatch")
    if token.verification_context_hash != context.question_digest:
        raise ProfileError("context_mismatch")
    if token.appraisal_policy != context.policy:
        raise ProfileError("policy_mismatch")
    try:
        active = context.status_check(token.model_copy(deep=True), now)
    except Exception as exc:
        raise ProfileError("status_unavailable") from exc
    if active is not True:
        raise ProfileError("status_not_active")
    derive_composite(token, context.requirements, context.policy, now, context.trusted_appraisers)
    return token


@_errors
def verify_proof(
    proof_bytes: bytes,
    token_bytes: bytes,
    token: Token,
    *,
    nonce: str,
    audience: str,
    session_id: str,
    action_digest: str,
    challenge_issued_at: int,
    challenge_expires_at: int,
    now: int,
) -> Proof:
    proof: Proof = authenticate(proof_bytes, PROOF_PROFILE, holder_public(token.cnf), Proof)
    if (
        proof.nonce != nonce
        or proof.token_digest != digest(token_bytes)
        or proof.token_id != token.jti
        or proof.audience != audience
        or proof.session_id != session_id
        or proof.action_digest != action_digest
    ):
        raise ProfileError("holder_proof_binding")
    if (
        not challenge_issued_at <= now < challenge_expires_at
        or proof.issued_at != challenge_issued_at
        or proof.expires_at != challenge_expires_at
        or proof.expires_at > token.exp
    ):
        raise ProfileError("holder_proof_expired")
    return proof


class RelyingParty:
    """Local per-call harness: verify, consume one-use challenge, apply policy.

    This is not wired into cMCP's production forwarding path or Cedar. A caller
    must evaluate action policy independently and forward only an allow result.
    """

    def __init__(self, context: VerificationContext) -> None:
        self.context = context
        self._challenges: dict[str, tuple[str, str, int, int]] = {}
        self._used_nonces: dict[str, int] = {}
        self._lock = Lock()

    def challenge(
        self, *, nonce: str, session_id: str, action_digest: str, issued_at: int, expires_at: int
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce):
            raise ProfileError("nonce_shape")
        if not issued_at < expires_at <= issued_at + 30:
            raise ProfileError("challenge_interval")
        with self._lock:
            self._used_nonces = {n: end for n, end in self._used_nonces.items() if end > issued_at}
            self._challenges = {n: c for n, c in self._challenges.items() if c[3] > issued_at}
            if nonce in self._challenges or nonce in self._used_nonces:
                raise ProfileError("challenge_reused")
            if len(self._challenges) + len(self._used_nonces) >= 4096:
                raise ProfileError("challenge_capacity")
            self._challenges[nonce] = (session_id, action_digest, issued_at, expires_at)

    def authorize(
        self,
        token_bytes: bytes,
        proof_bytes: bytes,
        *,
        nonce: str,
        action: dict[str, Any],
        session_id: str,
        now: int,
        policy: Callable[[Token, dict[str, Any]], bool],
    ) -> tuple[Token, bool]:
        token = verify_token(token_bytes, self.context, now)
        with self._lock:
            challenge = self._challenges.pop(nonce, None)
            if challenge is not None:
                self._used_nonces[nonce] = challenge[3]
        if challenge is None:
            raise ProfileError("challenge_missing_or_consumed")
        session, expected_action, issued, expires = challenge
        snapshot = json.loads(rfc8785.dumps(action))
        action_hash = canonical_digest(snapshot)
        if session != session_id or expected_action != action_hash:
            raise ProfileError("challenge_action_or_session")
        verify_proof(
            proof_bytes,
            token_bytes,
            token,
            nonce=nonce,
            audience=self.context.audience,
            session_id=session_id,
            action_digest=action_hash,
            challenge_issued_at=issued,
            challenge_expires_at=expires,
            now=now,
        )
        if token.composite_appraisal.status not in ("affirming", "warning"):
            raise ProfileError("appraisal_not_acceptable")
        if (
            token.composite_appraisal.status == "warning"
            and not self.context.requirements.allow_warnings
        ):
            raise ProfileError("warning_not_acceptable")
        decision = policy(token.model_copy(deep=True), snapshot)
        if type(decision) is not bool:
            raise ProfileError("policy_result_invalid")
        return token, decision

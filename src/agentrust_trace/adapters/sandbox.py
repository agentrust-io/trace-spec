"""TraceSandboxAdapter — maps a sandboxed agent runtime's session output to a Trust Record.

A sandboxed agent runtime confines one agent on one machine: filesystem, process and
network isolation at the kernel, an egress policy, and credentials injected without the
agent holding them. That answers what a single agent may touch. It does not answer, on
its own, what the agent did, under which rules, on which machine, in a form somebody who
trusts neither the operator nor the vendor can check.

This adapter closes that gap without changing the runtime. It consumes what the runtime
already has at session close and emits a signed Trust Record::

    session = SandboxSessionResult(
        sandbox_id="spiffe://runtime.example.org/sandbox/build-7f2a",
        image_digest="sha256:" + "a" * 64,
        policy_bundle_bytes=Path("sandbox-policy.yaml").read_bytes(),
        decisions=runtime.decision_log(),
    )
    record = sign_record(adapter.build_trust_record(session), key)

Two things separate this from :class:`~agentrust_trace.adapters.agt.TraceAGTAdapter`,
and both come from the deployments this was written for.

**It spans Level 0 and Level 1 from one code path.** A sandbox runs wherever the
customer runs it: a laptop with a TPM, a confidential VM, a machine with no secure
hardware at all. Passing a :class:`SandboxAttestation` moves the record from
``software-only`` to the platform that produced the evidence, and nothing else about
the call changes. An adapter that could only emit Level 0 would force a second code
path for the deployments that matter most.

**It will not let a caller claim hardware it does not have.** ``platform`` is only ever
set from a supplied attestation, an attestation may not name ``software-only``, and the
platform is checked against the enum on :class:`~agentrust_trace.models.RuntimeInfo`
rather than a copy of it. A record that says ``tpm2`` therefore carries a measurement
that something other than this process produced.

Sandbox identity and image are carried in the existing v0.2 fields (``subject`` and
``build_provenance.digest``). A dedicated ``sandbox`` object belongs in a later profile;
this adapter deliberately needs no schema change.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal, get_args

import rfc8785

from agentrust_trace.models import (
    Appraisal,
    BuildProvenance,
    ModelInfo,
    PolicyInfo,
    RuntimeInfo,
    ToolTranscript,
)

__all__ = ["SandboxAttestation", "SandboxSessionResult", "TraceSandboxAdapter"]

# Read the accepted platforms off the model so this cannot drift from the schema when a
# new platform lands. A hand-maintained copy is exactly the kind of thing that silently
# rots and then accepts a platform the verifier rejects.
_PLATFORMS: frozenset[str] = frozenset(
    get_args(RuntimeInfo.model_fields["platform"].annotation)
)

# Mirrors TrustRecord.subject. Checked here so a bad identity fails at the adapter with
# a message naming the field, rather than at model_validate() several steps later.
_SUBJECT_RE = re.compile(r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$")

_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")


@dataclass(frozen=True)
class SandboxAttestation:
    """Hardware evidence for the machine a sandbox ran on.

    Supply this when the host produced attestation evidence. Omit it and the record is
    Level 0, marked ``software-only``, which is the honest description of a sandbox on
    a machine with no root of trust.
    """

    platform: str
    """One of the platforms accepted by :class:`~agentrust_trace.models.RuntimeInfo`.
    ``software-only`` is rejected: an attestation that attests nothing is a contradiction,
    and omitting the attestation says the same thing without the claim."""

    measurement: str
    """``sha256:`` or ``sha384:`` digest supplied by the platform, not computed here.
    Becomes ``runtime.measurement``."""

    rim_uri: str | None = None
    firmware_version: str | None = None
    nonce: str | None = None

    def __post_init__(self) -> None:
        if self.platform == "software-only":
            raise ValueError(
                "SandboxAttestation.platform must not be 'software-only'. Omit the "
                "attestation entirely for an unattested sandbox; the adapter then emits "
                "platform='software-only' with a measurement derived from the image and "
                "policy digests, which is what an unattested record should say."
            )
        if self.platform not in _PLATFORMS:
            raise ValueError(
                f"SandboxAttestation.platform {self.platform!r} is not an accepted "
                f"platform. Accepted: {', '.join(sorted(_PLATFORMS))}."
            )
        if not _DIGEST_RE.match(self.measurement):
            raise ValueError(
                f"SandboxAttestation.measurement {self.measurement!r} is not a sha256: or "
                "sha384: digest. It must be the measurement the platform reported, not a "
                "value computed by this process."
            )


@dataclass
class SandboxSessionResult:
    """One sandbox session, as the runtime has it at close.

    Every field is something a sandboxed runtime already knows. Nothing here requires
    the runtime to be modified to produce it.
    """

    sandbox_id: str
    """SPIFFE URI or DID identifying this sandbox instance. Becomes ``subject``."""

    image_digest: str
    """Digest of the runtime image the sandbox was launched from. Becomes
    ``build_provenance.digest``."""

    policy_bundle_bytes: bytes
    """The effective policy bundle, as bytes. Its SHA-256 becomes ``policy.bundle_hash``,
    so editing the policy changes the record. Where a runtime composes policy from several
    files, concatenate them in a defined order and keep that order stable: the hash is only
    worth something if both sides derive it the same way."""

    decisions: list[dict[str, Any]]
    """The runtime's decision log for the session, as plain dicts. The RFC 8785 canonical
    form is hashed into ``tool_transcript.hash``."""

    attestation: SandboxAttestation | None = None
    """Platform evidence, when the host produced any. ``None`` yields a Level 0 record."""

    call_count: int | None = None
    """Override for ``tool_transcript.call_count``. Defaults to ``len(decisions)``."""

    iat: int = field(default_factory=lambda: int(time.time()))
    """Issuance timestamp. Defaults to now."""

    def __post_init__(self) -> None:
        if not _SUBJECT_RE.match(self.sandbox_id):
            raise ValueError(
                f"sandbox_id {self.sandbox_id!r} must be a SPIFFE URI "
                "('spiffe://<trust-domain>/<path>') or a DID ('did:<method>:<id>'). "
                "It becomes the record subject, which is what a verifier keys on."
            )
        if not _DIGEST_RE.match(self.image_digest):
            raise ValueError(
                f"image_digest {self.image_digest!r} must be a sha256: or sha384: digest."
            )


class TraceSandboxAdapter:
    """Build Trust Records from a sandboxed agent runtime's session output.

    Configure once per deployment with the parts that do not change between sessions,
    then call :meth:`build_trust_record` per session::

        adapter = TraceSandboxAdapter(
            model_provider="anthropic",
            model_id="claude-sonnet-4-6",
            data_class="confidential",
        )
        record = adapter.build_trust_record(session)
        signed = sign_record(record, key)

    The returned dict is unsigned and carries a placeholder ``cnf.jwk``;
    :func:`~agentrust_trace.sign.sign_record` populates both. Pass the result to
    ``TrustRecord.model_validate()`` for structural validation.
    """

    def __init__(
        self,
        *,
        model_provider: str,
        model_id: str,
        model_version: str | None = None,
        data_class: str = "confidential",
        enforcement_mode: Literal["enforce", "advisory", "silent"] = "enforce",
        policy_version: str | None = None,
        policy_uri: str | None = None,
        build_provenance_slsa_level: int = 0,
        build_provenance_builder: str | None = None,
        build_provenance_uri: str | None = None,
        appraisal_verifier: str = "https://agentrust-io.com/verify",
        appraisal_status: Literal["affirming", "warning", "contraindicated", "none"] = "none",
        appraisal_policy_ref: str | None = None,
        transparency: str | None = None,
    ) -> None:
        """
        Args:
            appraisal_status: Defaults to ``"none"``. A record is not appraised by being
                built, and stamping ``affirming`` on an unappraised record puts a verdict
                in the field a consumer reads to find out whether anybody checked. Set
                this only when an appraisal actually happened.
            transparency: SCITT receipt URI. ``None`` means unanchored, which is correct
                below Level 2 and leaves the key out of the record.
            build_provenance_slsa_level: Defaults to 0, meaning no provenance claim. Raise
                it only when a builder genuinely produced the attested level.
        """
        self._model = ModelInfo(
            provider=model_provider, model_id=model_id, version=model_version
        )
        self._data_class = data_class
        self._enforcement_mode = enforcement_mode
        self._policy_version = policy_version
        self._policy_uri = policy_uri
        self._slsa_level = build_provenance_slsa_level
        self._builder = build_provenance_builder
        self._provenance_uri = build_provenance_uri
        self._appraisal_verifier = appraisal_verifier
        self._appraisal_status = appraisal_status
        self._appraisal_policy_ref = appraisal_policy_ref
        self._transparency = transparency

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_trust_record(self, session: SandboxSessionResult) -> dict[str, Any]:
        """Return an unsigned Trust Record for *session*.

        Level 0 when ``session.attestation`` is ``None``, Level 1 when it is supplied.
        """
        bundle_hash = self.bundle_hash(session.policy_bundle_bytes)
        runtime = self._runtime(session, bundle_hash)

        record: dict[str, Any] = {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": session.iat,
            "subject": session.sandbox_id,
            "model": self._model.model_dump(exclude_none=True),
            "runtime": runtime.model_dump(exclude_none=True),
            "policy": PolicyInfo(
                bundle_hash=bundle_hash,
                enforcement_mode=self._enforcement_mode,
                version=self._policy_version,
                policy_uri=self._policy_uri,
            ).model_dump(exclude_none=True),
            "data_class": self._data_class,
            "tool_transcript": ToolTranscript(
                hash=self.transcript_hash(session.decisions),
                call_count=(
                    session.call_count
                    if session.call_count is not None
                    else len(session.decisions)
                ),
            ).model_dump(exclude_none=True),
            "build_provenance": BuildProvenance(
                slsa_level=self._slsa_level,
                digest=session.image_digest,
                builder=self._builder,
                provenance_uri=self._provenance_uri,
            ).model_dump(exclude_none=True),
            "appraisal": Appraisal(
                status=self._appraisal_status,
                verifier=self._appraisal_verifier,
                policy_ref=self._appraisal_policy_ref,
                timestamp=session.iat,
            ).model_dump(exclude_none=True),
            # Placeholder until sign_record() writes the real confirmation key.
            "cnf": {
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
            },
        }
        if self._transparency is not None:
            record["transparency"] = self._transparency
        return record

    # ------------------------------------------------------------------
    # Hash helpers, public so a non-Python runtime can reproduce them
    # ------------------------------------------------------------------

    @staticmethod
    def bundle_hash(policy_bundle_bytes: bytes) -> str:
        """SHA-256 of the policy bundle bytes, exactly as supplied."""
        return "sha256:" + hashlib.sha256(policy_bundle_bytes).hexdigest()

    @staticmethod
    def transcript_hash(decisions: list[dict[str, Any]]) -> str:
        """SHA-256 over the RFC 8785 canonical form of the decision log.

        JCS, not ``json.dumps(sort_keys=True)``. The two agree on ASCII input and diverge
        on non-ASCII strings and on number formatting, and a decision log carries
        user-controlled strings. Using the same canonicalisation as the signature
        pre-image (see :func:`~agentrust_trace.sign.sign_record`) keeps a record
        reproducible by an implementation in another language.
        """
        return "sha256:" + hashlib.sha256(rfc8785.dumps(decisions)).hexdigest()

    @staticmethod
    def software_measurement(image_digest: str, bundle_hash: str) -> str:
        """The measurement for an unattested sandbox.

        ``sha256(image_digest + "\\n" + bundle_hash)`` over UTF-8, both operands in their
        ``sha256:``-prefixed form. Deliberately simple so another implementation can
        reproduce it without a JSON library.

        This binds the record to the composition that was observed. It is not hardware
        evidence and does not pretend to be: the record carries
        ``platform: "software-only"``, which the model documents as never to be mistaken
        for hardware-backed evidence.
        """
        return (
            "sha256:"
            + hashlib.sha256(f"{image_digest}\n{bundle_hash}".encode()).hexdigest()
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _runtime(self, session: SandboxSessionResult, bundle_hash: str) -> RuntimeInfo:
        att = session.attestation
        if att is None:
            return RuntimeInfo(
                platform="software-only",
                measurement=self.software_measurement(session.image_digest, bundle_hash),
            )
        return RuntimeInfo(
            platform=att.platform,  # type: ignore[arg-type]
            measurement=att.measurement,
            rim_uri=att.rim_uri,
            firmware_version=att.firmware_version,
            nonce=att.nonce,
        )

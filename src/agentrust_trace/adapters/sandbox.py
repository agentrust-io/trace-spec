"""TraceSandboxAdapter: maps a sandboxed agent runtime's session output to a Trust Record.

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

**It rejects the ways a caller can misname unattested evidence; it does not appraise the
evidence itself.** ``platform`` is only ever set from a supplied attestation, an
attestation may not name ``software-only``, the platform is checked against the enum on
:class:`~agentrust_trace.models.RuntimeInfo` rather than a copy of it, and
``measurement`` must be a ``sha256:``/``sha384:`` digest. That is shape validation, not
cryptographic verification: nothing here checks a quote, a signature, or a nonce, so
constructing a :class:`SandboxAttestation` with an invented platform and an invented
digest is accepted and reaches the record unchanged. This is the same boundary
docs/trust-levels.md states for every Level 1 producer --
``agentrust_trace.sign.verify_record`` does not appraise hardware quotes either -- and it
applies here for the same reason: appraising the evidence requires the platform's own
verification path (a TDX/SEV-SNP quote check against the vendor's key, a TPM quote check
against a known PCR policy, and so on), which is outside what a record-shaped library can
do generically. Pass a :class:`SandboxAttestation` only after your own attestation
verifier has checked genuine evidence from the named platform; passing one built from
data your process invented produces a Level 1-shaped record with no Level 1 assurance
behind it.

**Independently verified evidence is necessary but not sufficient.** docs/trust-levels.md
is explicit that Level 1 needs "authenticated evidence binding the record-signing key to
the expected environment," and docs/verification.md puts the responsibility for that
binding on "the producing profile." This adapter is that producing profile for a sandbox
runtime, and it defines no binding: nothing here ties ``measurement`` (or ``nonce``) to
the specific key that ends up in the record's ``cnf.jwk`` -- the key :func:`sign_record`
is called with is chosen independently of, and after, whatever attestation was verified.
A caller who verifies a genuine quote and then signs with an unrelated key produces a
record that is no more bound to hardware than a fabricated one; :class:`SandboxAttestation`
and :func:`~agentrust_trace.sign.sign_record` cannot tell the two cases apart. If your
attestation flow supports a caller-supplied challenge (a TPM quote's qualifying data, an
SNP report's ``REPORT_DATA``, a TDX quote's ``REPORTDATA``), bind it yourself: request the
quote with that field set to a value derived from the signing key you are about to pass to
``sign_record`` (for example its RFC 7638 thumbprint), verify the quote's binding to that
value in your own verifier, and only then carry it through as :attr:`SandboxAttestation.nonce`
so a downstream verifier that knows your convention can check it too.
:func:`~agentrust_trace.sign.verify_record` does not check this binding either -- nothing
in this codebase does; it is on you and on whatever verifier you point at these records.

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

    This dataclass validates shape only (an accepted platform name, a digest-shaped
    measurement); it does not verify that the evidence is genuine. Construct one only
    from a measurement your own attestation verifier obtained from the named platform,
    not from a value your process computed or invented -- nothing downstream of this
    constructor can tell the difference.

    Verifying the evidence is genuine is still not the same as Level 1 assurance: TRACE
    also requires that evidence to bind the record-signing key to the attested
    environment (see the module docstring). This dataclass has no field that expresses
    that binding on its own -- ``nonce`` is carried through to the record verbatim, on
    trust, and is not checked against ``measurement``, against any key, or against
    anything else. If you bind your quote's challenge to your signing key yourself,
    ``nonce`` is where that value goes; if you do not, leaving it unset is more honest
    than filling it with a value that implies a binding nobody verified.
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
    """Opaque, carried into ``runtime.nonce`` unchanged. If your attestation verifier
    bound the quote's challenge to the key you will sign this record with, this is
    where that challenge goes; nothing here or downstream checks that binding, so an
    unrelated string is accepted just as readily. Omit it rather than fill it with a
    value that was never actually bound to anything."""

    def __post_init__(self) -> None:
        if not isinstance(self.platform, str):
            raise ValueError(
                f"SandboxAttestation.platform must be a string, got {type(self.platform).__name__}"
            )
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
        if not isinstance(self.measurement, str):
            raise ValueError(
                "SandboxAttestation.measurement must be a string, got "
                f"{type(self.measurement).__name__}"
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
        if not isinstance(self.sandbox_id, str):
            raise ValueError(f"sandbox_id must be a string, got {type(self.sandbox_id).__name__}")
        if not _SUBJECT_RE.match(self.sandbox_id):
            raise ValueError(
                f"sandbox_id {self.sandbox_id!r} must be a SPIFFE URI "
                "('spiffe://<trust-domain>/<path>') or a DID ('did:<method>:<id>'). "
                "It becomes the record subject, which is what a verifier keys on."
            )
        if not isinstance(self.image_digest, str):
            raise ValueError(
                f"image_digest must be a string, got {type(self.image_digest).__name__}"
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

        Level 0 when ``session.attestation`` is ``None``. Otherwise the record is
        Level 1-*shaped*: ``runtime.platform`` and ``runtime.measurement`` carry the
        supplied evidence verbatim, with no cryptographic check performed on it here.
        Actual Level 1 assurance requires that evidence to have been independently
        verified -- by your own attestation verifier, against the named platform --
         before you construct the :class:`SandboxAttestation`, *and* it requires that
        verification to bind the key :func:`~agentrust_trace.sign.sign_record` is
        called with to the attested environment. This method has no way to check
        either: the ``cnf`` it returns is a placeholder, and the real key arrives
        later, at ``sign_record``, decided independently of whatever attestation was
        passed here. See the module docstring and :class:`SandboxAttestation` for this
        boundary.
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

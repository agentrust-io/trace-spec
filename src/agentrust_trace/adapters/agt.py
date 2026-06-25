"""TraceAGTAdapter — maps AGT govern() session output to a TRACE Trust Record.

Replaces ~50 lines of manual field wiring (see docs/integration/agt.md) with a
single method call. Level 0 (software-only) only; for Level 2 deploy inside cMCP.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from agentrust_trace.models import (
    Appraisal,
    BuildProvenance,
    ModelInfo,
    PolicyInfo,
    RuntimeInfo,
    ToolTranscript,
)


@dataclass
class AGTSessionResult:
    """Minimal AGT session data needed to build a Level 0 TRACE Trust Record.

    Collect these fields from the governed function after ``close_session()``::

        session = AGTSessionResult(
            agent_did=govern_fn.agent_did,
            policy_bundle_bytes=Path("policy.cedar").read_bytes(),
            audit_entries=govern_fn.get_audit_entries(),
            merkle_chain_tip=govern_fn.chain_tip,
        )
    """

    agent_did: str
    """SPIFFE URI or DID of the governed agent (becomes ``subject`` in the record)."""

    policy_bundle_bytes: bytes
    """Raw Cedar policy bundle bytes. SHA-256 of these becomes ``policy.bundle_hash``."""

    audit_entries: list[dict[str, Any]]
    """Merkle audit entries from the AGT session as plain dicts.
    Their canonical JSON SHA-256 becomes ``tool_transcript.hash``.
    """

    merkle_chain_tip: str
    """Hex string of the Merkle chain tip hash (from ``AuditChain.tip``).
    SHA-256 of this value becomes ``runtime.measurement``.
    """

    call_count: int | None = None
    """Override for ``tool_transcript.call_count``. Defaults to ``len(audit_entries)``."""

    iat: int = field(default_factory=lambda: int(time.time()))
    """Issuance timestamp. Defaults to now."""


class TraceAGTAdapter:
    """Build Level 0 TRACE Trust Records from AGT govern() session output.

    Instantiate once per deployment configuration, call ``build_trust_record()``
    once per AGT session::

        adapter = TraceAGTAdapter(
            model_provider="anthropic",
            model_id="claude-sonnet-4-6",
            model_version="20251001",
            build_provenance_digest="sha256:e5f6a7b8...",
            transparency="https://registry.agentrust.io/claim/...",
        )

        record = adapter.build_trust_record(session)

    The returned dict is ready for ``sign_record()`` and then ``json.dumps()`` or
    ``TrustRecord.model_validate()`` for structural validation.

    To upgrade to Level 2 (hardware-rooted), deploy your AGT agent inside cMCP.
    The cMCP runtime supersedes this Level 0 record with a TEE-bound Level 2 record
    that shares the same ``subject`` and ``tool_transcript.hash``.
    """

    def __init__(
        self,
        *,
        model_provider: str,
        model_id: str,
        model_version: str | None = None,
        data_class: str = "confidential",
        build_provenance_slsa_level: int = 0,
        build_provenance_digest: str,
        build_provenance_builder: str | None = None,
        build_provenance_uri: str | None = None,
        transparency: str,
        appraisal_verifier: str = "https://agentrust.io/verify",
        appraisal_policy_ref: str | None = None,
        enforcement_mode: str = "enforce",
    ) -> None:
        self._model = ModelInfo(
            provider=model_provider,
            model_id=model_id,
            version=model_version,
        )
        self._data_class = data_class
        self._build_provenance = BuildProvenance(
            slsa_level=build_provenance_slsa_level,
            digest=build_provenance_digest,
            builder=build_provenance_builder,
            provenance_uri=build_provenance_uri,
        )
        self._transparency = transparency
        self._appraisal_verifier = appraisal_verifier
        self._appraisal_policy_ref = appraisal_policy_ref
        self._enforcement_mode = enforcement_mode

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_trust_record(self, session: AGTSessionResult) -> dict[str, Any]:
        """Return an unsigned TRACE Trust Record dict for the given AGT session.

        Pass the result to ``sign_record(record, key)`` to add a signature, then
        to ``TrustRecord.model_validate(record)`` for structural validation.

        Args:
            session: AGT session data collected after ``govern_fn.close_session()``.

        Returns:
            A plain JSON-serialisable dict conforming to the TRACE v0.1 schema.
            The ``cnf.jwk`` placeholder carries no key material until ``sign_record()``
            populates it from the signing key.
        """
        call_count = (
            session.call_count
            if session.call_count is not None
            else len(session.audit_entries)
        )

        record: dict[str, Any] = {
            "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
            "iat": session.iat,
            "subject": session.agent_did,
            "model": self._model.model_dump(exclude_none=True),
            "runtime": RuntimeInfo(
                platform="software-only",
                measurement=self._measurement(session.merkle_chain_tip),
            ).model_dump(exclude_none=True),
            "policy": PolicyInfo(
                bundle_hash=self._bundle_hash(session.policy_bundle_bytes),
                enforcement_mode=self._enforcement_mode,  # type: ignore[arg-type]
            ).model_dump(exclude_none=True),
            "data_class": self._data_class,
            "tool_transcript": ToolTranscript(
                hash=self._transcript_hash(session.audit_entries),
                call_count=call_count,
            ).model_dump(exclude_none=True),
            "build_provenance": self._build_provenance.model_dump(exclude_none=True),
            "appraisal": Appraisal(
                status="affirming",
                verifier=self._appraisal_verifier,
                policy_ref=self._appraisal_policy_ref,
                timestamp=session.iat,
            ).model_dump(exclude_none=True),
            "transparency": self._transparency,
            # cnf is populated by sign_record(); placeholder keeps schema valid
            "cnf": {
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
            },
        }
        return record

    # ------------------------------------------------------------------
    # Hash helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bundle_hash(policy_bundle_bytes: bytes) -> str:
        return "sha256:" + hashlib.sha256(policy_bundle_bytes).hexdigest()

    @staticmethod
    def _transcript_hash(audit_entries: list[dict[str, Any]]) -> str:
        canonical = json.dumps(
            audit_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _measurement(merkle_chain_tip: str) -> str:
        return "sha256:" + hashlib.sha256(merkle_chain_tip.encode()).hexdigest()

"""Experimental cMCP adapter with durable challenge consumption and receipts.

Operator injects a fully verified context; network clients supply no trust keys.
Replay state lives behind ``GateStore``. The default SQLite store coordinates
workers on one host; ``RemoteGateStore`` shares one linearizable store across
replicas on several hosts (see ``prototype.gate_store``).
"""

from __future__ import annotations

import base64
import math
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rfc8785

from . import verifier_token as v
from .gate_store import GateStore, SQLiteGateStore


@dataclass(frozen=True)
class CallAdmission:
    token_bytes: bytes
    action_bytes: bytes
    generation: int
    session_id: str
    call_id: str


class CMCPTraceGate:
    """Single configured subject/instance; authenticated holder binds every call."""

    RECEIPT_APPEND_ATTEMPTS = 64

    def __init__(
        self,
        context: v.VerificationContext,
        *,
        database: str | Path | None = None,
        store: GateStore | None = None,
        gateway_key: Ed25519PrivateKey,
        gateway_issuer: str,
        gateway_policy_digest: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Exactly one of ``database`` (default SQLite store) or ``store``."""
        if (database is None) == (store is None):
            raise v.ProfileError("gate_store_configuration_invalid")
        self.context = context
        self._database = None if database is None else str(database)
        self._key = gateway_key
        self._issuer = gateway_issuer
        if (
            not isinstance(gateway_policy_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", gateway_policy_digest) is None
        ):
            raise v.ProfileError("gateway_policy_configuration_invalid")
        self._gateway_policy_digest = gateway_policy_digest
        self._clock = clock
        self._lock = RLock()
        self._store: GateStore = store if store is not None else SQLiteGateStore(database or "")

    def now(self) -> int:
        value = self._clock()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
            or value > 9007199254740991
        ):
            raise v.ProfileError("clock_unavailable")
        return int(value)

    @staticmethod
    def _encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @staticmethod
    def _decode(value: object) -> bytes:
        if not isinstance(value, str) or len(value) > 90000:
            raise v.ProfileError("credential_shape")
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        except ValueError as exc:
            raise v.ProfileError("credential_encoding") from exc
        if CMCPTraceGate._encode(raw) != value:
            raise v.ProfileError("credential_encoding")
        return raw

    def challenge(
        self, token_bytes: bytes, *, session_id: str, action: dict[str, Any]
    ) -> dict[str, Any]:
        now = self.now()
        token = v.verify_token(token_bytes, self.context, now)
        nonce = secrets.token_urlsafe(32)
        action_hash = v.canonical_digest(action)
        expiry = min(now + 30, token.exp)
        self._store.mint_challenge(
            issuer=token.iss,
            token_id=token.jti,
            token_digest=v.digest(token_bytes),
            nonce=nonce,
            session_id=session_id,
            action_digest=action_hash,
            issued=now,
            expires=expiry,
        )
        return {
            "nonce": nonce,
            "session_id": session_id,
            "action_digest": action_hash,
            "issued_at": now,
            "expires_at": expiry,
            "token_digest": v.digest(token_bytes),
            "token_id": token.jti,
            "audience": self.context.audience,
        }

    def _prove(
        self, raw: bytes, credentials: object, *, session_id: str, action: dict[str, Any]
    ) -> v.Token:
        now = self.now()
        token = v.verify_token(raw, self.context, now)
        if not isinstance(credentials, dict) or set(credentials) != {"nonce", "proof"}:
            raise v.ProfileError("holder_credentials_required")
        nonce = credentials["nonce"]
        if not isinstance(nonce, str) or len(nonce) != 43:
            raise v.ProfileError("nonce_shape")
        proof = self._decode(credentials["proof"])
        record = self._store.consume_challenge(nonce)
        if record is None:
            raise v.ProfileError("challenge_missing_or_consumed")
        row = (
            record.token_digest,
            record.session_id,
            record.action_digest,
            record.issued,
            record.expires,
        )
        # Consumption commits before proof evaluation: invalid guesses burn a nonce.
        if row[:3] != (v.digest(raw), session_id, v.canonical_digest(action)):
            raise v.ProfileError("challenge_action_or_session")
        v.verify_proof(
            proof,
            raw,
            token,
            nonce=nonce,
            audience=self.context.audience,
            session_id=session_id,
            action_digest=row[2],
            challenge_issued_at=row[3],
            challenge_expires_at=row[4],
            now=now,
        )
        if token.composite_appraisal.status not in ("affirming", "warning"):
            raise v.ProfileError("appraisal_not_acceptable")
        if (
            token.composite_appraisal.status == "warning"
            and not self.context.requirements.allow_warnings
        ):
            raise v.ProfileError("warning_not_acceptable")
        return token

    def admit(self, token_bytes: bytes, credentials: object, *, session_id: str) -> dict[str, Any]:
        with self._lock:
            action = {"domain": "cmcp:trace-admission:experimental-v1", "session_id": session_id}
            token = self._prove(token_bytes, credentials, session_id=session_id, action=action)
            generation = self._store.bump_admission(session_id, bytes(token_bytes))
            return {
                "token_digest": v.digest(token_bytes),
                "expires_at": token.exp,
                "generation": generation,
            }

    def begin(
        self,
        credentials: object,
        *,
        action: dict[str, Any],
        session_id: str,
        call_id: str,
        policy_digest: str,
    ) -> tuple[CallAdmission, dict[str, Any]]:
        with self._lock:
            admitted = self._store.admission(session_id)
            reused = self._store.receipted(session_id, call_id)
            if admitted is None:
                raise v.ProfileError("trace_required")
            raw, generation = admitted
            token = self._prove(raw, credentials, session_id=session_id, action=action)
            if reused:
                raise v.ProfileError("call_id_reused")
            if policy_digest != self._gateway_policy_digest:
                raise v.ProfileError("gateway_policy_changed")
            if not self._store.reserve_call(session_id, call_id, v.canonical_digest(action)):
                raise v.ProfileError("call_id_reused")
            handle = CallAdmission(raw, rfc8785.dumps(action), generation, session_id, call_id)
            return handle, {
                "token_digest": v.digest(raw),
                "token_id": token.jti,
                "issuer": token.iss,
                "subject": token.sub,
                "expires_at": token.exp,
                "manifest_digest": token.manifest.digest,
                "appraisal_policy_digest": token.appraisal_policy.digest,
                "composite_status": token.composite_appraisal.status,
                "component_status": {c.component_id: c.status for c in token.components},
            }

    def recheck(self, handle: CallAdmission, *, action: dict[str, Any], policy_digest: str) -> None:
        with self._lock:
            current = self._store.admission(handle.session_id)
            if current != (handle.token_bytes, handle.generation):
                raise v.ProfileError("trace_generation_changed")
            if rfc8785.dumps(action) != handle.action_bytes:
                raise v.ProfileError("accepted_action_changed")
            if policy_digest != self._gateway_policy_digest:
                raise v.ProfileError("gateway_policy_changed")
            v.verify_token(handle.token_bytes, self.context, self.now())

    def receipt(self, handle: CallAdmission, *, allowed: bool, reason: str) -> None:
        """Persist signed authorization before execution; receipt is not an outcome.

        Compare-and-append: sign against the observed chain head and retry if
        another worker or replica appended first, so the chain never forks.
        An allow never rides on another receipt already recorded for this call
        (for example a concurrent replay's refusal): that fails closed.
        """
        with self._lock:
            token = (
                v.read_payload(v.unpack(handle.token_bytes, v.PROFILE)[1], v.Token)
                if handle.token_bytes
                else None
            )
            if token is None and allowed:
                raise v.ProfileError("trace_required")
            for _ in range(self.RECEIPT_APPEND_ATTEMPTS):
                existing, previous = self._store.receipt_head(handle.session_id, handle.call_id)
                if existing is not None:
                    if allowed and not self._allows(existing, handle):
                        raise v.ProfileError("call_receipt_conflict")
                    return
                payload = v.Receipt(
                    profile=v.RECEIPT_PROFILE,
                    issuer=self._issuer,
                    issued_at=self.now(),
                    session_id=handle.session_id,
                    call_id=handle.call_id,
                    trace_digest=v.digest(handle.token_bytes),
                    trace_jti=token.jti if token else "absent",
                    action_digest=v.digest(handle.action_bytes),
                    policy_digest=self._gateway_policy_digest,
                    decision="allow" if allowed else "deny",
                    reason=reason,
                    previous_receipt_hash=previous,
                )
                envelope = v.sign_payload(payload, self._key)
                outcome = self._store.append_receipt(
                    handle.session_id, handle.call_id, envelope, v.digest(envelope), previous
                )
                if outcome == "appended":
                    return
            raise v.ProfileError("receipt_chain_contention")

    @staticmethod
    def _allows(envelope: bytes, handle: CallAdmission) -> bool:
        recorded = v.read_payload(v.unpack(envelope, v.RECEIPT_PROFILE)[1], v.Receipt)
        return bool(
            recorded.decision == "allow"
            and recorded.trace_digest == v.digest(handle.token_bytes)
            and recorded.action_digest == v.digest(handle.action_bytes)
        )

    def refusal(self, *, action: dict[str, Any], session_id: str, call_id: str) -> None:
        with self._lock:
            admitted = self._store.admission(session_id)
            raw, generation = admitted or (b"", 0)
            handle = CallAdmission(raw, rfc8785.dumps(action), generation, session_id, call_id)
            self.receipt(handle, allowed=False, reason="trace_refused")

    def receipts(self) -> list[bytes]:
        return self._store.receipts()

"""Replay-state stores for the experimental cMCP TRACE gate.

The gate keeps five kinds of state: one-use holder-proof challenges, issuer and
token-ID collision records, session admission generations, reserved call IDs and
the signed receipt chain. ``GateStore`` names exactly the operations the gate
performs on that state and the atomicity each one needs.

``SQLiteGateStore`` is the default and coordinates workers that share one SQLite
file on one host. ``RemoteGateStore`` talks to ``GateStoreServer``, one process
that owns the SQLite file and applies every operation atomically, so gateway
replicas on different hosts share one linearizable replay state without sharing a
filesystem path. The server is a stdlib prototype: it has no replication of its
own, so it is a single point of failure, and every replica fails closed while it
is unreachable.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import socket
import socketserver
import sqlite3
import struct
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import astuple, dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from . import verifier_token as v

AppendOutcome = Literal["appended", "duplicate", "stale"]
CHALLENGE_CAPACITY = 4096


class GateStoreUnavailable(ConnectionError):
    """Replay state could not be read or written. Callers must fail closed.

    Deliberately not a ``ValueError``: cMCP turns a ``ValueError`` from the gate
    into a refusal receipt, which would need the same unreachable store.
    """


@dataclass(frozen=True)
class ChallengeRecord:
    token_digest: str
    session_id: str
    action_digest: str
    issued: int
    expires: int


class GateStore(Protocol):
    """Operations the gate needs. Each method is one linearizable operation.

    "Atomic" means the method's reads and writes take effect as one step with
    respect to every other call on the same store, from any process or host.
    Implementations raise ``GateStoreUnavailable`` when the outcome is unknown
    and never retry a non-idempotent write on their own.
    """

    def mint_challenge(
        self,
        *,
        issuer: str,
        token_id: str,
        token_digest: str,
        nonce: str,
        session_id: str,
        action_digest: str,
        issued: int,
        expires: int,
    ) -> None:
        """Atomic. Refuse ``token_id_collision`` when (issuer, token_id) is
        recorded with a different digest, else record it; purge challenges with
        ``expires <= issued``; refuse ``challenge_capacity`` at the cap; insert
        the unconsumed challenge. A refusal leaves no partial write."""

    def consume_challenge(self, nonce: str) -> ChallengeRecord | None:
        """Atomic compare-and-set. Return the record and mark it consumed only
        if it exists and is unconsumed; otherwise return None. Among concurrent
        callers for one nonce, at most one receives the record."""

    def bump_admission(self, session_id: str, token: bytes) -> int:
        """Atomic read-increment-write of the session generation, storing the
        admitted token bytes. Returns the new generation (first is 1)."""

    def admission(self, session_id: str) -> tuple[bytes, int] | None:
        """Linearizable read of (token bytes, generation), or None."""

    def receipted(self, session_id: str, call_id: str) -> bool:
        """Linearizable read: a receipt exists for (session_id, call_id)."""

    def reserve_call(self, session_id: str, call_id: str, action_digest: str) -> bool:
        """Atomic insert-if-absent. True only for the first reservation."""

    def receipt_head(self, session_id: str, call_id: str) -> tuple[bytes | None, str | None]:
        """Read (this call's receipt envelope or None, digest of the chain head)."""

    def append_receipt(
        self, session_id: str, call_id: str, envelope: bytes, digest: str, previous: str | None
    ) -> AppendOutcome:
        """Atomic compare-and-append. ``duplicate`` if the call already has a
        receipt; ``stale`` if the head is no longer ``previous``; otherwise
        append and return ``appended``. The chain therefore never forks."""

    def receipts(self) -> list[bytes]:
        """All receipt envelopes in chain order."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS challenges (
    nonce TEXT PRIMARY KEY, token_digest TEXT NOT NULL,
    session_id TEXT NOT NULL, action_digest TEXT NOT NULL,
    issued INTEGER NOT NULL, expires INTEGER NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS receipts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
    call_id TEXT NOT NULL, envelope BLOB NOT NULL, digest TEXT NOT NULL,
    previous_digest TEXT, UNIQUE(session_id,call_id));
CREATE TABLE IF NOT EXISTS admissions (
    session_id TEXT PRIMARY KEY, token BLOB NOT NULL, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS calls (
    session_id TEXT NOT NULL, call_id TEXT NOT NULL, action_digest TEXT NOT NULL,
    PRIMARY KEY(session_id,call_id));
CREATE TABLE IF NOT EXISTS token_ids (
    issuer TEXT NOT NULL, token_id TEXT NOT NULL, digest TEXT NOT NULL,
    PRIMARY KEY(issuer,token_id));
"""


class SQLiteGateStore:
    """Default store: one SQLite file, ``BEGIN IMMEDIATE`` per atomic method.

    Correct for several workers on one host sharing the file. It is not a
    multi-host database: network filesystems do not give SQLite reliable locks.
    """

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        with self._connect() as db:
            db.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def mint_challenge(
        self,
        *,
        issuer: str,
        token_id: str,
        token_digest: str,
        nonce: str,
        session_id: str,
        action_digest: str,
        issued: int,
        expires: int,
    ) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT digest FROM token_ids WHERE issuer=? AND token_id=?", (issuer, token_id)
            ).fetchone()
            if prior is not None and prior[0] != token_digest:
                raise v.ProfileError("token_id_collision")
            db.execute(
                "INSERT OR IGNORE INTO token_ids VALUES(?,?,?)", (issuer, token_id, token_digest)
            )
            db.execute("DELETE FROM challenges WHERE expires <= ?", (issued,))
            if db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] >= CHALLENGE_CAPACITY:
                raise v.ProfileError("challenge_capacity")
            db.execute(
                "INSERT INTO challenges VALUES(?,?,?,?,?,?,0)",
                (nonce, token_digest, session_id, action_digest, issued, expires),
            )

    def consume_challenge(self, nonce: str) -> ChallengeRecord | None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT token_digest,session_id,action_digest,issued,expires,consumed "
                "FROM challenges WHERE nonce=?",
                (nonce,),
            ).fetchone()
            if row is None or row[5]:
                return None
            db.execute("UPDATE challenges SET consumed=1 WHERE nonce=?", (nonce,))
        return ChallengeRecord(*row[:5])

    def bump_admission(self, session_id: str, token: bytes) -> int:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                "SELECT generation FROM admissions WHERE session_id=?", (session_id,)
            ).fetchone()
            generation = int(current[0] if current else 0) + 1
            db.execute(
                "INSERT INTO admissions VALUES(?,?,?) ON CONFLICT(session_id) "
                "DO UPDATE SET token=excluded.token,generation=excluded.generation",
                (session_id, bytes(token), generation),
            )
        return generation

    def admission(self, session_id: str) -> tuple[bytes, int] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT token,generation FROM admissions WHERE session_id=?", (session_id,)
            ).fetchone()
        return (bytes(row[0]), int(row[1])) if row else None

    def receipted(self, session_id: str, call_id: str) -> bool:
        with self._connect() as db:
            return (
                db.execute(
                    "SELECT 1 FROM receipts WHERE session_id=? AND call_id=?", (session_id, call_id)
                ).fetchone()
                is not None
            )

    def reserve_call(self, session_id: str, call_id: str, action_digest: str) -> bool:
        try:
            with self._connect() as db:
                db.execute("INSERT INTO calls VALUES(?,?,?)", (session_id, call_id, action_digest))
        except sqlite3.IntegrityError:
            return False
        return True

    def receipt_head(self, session_id: str, call_id: str) -> tuple[bytes | None, str | None]:
        with self._connect() as db:
            db.execute("BEGIN")
            existing = db.execute(
                "SELECT envelope FROM receipts WHERE session_id=? AND call_id=?",
                (session_id, call_id),
            ).fetchone()
            head = db.execute("SELECT digest FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
        return (bytes(existing[0]) if existing else None), (head[0] if head else None)

    def append_receipt(
        self, session_id: str, call_id: str, envelope: bytes, digest: str, previous: str | None
    ) -> AppendOutcome:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM receipts WHERE session_id=? AND call_id=?", (session_id, call_id)
            ).fetchone():
                return "duplicate"
            head = db.execute("SELECT digest FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
            if (head[0] if head else None) != previous:
                return "stale"
            db.execute(
                "INSERT INTO receipts(session_id,call_id,envelope,digest,previous_digest) "
                "VALUES(?,?,?,?,?)",
                (session_id, call_id, bytes(envelope), digest, previous),
            )
        return "appended"

    def receipts(self) -> list[bytes]:
        with self._connect() as db:
            rows = db.execute("SELECT envelope FROM receipts ORDER BY seq").fetchall()
        return [bytes(row[0]) for row in rows]


# Wire protocol: 4-byte big-endian length, then a JSON object. Bytes travel as
# unpadded base64url. Requests carry the pre-shared secret; responses carry
# {"ok": result} or {"error": code}. One request per connection.

_MAX_REQUEST = 1 << 20
_MAX_RESPONSE = 1 << 28
_FORWARDED_ERRORS = frozenset({"token_id_collision", "challenge_capacity"})


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: object) -> bytes:
    if not isinstance(text, str):
        raise TypeError("bytes field")
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


def _send(sock: socket.socket, message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":")).encode()
    sock.sendall(struct.pack(">I", len(body)) + body)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(min(65536, size - len(chunks)))
        if not chunk:
            raise ConnectionError("store connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv(sock: socket.socket, limit: int) -> Any:
    (size,) = struct.unpack(">I", _recv_exact(sock, 4))
    if size > limit:
        raise ConnectionError("store frame too large")
    return json.loads(_recv_exact(sock, size))


def _str(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("string field")
    return value


def _int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("integer field")
    return value


def _dispatch(store: SQLiteGateStore, op: str, a: dict[str, Any]) -> Any:
    if op == "mint_challenge":
        store.mint_challenge(
            issuer=_str(a["issuer"]),
            token_id=_str(a["token_id"]),
            token_digest=_str(a["token_digest"]),
            nonce=_str(a["nonce"]),
            session_id=_str(a["session_id"]),
            action_digest=_str(a["action_digest"]),
            issued=_int(a["issued"]),
            expires=_int(a["expires"]),
        )
        return None
    if op == "consume_challenge":
        record = store.consume_challenge(_str(a["nonce"]))
        return None if record is None else list(astuple(record))
    if op == "bump_admission":
        return store.bump_admission(_str(a["session_id"]), _unb64(a["token"]))
    if op == "admission":
        found = store.admission(_str(a["session_id"]))
        return None if found is None else [_b64(found[0]), found[1]]
    if op == "receipted":
        return store.receipted(_str(a["session_id"]), _str(a["call_id"]))
    if op == "reserve_call":
        return store.reserve_call(
            _str(a["session_id"]), _str(a["call_id"]), _str(a["action_digest"])
        )
    if op == "receipt_head":
        existing, head = store.receipt_head(_str(a["session_id"]), _str(a["call_id"]))
        return [None if existing is None else _b64(existing), head]
    if op == "append_receipt":
        previous = a["previous"]
        return store.append_receipt(
            _str(a["session_id"]),
            _str(a["call_id"]),
            _unb64(a["envelope"]),
            _str(a["digest"]),
            None if previous is None else _str(previous),
        )
    if op == "receipts":
        return [_b64(raw) for raw in store.receipts()]
    raise KeyError(op)


class GateStoreServer(socketserver.ThreadingTCPServer):
    """One process owns the SQLite file; each request runs under one lock.

    The lock plus ``BEGIN IMMEDIATE`` makes every operation linearizable for all
    clients. The pre-shared secret is compared in constant time but travels in
    cleartext: a deployment must put this channel inside mutual TLS.
    """

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], database: str | Path, secret: bytes) -> None:
        if len(secret) < 16:
            raise ValueError("store secret must be at least 16 bytes")
        self.store = SQLiteGateStore(database)
        self.secret = secret
        self.op_lock = threading.Lock()
        super().__init__(address, _Handler)


class _Handler(socketserver.BaseRequestHandler):
    server: GateStoreServer

    def handle(self) -> None:
        sock: socket.socket = self.request
        sock.settimeout(10)
        try:
            request = _recv(sock, _MAX_REQUEST)
        except (OSError, ValueError, struct.error):
            return
        if not isinstance(request, dict) or not hmac.compare_digest(
            str(request.get("secret", "")).encode(), self.server.secret
        ):
            _send(sock, {"error": "unauthenticated"})
            return
        op, args = request.get("op"), request.get("args")
        if not isinstance(op, str) or not isinstance(args, dict):
            _send(sock, {"error": "malformed"})
            return
        try:
            with self.server.op_lock:
                result = _dispatch(self.server.store, op, args)
        except v.ProfileError as exc:
            code = str(exc)
            _send(sock, {"error": code if code in _FORWARDED_ERRORS else "store_internal"})
            return
        except (KeyError, TypeError, ValueError):
            _send(sock, {"error": "malformed"})
            return
        except sqlite3.Error:
            _send(sock, {"error": "store_internal"})
            return
        _send(sock, {"ok": result})


class RemoteGateStore:
    """Client for ``GateStoreServer``. Never retries: an unknown outcome raises
    ``GateStoreUnavailable`` so the gate fails closed (a lost consume burns the
    nonce; a lost append is resolved by the next ``receipt_head``)."""

    def __init__(self, host: str, port: int, secret: bytes, *, timeout: float = 5.0) -> None:
        self.address = (host, port)
        self._secret = secret.decode()
        self._timeout = timeout

    def _call(self, op: str, **args: Any) -> Any:
        try:
            with socket.create_connection(self.address, timeout=self._timeout) as sock:
                _send(sock, {"secret": self._secret, "op": op, "args": args})
                response = _recv(sock, _MAX_RESPONSE)
        except (OSError, ValueError, struct.error) as exc:
            raise GateStoreUnavailable(f"gate store {op} failed: {exc}") from exc
        if not isinstance(response, dict):
            raise GateStoreUnavailable(f"gate store {op} returned a malformed response")
        if "error" in response:
            if response["error"] in _FORWARDED_ERRORS:
                raise v.ProfileError(response["error"])
            raise GateStoreUnavailable(f"gate store {op} refused: {response['error']}")
        return response.get("ok")

    def mint_challenge(self, **fields: Any) -> None:
        self._call("mint_challenge", **fields)

    def consume_challenge(self, nonce: str) -> ChallengeRecord | None:
        row = self._call("consume_challenge", nonce=nonce)
        if row is None:
            return None
        try:
            return ChallengeRecord(
                _str(row[0]), _str(row[1]), _str(row[2]), _int(row[3]), _int(row[4])
            )
        except (IndexError, TypeError) as exc:
            raise GateStoreUnavailable("gate store returned a malformed challenge") from exc

    def bump_admission(self, session_id: str, token: bytes) -> int:
        return _int(self._call("bump_admission", session_id=session_id, token=_b64(token)))

    def admission(self, session_id: str) -> tuple[bytes, int] | None:
        found = self._call("admission", session_id=session_id)
        return None if found is None else (_unb64(found[0]), _int(found[1]))

    def receipted(self, session_id: str, call_id: str) -> bool:
        return self._call("receipted", session_id=session_id, call_id=call_id) is True

    def reserve_call(self, session_id: str, call_id: str, action_digest: str) -> bool:
        reserved = self._call(
            "reserve_call", session_id=session_id, call_id=call_id, action_digest=action_digest
        )
        return reserved is True

    def receipt_head(self, session_id: str, call_id: str) -> tuple[bytes | None, str | None]:
        existing, head = self._call("receipt_head", session_id=session_id, call_id=call_id)
        return (None if existing is None else _unb64(existing)), (
            None if head is None else _str(head)
        )

    def append_receipt(
        self, session_id: str, call_id: str, envelope: bytes, digest: str, previous: str | None
    ) -> AppendOutcome:
        outcome = self._call(
            "append_receipt",
            session_id=session_id,
            call_id=call_id,
            envelope=_b64(envelope),
            digest=digest,
            previous=previous,
        )
        if outcome not in ("appended", "duplicate", "stale"):
            raise GateStoreUnavailable("gate store returned a malformed append outcome")
        return outcome  # type: ignore[no-any-return]

    def receipts(self) -> list[bytes]:
        return [_unb64(raw) for raw in self._call("receipts")]


def main(argv: list[str] | None = None) -> None:
    """Serve one store. The secret comes from TRACE_GATE_STORE_SECRET, not argv.

    Prints the bound port on the first stdout line, then serves until killed.
    """
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    options = parser.parse_args(argv)
    secret = os.environ.get("TRACE_GATE_STORE_SECRET", "").encode()
    server = GateStoreServer((options.host, options.port), options.database, secret)
    print(server.server_address[1], flush=True)
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()

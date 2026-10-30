"""Regression and boundary tests for prototype.gate_store and prototype.cmcp_gate (#606)."""

from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prototype import gate_store
from prototype import verifier_token as v
from prototype.cmcp_gate import CallAdmission, CMCPTraceGate
from prototype.gate_store import GateStoreServer, GateStoreUnavailable, RemoteGateStore
from tests.test_verifier_token_profile import context, fixture, g, unb64

__all__ = ["fixture"]

POLICY = "sha256:" + "a" * 64
BINARY_SECRET = b"\x80\xff\x00\xfe\x91\xa2\xb3\xc4" * 4
GATEWAY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))


def _holder_proof(challenge: dict[str, Any], raw: bytes) -> dict[str, str]:
    payload = {
        "profile": v.PROOF_PROFILE,
        "nonce": challenge["nonce"],
        "token_digest": v.digest(raw),
        "token_id": challenge["token_id"],
        "audience": challenge["audience"],
        "session_id": challenge["session_id"],
        "action_digest": challenge["action_digest"],
        "issued_at": challenge["issued_at"],
        "expires_at": challenge["expires_at"],
    }
    return {
        "nonce": challenge["nonce"],
        "proof": CMCPTraceGate._encode(g.envelope(payload, g.HOLDER)),
    }


@contextmanager
def _running_server(database: Path, secret: bytes = BINARY_SECRET) -> Iterator[GateStoreServer]:
    server = GateStoreServer(("127.0.0.1", 0), database, secret)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def _raw_reply_server(payload: bytes) -> Iterator[int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5)
                try:
                    gate_store._recv(conn, 1 << 20)
                except Exception:
                    pass
                conn.sendall(struct.pack(">I", len(payload)) + payload)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        thread.join(timeout=5)


def test_remote_and_server_support_non_utf8_binary_secret(
    fixture: dict[str, Any], tmp_path: Path
) -> None:
    raw = unb64(fixture["envelope_b64"])
    with _running_server(tmp_path / "store.sqlite", BINARY_SECRET) as server:
        port = int(server.server_address[1])
        store = RemoteGateStore("127.0.0.1", port, BINARY_SECRET)
        gate = CMCPTraceGate(
            context(fixture),
            store=store,
            gateway_key=GATEWAY_KEY,
            gateway_issuer="spiffe://example.test/gateway",
            gateway_policy_digest=POLICY,
            clock=lambda: g.NOW,
        )
        admit_action = {"domain": "cmcp:trace-admission:experimental-v1", "session_id": "session-1"}
        ch = gate.challenge(raw, session_id="session-1", action=admit_action)
        admitted = gate.admit(raw, _holder_proof(ch, raw), session_id="session-1")
        assert admitted["generation"] == 1

        call_action = {"tool": "read", "arguments": {}}
        call_ch = gate.challenge(raw, session_id="session-1", action=call_action)
        handle, info = gate.begin(
            _holder_proof(call_ch, raw),
            action=call_action,
            session_id="session-1",
            call_id="call-1",
            policy_digest=POLICY,
        )
        assert info["token_id"] == fixture["token"]["jti"]
        gate.recheck(handle, action=call_action, policy_digest=POLICY)
        gate.receipt(handle, allowed=True, reason="cedar_allowed")
        gate.refusal(action=call_action, session_id="session-1", call_id="call-2")
        assert len(gate.receipts()) == 2

        wrong = RemoteGateStore("127.0.0.1", port, b"\xff" * 32)
        with pytest.raises(GateStoreUnavailable, match="unauthenticated"):
            wrong.receipts()


def test_cli_server_supports_binary_secret_via_b64_env(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), *filter(None, [env.get("PYTHONPATH", "")])])
    env["TRACE_GATE_STORE_SECRET_B64"] = gate_store._b64(BINARY_SECRET)
    proc = subprocess.Popen(
        [sys.executable, "-m", "prototype.gate_store", "--database", str(tmp_path / "cli.sqlite")],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().strip()
        assert line.isdigit(), proc.stderr.read() if proc.stderr else "server exited"
        store = RemoteGateStore("127.0.0.1", int(line), BINARY_SECRET)
        assert store.bump_admission("session-1", b"token-bytes") == 1
        assert store.admission("session-1") == (b"token-bytes", 1)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)


@pytest.mark.parametrize(
    "bad_secret",
    [b"", b"short", b"x" * 15, bytearray(b"a" * 16), None],
)
def test_remote_gate_store_rejects_short_or_non_bytes_secret(bad_secret: Any) -> None:
    with pytest.raises(ValueError, match="^store secret must be at least 16 bytes$"):
        RemoteGateStore("127.0.0.1", 9999, bad_secret)
    with pytest.raises(ValueError, match="^store secret must be at least 16 bytes$"):
        RemoteGateStore("127.0.0.1", 9999, "a" * 16)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_secret",
    ["a" * 16, bytearray(b"a" * 16), [1] * 16],
)
def test_gate_store_server_rejects_non_bytes_or_short_secret(
    bad_secret: Any, tmp_path: Path
) -> None:
    db_path = tmp_path / "unused.sqlite"
    server: GateStoreServer | None = None
    try:
        with pytest.raises(ValueError, match="^store secret must be at least 16 bytes$"):
            server = GateStoreServer(("127.0.0.1", 0), db_path, bad_secret)
    finally:
        if server is not None:
            server.server_close()
    assert not db_path.exists()
    with pytest.raises(ValueError, match="^store secret must be at least 16 bytes$"):
        GateStoreServer(("127.0.0.1", 0), db_path, b"x" * 15)


@pytest.mark.parametrize(
    "noncanonical",
    ["AAAA====", "AA==", "AAA=", "AB"],
)
def test_unb64_rejects_padded_and_noncanonical_base64url(noncanonical: str) -> None:
    assert gate_store._unb64("AAAA") == b"\x00\x00\x00"
    assert gate_store._unb64("AA") == b"\x00"
    with pytest.raises(ValueError):
        gate_store._unb64(noncanonical)


@pytest.mark.parametrize(
    "raw_frame",
    [
        pytest.param(b'{"ok":1,"ok":2}', id="duplicate-key"),
        pytest.param(b'{"ok":NaN}', id="nan"),
        pytest.param(b'{"ok":Infinity}', id="infinity"),
        pytest.param(b'\xef\xbb\xbf{"ok":1}', id="utf8-bom"),
        pytest.param(b"[" * 200_000 + b"]" * 200_000, id="deep-nesting"),
    ],
)
def test_recv_rejects_duplicate_keys_nonfinite_bom_and_deep_nesting(raw_frame: bytes) -> None:
    left, right = socket.socketpair()
    try:
        frame = struct.pack(">I", len(raw_frame)) + raw_frame
        sender = threading.Thread(target=left.sendall, args=(frame,), daemon=True)
        sender.start()
        with pytest.raises(ValueError):
            gate_store._recv(right, 1 << 20)
        sender.join(timeout=5)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize(
    ("raw_response", "invoke"),
    [
        (
            b"{}",
            lambda s: s.mint_challenge(
                issuer="iss",
                token_id="jti",
                token_digest="sha256:" + "0" * 64,
                nonce="n" * 43,
                session_id="s1",
                action_digest="sha256:" + "1" * 64,
                issued=1,
                expires=2,
            ),
        ),
        (b'{"ok":[],"extra":1}', lambda s: s.receipts()),
        (b'{"error":["unhashable"]}', lambda s: s.receipts()),
        (b'{"ok":[],"ok":[]}', lambda s: s.receipts()),
        (
            b'{"ok":"unexpected"}',
            lambda s: s.mint_challenge(
                issuer="iss",
                token_id="jti",
                token_digest="sha256:" + "0" * 64,
                nonce="n" * 43,
                session_id="s1",
                action_digest="sha256:" + "1" * 64,
                issued=1,
                expires=2,
            ),
        ),
        (b'{"ok":{"0":"a","1":"b","2":"c","3":1,"4":2}}', lambda s: s.consume_challenge("n" * 43)),
        (b'{"ok":["a","b","c",1,2,3]}', lambda s: s.consume_challenge("n" * 43)),
        (
            b'{"ok":["not-a-digest","s1","not-a-digest",1,2]}',
            lambda s: s.consume_challenge("n" * 43),
        ),
        (b'{"ok":"not-int"}', lambda s: s.bump_admission("s1", b"tok")),
        (b'{"ok":0}', lambda s: s.bump_admission("s1", b"tok")),
        (b'{"ok":true}', lambda s: s.bump_admission("s1", b"tok")),
        (b'{"ok":["===bad===",1]}', lambda s: s.admission("s1")),
        (b'{"ok":["AAAA====",1]}', lambda s: s.admission("s1")),
        (b'{"ok":["AAAA"]}', lambda s: s.admission("s1")),
        (b'{"ok":"not-a-list"}', lambda s: s.admission("s1")),
        (b'{"ok":["AAAA",0]}', lambda s: s.admission("s1")),
        (b'{"ok":"yes"}', lambda s: s.receipted("s1", "c1")),
        (b'{"ok":1}', lambda s: s.reserve_call("s1", "c1", "sha256:" + "0" * 64)),
        (b'{"ok":["===bad===",null]}', lambda s: s.receipt_head("s1", "c1")),
        (b'{"ok":[null,"garbage"]}', lambda s: s.receipt_head("s1", "c1")),
        (b'{"ok":[null]}', lambda s: s.receipt_head("s1", "c1")),
        (b'{"ok":null}', lambda s: s.receipt_head("s1", "c1")),
        (b'{"ok":[null,123]}', lambda s: s.receipt_head("s1", "c1")),
        (b'{"ok":["===bad==="]}', lambda s: s.receipts()),
        (b'{"ok":"AAAA"}', lambda s: s.receipts()),
        (b'{"ok":null}', lambda s: s.receipts()),
        (b'{"ok":[123]}', lambda s: s.receipts()),
    ],
)
def test_remote_gate_store_wraps_malformed_responses_in_gate_store_unavailable(
    raw_response: bytes, invoke: Any
) -> None:
    with _raw_reply_server(raw_response) as port:
        store = RemoteGateStore("127.0.0.1", port, b"valid-ascii-secret-0123456789")
        with pytest.raises(GateStoreUnavailable):
            invoke(store)


@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"context": None}, "gate_configuration_invalid"),
        ({"context": {}}, "gate_configuration_invalid"),
        ({"gateway_key": None}, "gate_configuration_invalid"),
        ({"gateway_key": g.ISSUER.public_key()}, "gate_configuration_invalid"),
        ({"gateway_issuer": ""}, "gate_configuration_invalid"),
        ({"gateway_issuer": "bad issuer"}, "gate_configuration_invalid"),
        ({"gateway_issuer": 123}, "gate_configuration_invalid"),
        ({"clock": None}, "gate_configuration_invalid"),
        ({"clock": 123}, "gate_configuration_invalid"),
        ({"database": ""}, "gate_store_configuration_invalid"),
        ({"database": 123}, "gate_store_configuration_invalid"),
        ({"database": None, "store": object()}, "gate_store_configuration_invalid"),
    ],
)
def test_cmcp_trace_gate_init_validates_configuration(
    fixture: dict[str, Any], tmp_path: Path, overrides: dict[str, Any], expected_code: str
) -> None:
    kwargs: dict[str, Any] = {
        "context": context(fixture),
        "database": tmp_path / "gate.sqlite",
        "gateway_key": GATEWAY_KEY,
        "gateway_issuer": "spiffe://example.test/gateway",
        "gateway_policy_digest": POLICY,
        "clock": lambda: g.NOW,
    }
    kwargs.update(overrides)
    with pytest.raises(v.ProfileError, match=f"^{expected_code}$"):
        CMCPTraceGate(**kwargs)


@pytest.mark.parametrize("bad_id", ["", "bad id", "-leading-dash", 123, None])
def test_cmcp_trace_gate_rejects_invalid_session_and_call_identifiers(
    fixture: dict[str, Any], tmp_path: Path, bad_id: Any
) -> None:
    raw = unb64(fixture["envelope_b64"])
    gate = CMCPTraceGate(
        context(fixture),
        database=tmp_path / "gate.sqlite",
        gateway_key=GATEWAY_KEY,
        gateway_issuer="spiffe://example.test/gateway",
        gateway_policy_digest=POLICY,
        clock=lambda: g.NOW,
    )
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.challenge(raw, session_id=bad_id, action={"tool": "read"})
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.admit(raw, {}, session_id=bad_id)
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.begin(
            {},
            action={"tool": "read"},
            session_id=bad_id,
            call_id="call-1",
            policy_digest=POLICY,
        )
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.begin(
            {},
            action={"tool": "read"},
            session_id="session-1",
            call_id=bad_id,
            policy_digest=POLICY,
        )
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.refusal(action={"tool": "read"}, session_id=bad_id, call_id="call-1")
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.refusal(action={"tool": "read"}, session_id="session-1", call_id=bad_id)


@pytest.mark.parametrize("bad_action", [["list"], "string", 123, None, {"nan": float("nan")}])
def test_cmcp_trace_gate_rejects_non_dict_or_non_jcs_action(
    fixture: dict[str, Any], tmp_path: Path, bad_action: Any
) -> None:
    raw = unb64(fixture["envelope_b64"])
    gate = CMCPTraceGate(
        context(fixture),
        database=tmp_path / "gate.sqlite",
        gateway_key=GATEWAY_KEY,
        gateway_issuer="spiffe://example.test/gateway",
        gateway_policy_digest=POLICY,
        clock=lambda: g.NOW,
    )
    handle = CallAdmission(raw, b"{}", 1, "session-1", "call-1")
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.challenge(raw, session_id="session-1", action=bad_action)
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.begin(
            {},
            action=bad_action,
            session_id="session-1",
            call_id="call-1",
            policy_digest=POLICY,
        )
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.recheck(handle, action=bad_action, policy_digest=POLICY)
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        gate.refusal(action=bad_action, session_id="session-1", call_id="call-1")


@pytest.mark.parametrize(
    "call",
    [
        lambda gate, handle: gate.recheck(None, action={}, policy_digest=POLICY),
        lambda gate, handle: gate.recheck(
            replace(handle, session_id="bad id"), action={}, policy_digest=POLICY
        ),
        lambda gate, handle: gate.recheck(
            replace(handle, call_id="bad call"), action={}, policy_digest=POLICY
        ),
        lambda gate, handle: gate.receipt(None, allowed=False, reason="denied"),
        lambda gate, handle: gate.receipt(handle, allowed=1, reason="denied"),
        lambda gate, handle: gate.receipt(handle, allowed=False, reason="bad reason"),
        lambda gate, handle: gate.receipt(
            replace(handle, session_id="bad id"), allowed=False, reason="denied"
        ),
        lambda gate, handle: gate.receipt(
            replace(handle, call_id="bad call"), allowed=False, reason="denied"
        ),
    ],
)
def test_cmcp_trace_gate_recheck_and_receipt_validate_handle_and_reason(
    fixture: dict[str, Any], tmp_path: Path, call: Any
) -> None:
    raw = unb64(fixture["envelope_b64"])
    gate = CMCPTraceGate(
        context(fixture),
        database=tmp_path / "gate.sqlite",
        gateway_key=GATEWAY_KEY,
        gateway_issuer="spiffe://example.test/gateway",
        gateway_policy_digest=POLICY,
        clock=lambda: g.NOW,
    )
    gate._store.bump_admission("session-1", raw)
    handle = CallAdmission(raw, b"{}", 1, "session-1", "call-1")
    with pytest.raises(v.ProfileError, match="^input_invalid$"):
        call(gate, handle)


@pytest.mark.parametrize("raw_frame", [b'{"ok":1e309}', b'{"ok":-1e309}'])
def test_recv_rejects_float_exponent_overflow(raw_frame: bytes) -> None:
    left, right = socket.socketpair()
    try:
        frame = struct.pack(">I", len(raw_frame)) + raw_frame
        sender = threading.Thread(target=left.sendall, args=(frame,), daemon=True)
        sender.start()
        with pytest.raises(ValueError, match="non-finite json float"):
            gate_store._recv(right, 1 << 20)
        sender.join(timeout=5)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize(
    "bad_val",
    [-1, 9_007_199_254_740_992, 1 << 64],
)
def test_int_and_server_reject_out_of_range_integers_without_crashing(
    bad_val: int, tmp_path: Path
) -> None:
    assert gate_store._int(0) == 0
    assert gate_store._int(9_007_199_254_740_991) == 9_007_199_254_740_991
    with pytest.raises(ValueError, match="out of range"):
        gate_store._int(bad_val)

    with _running_server(tmp_path / "int-bounds.sqlite", BINARY_SECRET) as server:
        port = int(server.server_address[1])
        store = RemoteGateStore("127.0.0.1", port, BINARY_SECRET)
        with pytest.raises(GateStoreUnavailable, match="malformed"):
            store.mint_challenge(
                issuer="iss",
                token_id="jti",
                token_digest="sha256:" + "0" * 64,
                nonce="n" * 43,
                session_id="s1",
                action_digest="sha256:" + "1" * 64,
                issued=bad_val,
                expires=bad_val + 10 if bad_val >= 0 else 10,
            )


def test_str_and_server_reject_empty_string_identifiers(tmp_path: Path) -> None:
    assert gate_store._str("ok") == "ok"
    with pytest.raises(TypeError, match="string field"):
        gate_store._str("")

    with _running_server(tmp_path / "empty-str.sqlite", BINARY_SECRET) as server:
        port = int(server.server_address[1])
        store = RemoteGateStore("127.0.0.1", port, BINARY_SECRET)
        with pytest.raises(GateStoreUnavailable, match="malformed"):
            store.admission("")


@pytest.mark.parametrize(
    "bad_timeout",
    [False, True, 0, -1.0, float("nan"), float("inf"), "5"],
)
def test_remote_gate_store_rejects_invalid_timeout(bad_timeout: Any) -> None:
    assert RemoteGateStore("127.0.0.1", 9999, BINARY_SECRET, timeout=2.5)._timeout == 2.5
    with pytest.raises(ValueError, match="^timeout must be a positive finite number$"):
        RemoteGateStore("127.0.0.1", 9999, BINARY_SECRET, timeout=bad_timeout)


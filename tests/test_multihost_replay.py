"""Multi-host replay protection for the experimental cMCP TRACE gate.

Two gateway replicas run in separate OS processes and share replay state only
through ``GateStoreServer`` over TCP (``RemoteGateStore``); neither replica opens
the store's SQLite file. The replica harness drives the gate in cMCP's order
(begin, recheck, signed receipt, recheck, transport) and counts transports. A
separate in-process test runs the real cMCP proxy against the remote store.

The causal tests swap the shared store for per-replica local SQLite stores and
show the same sequences then succeed as counterexamples.
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("httpx", reason="cross-repository gateway test")
pytest.importorskip("cmcp_runtime.manifest_catalog", reason="needs cMCP TRACE gate")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prototype import verifier_token as v
from prototype.cmcp_gate import CMCPTraceGate
from prototype.gate_store import GateStoreUnavailable, RemoteGateStore, SQLiteGateStore
from tests.test_cmcp_trace_gate import admit as proxy_admit
from tests.test_cmcp_trace_gate import credentials as proxy_credentials
from tests.test_cmcp_trace_gate import deployment, holder_proof
from tests.test_verifier_token_profile import VECTORS, context, fixture, g, unb64

__all__ = ["deployment", "fixture"]

ROOT = Path(__file__).resolve().parents[1]
SECRET = b"stage4-test-store-secret-0123456789"
POLICY = "sha256:" + "a" * 64
SESSION = "session-mh"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
TIMEOUT = 60


def replica_key(name: str) -> Ed25519PrivateKey:
    """Each replica signs receipts with its own gateway key."""
    return Ed25519PrivateKey.from_private_bytes(bytes([0x40 + ord(name[0])]) * 32)


def child_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), *filter(None, [env.get("PYTHONPATH", "")])])
    env["TRACE_GATE_STORE_SECRET"] = SECRET.decode()
    return env


# Replica process ------------------------------------------------------------


def _replica_main() -> None:
    """JSON lines on stdin/stdout; one gate per process, rebuilt by ``store``."""
    name = sys.argv[1]
    fixture_ = json.loads((VECTORS / "01-valid.json").read_text())
    ctx = context(fixture_)
    raw = unb64(fixture_["envelope_b64"])
    state: dict = {"gate": None, "sent": 0, "clock": g.NOW}

    def build(spec: str) -> CMCPTraceGate:
        kind, _, value = spec.partition(":")
        store = (
            RemoteGateStore("127.0.0.1", int(value), SECRET)
            if kind == "remote"
            else SQLiteGateStore(value)
        )
        return CMCPTraceGate(
            ctx,
            store=store,
            gateway_key=replica_key(name),
            gateway_issuer=f"spiffe://example.test/gateway/{name}",
            gateway_policy_digest=POLICY,
            clock=lambda: state["clock"],
        )

    def token(args: dict) -> bytes:
        return unb64(args["token"]) if "token" in args else raw

    def wait(args: dict) -> None:
        start = args.get("start_at")
        if start is not None:
            time.sleep(max(0.0, start - time.time()))

    def begin_only(gate: CMCPTraceGate, args: dict) -> str:
        wait(args)
        try:
            gate.begin(
                args["credentials"],
                action=args["action"],
                session_id=args["session_id"],
                call_id=args["call_id"],
                policy_digest=POLICY,
            )
        except ValueError:
            return "refused"
        return "accepted"

    def call(gate: CMCPTraceGate, args: dict) -> dict:
        # Mirrors cMCP: a ValueError from begin becomes a refusal receipt; after
        # admission, recheck/receipt/recheck precede the transport.
        wait(args)
        action, call_id = args["action"], args["call_id"]
        try:
            handle, _ = gate.begin(
                args["credentials"],
                action=action,
                session_id=args["session_id"],
                call_id=call_id,
                policy_digest=POLICY,
            )
        except ValueError as exc:
            gate.refusal(action=action, session_id=args["session_id"], call_id=call_id)
            return {"allowed": False, "reason": str(exc)}
        try:
            gate.recheck(handle, action=action, policy_digest=POLICY)
            gate.receipt(handle, allowed=True, reason="cedar_allowed")
            gate.recheck(handle, action=action, policy_digest=POLICY)
        except ValueError as exc:
            return {"allowed": False, "reason": str(exc)}
        state["sent"] += 1
        return {"allowed": True, "reason": None}

    for line in sys.stdin:
        request = json.loads(line)
        op, args = request["op"], request.get("args", {})
        try:
            if op == "store":
                state.update(gate=build(args["spec"]), sent=0, clock=g.NOW)
                result = None
            elif op == "challenge":
                result = state["gate"].challenge(
                    token(args), session_id=args["session_id"], action=args["action"]
                )
            elif op == "admit":
                result = state["gate"].admit(
                    token(args), args["credentials"], session_id=args["session_id"]
                )
            elif op == "call":
                result = call(state["gate"], args)
            elif op == "begin":
                result = begin_only(state["gate"], args)
            elif op == "receipts":
                result = [CMCPTraceGate._encode(r) for r in state["gate"].receipts()]
            elif op == "sent":
                result = state["sent"]
            else:
                raise KeyError(op)
            reply = {"ok": result}
        except v.ProfileError as exc:
            reply = {"error": str(exc), "kind": "ProfileError"}
        except OSError as exc:
            reply = {"error": str(exc), "kind": type(exc).__name__}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


# Parent-side harness -------------------------------------------------------


class ReplicaError(Exception):
    def __init__(self, reply: dict) -> None:
        super().__init__(reply["error"])
        self.code = reply["error"]
        self.kind = reply["kind"]


class Replica:
    def __init__(self, name: str, log: Path) -> None:
        self.name = name
        self._log = log.open("w")
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "from tests.test_multihost_replay import _replica_main; _replica_main()",
                name,
            ],
            cwd=ROOT,
            env=child_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log,
            text=True,
            creationflags=NO_WINDOW,
        )
        self._lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put("")

    def send(self, op: str, **args) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"op": op, "args": args}) + "\n")
        self.proc.stdin.flush()

    def recv(self):
        line = self._lines.get(timeout=TIMEOUT)
        if not line:
            raise RuntimeError(f"replica {self.name} exited; see {self._log.name}")
        reply = json.loads(line)
        if "error" in reply:
            raise ReplicaError(reply)
        return reply["ok"]

    def __call__(self, op: str, **args):
        self.send(op, **args)
        return self.recv()

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self._log.close()


class StoreServer:
    """``python -m prototype.gate_store`` in its own process, sole owner of the file."""

    def __init__(self, database: Path) -> None:
        self.database = database
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "prototype.gate_store", "--database", str(database)],
            cwd=ROOT,
            env=child_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            creationflags=NO_WINDOW,
        )
        assert self.proc.stdout is not None
        self.port = int(self.proc.stdout.readline())

    @property
    def spec(self) -> str:
        return f"remote:{self.port}"

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=10)


@pytest.fixture(scope="module")
def replicas(tmp_path_factory):
    logs = tmp_path_factory.mktemp("replica-logs")
    pair = (Replica("A", logs / "A.log"), Replica("B", logs / "B.log"))
    yield pair
    for replica in pair:
        replica.close()


@pytest.fixture
def store_server(tmp_path):
    server = StoreServer(tmp_path / "shared-store.sqlite")
    yield server
    server.stop()


@pytest.fixture
def shared(replicas, store_server):
    for replica in replicas:
        replica("store", spec=store_server.spec)
    return replicas


@pytest.fixture
def local(replicas, tmp_path):
    for replica in replicas:
        replica("store", spec=f"sqlite:{tmp_path / f'local-{replica.name}.sqlite'}")
    return replicas


def admission_action(session: str = SESSION) -> dict:
    return {"domain": "cmcp:trace-admission:experimental-v1", "session_id": session}


def call_action(call_id: str, session: str = SESSION) -> dict:
    return {
        "domain": "cmcp:protected-action:experimental-v1",
        "session_id": session,
        "call_id": call_id,
        "tool_name": "read",
        "arguments": {},
    }


def raw_token() -> bytes:
    return unb64(json.loads((VECTORS / "01-valid.json").read_text())["envelope_b64"])


def admit_on(replica: Replica, minted_by: Replica | None = None) -> None:
    challenge = (minted_by or replica)("challenge", session_id=SESSION, action=admission_action())
    replica("admit", credentials=holder_proof(challenge, raw_token()), session_id=SESSION)


def proof_for(replica: Replica, call_id: str) -> dict:
    challenge = replica("challenge", session_id=SESSION, action=call_action(call_id))
    return holder_proof(challenge, raw_token())


def call_on(replica: Replica, call_id: str, credentials: dict, **extra) -> dict:
    return replica(
        "call",
        credentials=credentials,
        action=call_action(call_id),
        session_id=SESSION,
        call_id=call_id,
        **extra,
    )


def collision_token() -> bytes:
    changed = v.read_payload(v.unpack(raw_token(), v.PROFILE)[1], v.Token).model_dump()
    changed["cnf"] = v.holder_key(g.ROGUE).model_dump()
    return g.envelope(changed, g.ISSUER)


def verified_chain(envelopes: list[bytes]) -> list[v.Receipt]:
    """Authenticate each receipt under its replica's key; demand one unforked chain."""
    keys = {f"spiffe://example.test/gateway/{n}": replica_key(n) for n in "AB"}
    previous = None
    records = []
    for raw in envelopes:
        issuer = v.read_payload(v.unpack(raw, v.RECEIPT_PROFILE)[1], v.Receipt).issuer
        record = v.authenticate(raw, v.RECEIPT_PROFILE, keys[issuer].public_key(), v.Receipt)
        assert record.previous_receipt_hash == previous
        previous = v.digest(raw)
        records.append(record)
    return records


def receipts_of(replica: Replica) -> list[bytes]:
    return [CMCPTraceGate._decode(r) for r in replica("receipts")]


# Shared store: the guarantees ----------------------------------------------


def test_replicas_do_not_share_a_filesystem_path(shared, store_server, tmp_path):
    """Replicas reach state only through TCP: no replica store file exists."""
    a, b = shared
    admit_on(a)
    assert store_server.database.exists()
    assert not list(tmp_path.glob("local-*.sqlite"))


def test_proof_consumed_on_a_cannot_be_replayed_on_b(shared):
    a, b = shared
    admission = a("challenge", session_id=SESSION, action=admission_action())
    admission_proof = holder_proof(admission, raw_token())
    a("admit", credentials=admission_proof, session_id=SESSION)
    with pytest.raises(ReplicaError, match="^challenge_missing_or_consumed$"):
        b("admit", credentials=admission_proof, session_id=SESSION)

    proof = proof_for(a, "call-1")
    assert call_on(a, "call-1", proof)["allowed"]
    replay = call_on(b, "call-1", proof)
    assert replay == {"allowed": False, "reason": "challenge_missing_or_consumed"}
    assert (a("sent"), b("sent")) == (1, 0)
    # The replay's refusal did not displace the recorded allow for call-1.
    [record] = verified_chain(receipts_of(b))
    assert (record.call_id, record.decision) == ("call-1", "allow")


def test_session_continues_when_client_moves_replicas(shared):
    """Failover: admission on A, challenge on A, call executes on B."""
    a, b = shared
    admit_on(a)
    assert call_on(b, "call-1", proof_for(a, "call-1"))["allowed"]
    assert b("sent") == 1


def race(replicas, op: str, call_id: str, proof: dict) -> list:
    start = time.time() + 0.5
    for replica in replicas:
        replica.send(
            op,
            credentials=proof,
            action=call_action(call_id),
            session_id=SESSION,
            call_id=call_id,
            start_at=start,
        )
    return [replica.recv() for replica in replicas]


def test_concurrent_consumption_on_a_and_b_admits_exactly_one(shared):
    """One proof sent to A and B at the same instant: exactly one admission."""
    a, b = shared
    admit_on(a)
    for round_ in range(8):
        call_id = f"race-{round_}"
        outcomes = race((a, b), "begin", call_id, proof_for(a if round_ % 2 else b, call_id))
        assert sorted(outcomes) == ["accepted", "refused"]


def test_concurrent_replay_never_executes_under_a_deny_receipt(shared):
    """Full cMCP order. The loser's refusal may reach the winner's call ID first;
    the winner then fails closed instead of transporting under a deny receipt
    (a race the original single-host gate also had). At most one transport, and
    every transport has an allow receipt on the one chain."""
    a, b = shared
    admit_on(a)
    for round_ in range(6):
        call_id = f"race-{round_}"
        outcomes = race((a, b), "call", call_id, proof_for(a if round_ % 2 else b, call_id))
        reasons = sorted(str(o["reason"]) for o in outcomes if not o["allowed"])
        assert sum(o["allowed"] for o in outcomes) <= 1
        assert "challenge_missing_or_consumed" in reasons
    sent = a("sent") + b("sent")
    records = verified_chain(receipts_of(a))
    assert len([r for r in records if r.decision == "allow"]) == sent
    assert len({r.call_id for r in records}) == len(records) == 6


def test_concurrent_consume_has_one_winner_at_the_store(shared, store_server):
    """The consume itself: two processes, one nonce, exactly one record returned."""
    a, _ = shared
    challenge = a("challenge", session_id=SESSION, action=call_action("x"))
    script = (
        "import sys,time\n"
        "from prototype.gate_store import RemoteGateStore\n"
        "s=RemoteGateStore('127.0.0.1',int(sys.argv[1]),sys.argv[2].encode())\n"
        "time.sleep(max(0,float(sys.argv[4])-time.time()))\n"
        "print('won' if s.consume_challenge(sys.argv[3]) else 'lost')\n"
    )
    start = str(time.time() + 3.0)
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(store_server.port), SECRET.decode()]
            + [challenge["nonce"], start],
            cwd=ROOT,
            env=child_env(),
            stdout=subprocess.PIPE,
            text=True,
            creationflags=NO_WINDOW,
        )
        for _ in range(4)
    ]
    results = sorted(p.communicate(timeout=TIMEOUT)[0].strip() for p in procs)
    assert results == ["lost", "lost", "lost", "won"]


def test_token_id_reused_with_different_bytes_is_refused_on_b(shared):
    a, b = shared
    a("challenge", session_id=SESSION, action={"tool": "read"})
    replacement = CMCPTraceGate._encode(collision_token())
    with pytest.raises(ReplicaError, match="^token_id_collision$"):
        b("challenge", token=replacement, session_id=SESSION, action={"tool": "read"})
    changed = v.read_payload(v.unpack(collision_token(), v.PROFILE)[1], v.Token).model_dump()
    changed["jti"] = "replacement-token"
    fresh = CMCPTraceGate._encode(g.envelope(changed, g.ISSUER))
    assert b("challenge", token=fresh, session_id=SESSION, action={"tool": "read"})


def test_receipt_chain_stays_linear_across_alternating_replicas(shared):
    a, b = shared
    admit_on(a, minted_by=b)
    order = [a, b, a, b, b, a]
    for number, replica in enumerate(order):
        other = b if replica is a else a
        assert call_on(replica, f"call-{number}", proof_for(other, f"call-{number}"))["allowed"]
    # A refused call is chained as well.
    assert not call_on(b, "call-refused", {"nonce": "x" * 43, "proof": "AA"})["allowed"]
    # Concurrent appends from both replicas still extend one chain.
    for round_ in range(4):
        start = time.time() + 0.5
        ids = {a: f"par-a-{round_}", b: f"par-b-{round_}"}
        proofs = {r: proof_for(r, c) for r, c in ids.items()}
        for replica, call_id in ids.items():
            replica.send(
                "call",
                credentials=proofs[replica],
                action=call_action(call_id),
                session_id=SESSION,
                call_id=call_id,
                start_at=start,
            )
        assert a.recv()["allowed"] and b.recv()["allowed"]
    envelopes = receipts_of(b)
    assert envelopes == receipts_of(a)
    records = verified_chain(envelopes)
    calls = [r.call_id for r in records]
    assert calls[:7] == [f"call-{n}" for n in range(6)] + ["call-refused"]
    assert len(set(calls)) == len(calls) == 15
    issuers = {r.issuer.rsplit("/", 1)[1] for r in records}
    assert issuers == {"A", "B"}


def test_store_outage_fails_closed_without_transport(shared, store_server):
    a, b = shared
    admit_on(a)
    consumed = proof_for(a, "call-1")
    assert call_on(a, "call-1", consumed)["allowed"]
    pending = proof_for(a, "call-2")
    store_server.stop()
    for replica in (a, b):
        with pytest.raises(ReplicaError) as refused:
            call_on(replica, "call-2", pending)
        assert refused.value.kind == GateStoreUnavailable.__name__
        with pytest.raises(ReplicaError) as refused:
            replica("challenge", session_id=SESSION, action=call_action("call-3"))
        assert refused.value.kind == GateStoreUnavailable.__name__
    assert (a("sent"), b("sent")) == (1, 0)
    # State is durable: after a store restart the consumed proof stays consumed,
    # and the proof that never reached a consume is still usable (on B).
    restarted = StoreServer(store_server.database)
    try:
        for replica in (a, b):
            replica("store", spec=restarted.spec)
        assert call_on(b, "call-1", consumed) == {
            "allowed": False,
            "reason": "challenge_missing_or_consumed",
        }
        assert call_on(b, "call-2", pending)["allowed"]
        calls = [(r.call_id, r.decision) for r in verified_chain(receipts_of(b))]
        assert calls == [("call-1", "allow"), ("call-2", "allow")]
    finally:
        restarted.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("when", ["before-begin", "after-begin"])
async def test_real_proxy_store_outage_stops_transport(deployment, store_server, monkeypatch, when):
    """The real cMCP proxy on a remote store: an outage raises and nothing is sent."""
    d = deployment
    old = d["gate"]
    gate = CMCPTraceGate(
        old.context,
        store=RemoteGateStore("127.0.0.1", store_server.port, SECRET),
        gateway_key=d["key"],
        gateway_issuer=old._issuer,
        gateway_policy_digest=old._gateway_policy_digest,
        clock=lambda: d["clock"][0],
    )
    d["gate"] = gate
    monkeypatch.setattr(d["proxy"], "_trace_gate", gate)
    proxy_admit(d)
    proof = proxy_credentials(d)
    if when == "before-begin":
        store_server.stop()
    else:
        original = d["proxy"]._check_provenance

        async def outage(entry):
            result = await original(entry)
            store_server.stop()
            return result

        monkeypatch.setattr(d["proxy"], "_check_provenance", outage)
    with pytest.raises(OSError):
        await d["proxy"].call_tool("call-1", "read", {}, trace_credentials=proof)
    assert d["calls"] == []
    await d["client"].aclose()


def test_remote_store_refuses_a_client_without_the_secret(store_server):
    with pytest.raises(GateStoreUnavailable, match="unauthenticated"):
        RemoteGateStore("127.0.0.1", store_server.port, b"wrong-secret-0123456789").receipts()


# Causal: per-replica local stores reopen each gap ----------------------------


def replicate(source: Path, target: Path) -> None:
    """Snapshot replication, as an asynchronous replica or file copy would give."""
    with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
        src.backup(dst)


def test_causal_local_stores_admit_cross_replica_replay(local, tmp_path):
    a, b = local
    admit_on(a)
    proof = proof_for(a, "call-1")
    # B holds a copy taken before A consumed the nonce. Without any copy B would
    # refuse for lack of the challenge, and failover would not work either.
    replicate(tmp_path / "local-A.sqlite", tmp_path / "local-B.sqlite")
    assert call_on(a, "call-1", proof)["allowed"]
    assert call_on(b, "call-1", proof)["allowed"]
    assert (a("sent"), b("sent")) == (1, 1)


def test_causal_local_stores_miss_token_id_collision(local):
    a, b = local
    a("challenge", session_id=SESSION, action={"tool": "read"})
    replacement = CMCPTraceGate._encode(collision_token())
    assert b("challenge", token=replacement, session_id=SESSION, action={"tool": "read"})


def test_causal_local_stores_fork_the_receipt_chain(local):
    a, b = local
    for replica in (a, b):
        admit_on(replica)
    for number, replica in enumerate([a, b, a, b]):
        assert call_on(replica, f"call-{number}", proof_for(replica, f"call-{number}"))["allowed"]
    heads = [verified_chain(receipts_of(r))[0].previous_receipt_hash for r in (a, b)]
    # Two chains for one session, each with its own genesis: a fork.
    assert heads == [None, None]
    assert receipts_of(a) != receipts_of(b)

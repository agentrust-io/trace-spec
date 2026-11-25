"""Build the behavior-trace vectors (docs/rfcs/behavior-trace.md).

Uses raw primitives only, not prototype/behavior_trace.py, so the vectors
check that code instead of copying it. Keys come from fixed seeds and Ed25519
is deterministic, so every run writes the same bytes.

    python examples/behavior-trace/gen_vectors.py
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

OUT = pathlib.Path(__file__).resolve().parent
PROFILE = "behavior-trace-block/experimental-v1"
T0 = 1794700000000


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _jwk(key: Ed25519PrivateKey) -> dict[str, str]:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64(raw)}


def _kid(key: Ed25519PrivateKey) -> str:
    # RFC 7638: SHA-256 over the required members in lexicographic order.
    jwk = _jwk(key)
    members = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":")
    )
    return _b64(hashlib.sha256(members.encode()).digest())


KEYS = {
    "wrapper": _key(1),
    "cmcp": _key(2),
    "model-gateway": _key(3),
    "egress-proxy": _key(4),
    "sandbox": _key(5),
    "ca2a": _key(6),
}
ROGUE = _key(9)
PINNED = {edge: [_jwk(k)] for edge, k in KEYS.items()}


def digest(block: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(block)).hexdigest()


def sign(block: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    body = {k: v for k, v in block.items() if k != "sig"}
    value = _b64(key.sign(rfc8785.dumps(body)))
    return {**body, "sig": {"alg": "Ed25519", "kid": _kid(key), "value": value}}


def build(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sign steps in order. Parents, prev and heartbeat peers name blocks by label.

    A step may override `seq`, `prev` (a label, "RUN" or a literal), `run_id` or
    `key`, or add `extra` members. That is how the failing vectors keep valid
    signatures.
    """
    out: dict[str, dict[str, Any]] = {}
    last: dict[str, str] = {}
    seqs: dict[str, int] = {}
    run_id = None

    def ref(label: str) -> str:
        return out[label]["digest"] if label in out else label

    for n, step in enumerate(steps):
        edge = step["edge"]
        seq = step.get("seq", seqs.get(edge, 0))
        seqs[edge] = seq + 1
        prev = None if step["kind"] == "run_start" else last.get(edge, run_id)
        if "prev" in step:
            want = step["prev"]
            prev = run_id if want == "RUN" else out[want]["digest"] if want in out else want
        block: dict[str, Any] = {"v": PROFILE}
        if step["kind"] != "run_start":
            block["run_id"] = step.get("run_id", run_id)
        block.update({
            "edge": edge,
            "seq": seq,
            "prev": prev,
            "parents": [ref(p) for p in step.get("parents", [])],
            "kind": step["kind"],
            "t": {"observed_at": T0 + n * 1000, "duration_ms": 5},
            "body": step.get("body", {}),
        })
        if "provenance" in step:
            block["provenance"] = step["provenance"]
        block.update(step.get("extra", {}))
        if "peers" in step:
            block["body"] = {"peers": {e: ref(lbl) for e, lbl in step["peers"].items()}}
        signed = sign(block, step.get("key", KEYS[edge]))
        d = digest(signed)
        out[step["label"]] = {"block": signed, "digest": d}
        last[edge] = d
        if step["kind"] == "run_start":
            run_id = d
    return [v["block"] for v in out.values()]


TASK = "sha256:" + "a" * 64
OTHER_RUN = "sha256:" + "b" * 64
UNKNOWN = "sha256:" + "c" * 64


def c(n: int) -> str:
    """A placeholder keyed commitment."""
    return f"hmac-sha256:{n:064x}"


MODEL = "example-model-1"


def run_a() -> list[dict[str, Any]]:
    """Two edges and a heartbeat, ending completed."""
    return [
        {"label": "W0", "edge": "wrapper", "kind": "run_start", "body": {"contract": TASK}},
        {"label": "M0", "edge": "model-gateway", "kind": "model_call", "parents": ["W0"],
         "body": {"model": MODEL, "request": c(1), "response": c(2),
                  "requested_tools": [{"tool": "search", "args": c(3)}]}},
        {"label": "C0", "edge": "cmcp", "kind": "tool_call", "parents": ["M0"],
         "body": {"tool": "search", "args": c(3), "decision": "allow"}},
        {"label": "C1", "edge": "cmcp", "kind": "tool_result", "parents": ["C0"],
         "body": {"tool": "search", "status": "ok", "result": c(4)}},
        {"label": "M1", "edge": "model-gateway", "kind": "heartbeat", "peers": {"cmcp": "C1"}},
        {"label": "W1", "edge": "wrapper", "kind": "run_end", "parents": ["C1"],
         "body": {"outcome": "completed"}},
    ]


def run_b() -> list[dict[str, Any]]:
    """Four edges, a policy deny, provenance tags, ending blocked."""
    return [
        {"label": "W0", "edge": "wrapper", "kind": "run_start", "body": {"contract": TASK}},
        {"label": "M0", "edge": "model-gateway", "kind": "model_call", "parents": ["W0"],
         "body": {"model": MODEL, "request": c(5), "response": c(6)}},
        {"label": "E0", "edge": "egress-proxy", "kind": "dns", "parents": ["M0"],
         "body": {"query": c(7)}},
        {"label": "E1", "edge": "egress-proxy", "kind": "dns", "parents": ["M0"],
         "body": {"query": c(8), "answers": c(9)}},
        {"label": "E2", "edge": "egress-proxy", "kind": "fetch", "parents": ["M0"],
         "body": {"url": c(10), "status": 200, "content": c(11), "bytes": 1024}},
        {"label": "M1", "edge": "model-gateway", "kind": "model_call", "parents": ["E2"],
         "provenance": {"/body/usage/input_tokens": "asserted"},
         "body": {"model": MODEL, "request": c(12), "response": c(13),
                  "usage": {"input_tokens": 512, "output_tokens": 64}}},
        {"label": "C0", "edge": "cmcp", "kind": "tool_call", "parents": ["M1"],
         "provenance": {"/body/tool": "observed"},
         "body": {"tool": "read", "args": c(14), "decision": "allow"}},
        {"label": "C1", "edge": "cmcp", "kind": "policy_decision", "parents": ["M1"],
         "body": {"tool": "delete_records", "decision": "deny", "rule": "no-deletes"}},
        {"label": "M2", "edge": "model-gateway", "kind": "heartbeat",
         "peers": {"cmcp": "C1", "egress-proxy": "E2"}},
        {"label": "W1", "edge": "wrapper", "kind": "run_end", "parents": ["C1", "M2"],
         "body": {"outcome": "blocked"}},
    ]


def run_every_kind() -> list[dict[str, Any]]:
    """Every kind, with a full body, in one run."""
    return [
        {"label": "W0", "edge": "wrapper", "kind": "run_start",
         "body": {"contract": TASK, "manifest": OTHER_RUN}},
        {"label": "M0", "edge": "model-gateway", "kind": "model_call", "parents": ["W0"],
         "body": {"model": MODEL, "request": c(20), "response": c(21),
                  "requested_tools": [{"tool": "fs.read", "args": c(22)}],
                  "usage": {"input_tokens": 1, "output_tokens": 2}, "ext": {"region": "eu-west"}}},
        {"label": "C0", "edge": "cmcp", "kind": "tool_call", "parents": ["M0"],
         "body": {"tool": "fs.read", "server": "spiffe://example.org/mcp/fs", "args": c(22),
                  "decision": "step_up", "rule": "needs-approval"}},
        {"label": "W1", "edge": "wrapper", "kind": "approval", "parents": ["C0"],
         "body": {"approver": "alice@example.org", "approves": TASK, "decision": "approved"}},
        {"label": "C1", "edge": "cmcp", "kind": "tool_result", "parents": ["W1"],
         "body": {"tool": "fs.read", "status": "error"}},
        {"label": "C2", "edge": "cmcp", "kind": "policy_decision", "parents": ["C1"],
         "body": {"tool": "fs.delete", "decision": "deny", "args": c(23)}},
        {"label": "S0", "edge": "sandbox", "kind": "file", "parents": ["C0"],
         "body": {"path": c(24), "op": "read", "bytes": 10}},
        {"label": "S1", "edge": "sandbox", "kind": "device", "parents": ["M0"],
         "body": {"device": "camera", "op": "open"}},
        {"label": "E0", "edge": "egress-proxy", "kind": "dns", "parents": ["M0"],
         "body": {"query": c(25)}},
        {"label": "E1", "edge": "egress-proxy", "kind": "fetch", "parents": ["E0"],
         "body": {"url": c(26), "host": c(27), "status": 404, "content": c(28)}},
        {"label": "A0", "edge": "ca2a", "kind": "delegation", "parents": ["M0"],
         "body": {"credential": "cred-1", "child_run": OTHER_RUN}},
        {"label": "M1", "edge": "model-gateway", "kind": "heartbeat",
         "peers": {"cmcp": "C2", "sandbox": "S1", "egress-proxy": "E1", "ca2a": "A0"}},
        {"label": "W2", "edge": "wrapper", "kind": "run_end", "parents": ["C2", "M1"],
         "body": {"outcome": "failed"}},
    ]


def without(blocks: list[dict[str, Any]], *drop: int) -> list[dict[str, Any]]:
    return [b for i, b in enumerate(blocks) if i not in drop]


def tweak(steps: list[dict[str, Any]], label: str, **changes: Any) -> list[dict[str, Any]]:
    steps = copy.deepcopy(steps)
    for s in steps:
        if s["label"] == label:
            s.update(changes)
    return steps


def vectors() -> list[tuple[str, str, list[dict[str, Any]], str, list[str]]]:
    a, b = build(run_a()), build(run_b())

    body_changed = copy.deepcopy(a)
    body_changed[2]["body"]["tool"] = "delete_records"
    swapped_sig = copy.deepcopy(a)
    swapped_sig[2]["sig"]["value"] = a[3]["sig"]["value"]
    kid_newline = copy.deepcopy(a)
    kid_newline[3]["sig"]["kid"] += "\n"

    return [
        ("01-valid-two-edges", "A complete run over two edges with a heartbeat.",
         a, "verified", []),
        ("02-valid-four-edges-shuffled", "A blocked run over four edges, blocks out of order.",
         list(reversed(b)), "verified", []),
        ("03-truncated-no-run-end", "Run A without its run_end.",
         without(a, 5), "truncated", []),
        ("04-truncated-tail-dropped", "Run B with its last three blocks dropped.",
         without(b, 7, 8, 9), "truncated", []),
        ("05-schema-unknown-member", "A block carries a member the schema does not name.",
         build(tweak(run_a(), "M1", extra={"note": "x"})), "rejected", ["schema_invalid"]),
        ("06-schema-kid-trailing-newline", "A kid ends in a newline, which ECMA-262 rejects.",
         kid_newline, "rejected", ["schema_invalid"]),
        ("07-key-unknown", "A cmcp block is signed by a key nobody pinned.",
         build(tweak(run_a(), "C1", key=ROGUE)), "rejected", ["key_not_pinned"]),
        ("08-key-pinned-for-other-edge", "A cmcp block is signed by the wrapper's key.",
         build(tweak(run_a(), "C1", key=KEYS["wrapper"])), "rejected", ["key_not_pinned"]),
        ("09-signature-body-changed", "A tool name is changed after signing.",
         body_changed, "rejected", ["signature_invalid"]),
        ("10-signature-from-other-block", "A block carries another block's signature.",
         swapped_sig, "rejected", ["signature_invalid"]),
        ("11-run-start-missing", "The run_start block is absent.",
         without(a, 0), "rejected", ["run_start_invalid"]),
        ("12-run-start-seq-not-zero", "The run_start has seq 1 instead of 0.",
         build(tweak(run_a(), "W0", seq=1)), "rejected", ["run_start_invalid"]),
        ("13-run-id-other-run", "A heartbeat names another run.",
         build(tweak(run_a(), "M1", run_id=OTHER_RUN)), "rejected", ["run_id_mismatch"]),
        ("14-run-id-on-run-end", "The run_end names another run.",
         build(tweak(run_a(), "W1", run_id=OTHER_RUN)), "rejected", ["run_id_mismatch"]),
        ("15-fork-cmcp", "Two cmcp blocks share seq 1.",
         build(run_a() + [
             {"label": "C1b", "edge": "cmcp", "kind": "tool_result", "seq": 1, "prev": "C0",
              "parents": ["C0"], "body": {"tool": "search", "status": "ok", "result": c(6)}},
         ]), "rejected", ["fork"]),
        ("16-fork-heartbeat", "Two model-gateway blocks share seq 1.",
         build(run_a() + [
             {"label": "M1b", "edge": "model-gateway", "kind": "heartbeat", "seq": 1,
              "prev": "M0", "peers": {"cmcp": "C0"}},
         ]), "rejected", ["fork"]),
        ("17-gap-first-block", "The first egress-proxy block is missing.",
         without(b, 2), "rejected", ["chain_gap"]),
        ("18-gap-middle-block", "A middle egress-proxy block is missing.",
         without(b, 3), "rejected", ["chain_gap"]),
        ("19-link-skips-a-block", "A cmcp block points at the run instead of its predecessor.",
         build(tweak(run_a(), "C1", prev="RUN")), "rejected", ["chain_link_broken"]),
        ("20-link-first-block-wrong", "The first cmcp block points at a model block.",
         build(tweak(run_a(), "C0", prev="M0")), "rejected", ["chain_link_broken"]),
        ("21-parent-unknown", "A block names a parent that is in no run.",
         build(tweak(run_a(), "W1", parents=["C1", UNKNOWN])), "rejected", ["parent_missing"]),
        ("22-parent-from-other-run", "A block names a parent from another run.",
         build(tweak(run_a(), "W1", parents=[OTHER_RUN])), "rejected", ["parent_missing"]),
        ("23-heartbeat-wrong-edge", "A heartbeat names a model block as the cmcp tip.",
         build(tweak(run_a(), "M1", peers={"cmcp": "M0"})), "rejected",
         ["heartbeat_peer_unknown"]),
        ("24-heartbeat-unknown-block", "A heartbeat names a block that is not in the run.",
         build(tweak(run_a(), "M1", peers={"cmcp": UNKNOWN})), "rejected",
         ["heartbeat_peer_unknown"]),
        ("25-block-after-run-end", "The wrapper writes a block after run_end.",
         build(run_a() + [
             {"label": "W2", "edge": "wrapper", "kind": "approval",
              "body": {"approver": "alice@example.org", "approves": TASK, "decision": "approved"}},
         ]), "rejected", ["block_after_end"]),
        ("26-run-end-on-cmcp", "A run_end is written by cmcp, not the wrapper.",
         build(tweak(run_a(), "W1", edge="cmcp")), "rejected", ["block_after_end"]),
        ("27-run-start-on-other-edge", "The only run_start is written by cmcp; no wrapper block.",
         build([
             {"label": "S", "edge": "cmcp", "kind": "run_start"},
             {"label": "C1", "edge": "cmcp", "kind": "tool_call", "parents": ["S"],
              "body": {"tool": "search", "args": c(33), "decision": "allow"}},
         ]), "rejected", ["run_start_invalid"]),
        ("28-duplicate-tool-block", "The same tool block appears twice.",
         a + [a[2]], "rejected", ["duplicate_block"]),
        ("29-duplicate-run-start", "The run_start appears twice.",
         [a[0], *a], "rejected", ["duplicate_block"]),
        ("30-two-run-ends", "The wrapper writes a second run_end.",
         build(run_a() + [
             {"label": "W2", "edge": "wrapper", "kind": "run_end", "body": {"outcome": "failed"}},
         ]), "rejected", ["block_after_end"]),
        ("31-provenance-missing-member", "Provenance names a member the block does not have.",
         build(tweak(run_a(), "C0", provenance={"/body/missing": "observed"})), "rejected",
         ["provenance_path_invalid"]),
        ("32-provenance-names-a-container", "Provenance names an array, not a leaf value.",
         build(tweak(run_a(), "M0", provenance={"/body/requested_tools": "observed"})),
         "rejected", ["provenance_path_invalid"]),
        ("33-valid-escaped-pointers", "Provenance uses escaped keys and an array index.",
         build(tweak(tweak(tweak(run_a(),
             "M0", provenance={"/body/requested_tools/0/tool": "observed"}),
             "C0", body={"tool": "search", "args": c(3), "decision": "allow", "ext": {"a/b": "x"}},
             provenance={"/body/ext/a~1b": "derived"}),
             "C1", body={"tool": "search", "status": "ok", "ext": {"a~1b": "y"}},
             provenance={"/body/ext/a~01b": "derived"})),
         "verified", []),
        ("34-provenance-dotted-path", "Provenance uses a dotted path, not a JSON Pointer.",
         build(tweak(run_a(), "C0", provenance={"body.tool": "observed"})), "rejected",
         ["schema_invalid"]),
        ("36-fork-at-run-end", "Another wrapper block shares the run_end's seq.",
         build(run_a() + [
             {"label": "W1b", "edge": "wrapper", "kind": "approval", "seq": 1, "prev": "W0",
              "body": {"approver": "alice@example.org", "approves": TASK, "decision": "approved"}},
         ]), "rejected", ["block_after_end", "fork"]),
        ("37-tool-call-after-end", "A cmcp block names the run_end as its parent.",
         build(run_a() + [
             {"label": "C2", "edge": "cmcp", "kind": "tool_call", "parents": ["W1"],
              "body": {"tool": "send_email", "args": c(30), "decision": "allow"}},
         ]), "rejected", ["block_after_end"]),
        ("38-model-call-after-end", "A model block names the run_end as its parent.",
         build(run_a() + [
             {"label": "M2", "edge": "model-gateway", "kind": "model_call", "parents": ["W1"],
              "body": {"model": MODEL, "request": c(31), "response": c(32)}},
         ]), "rejected", ["block_after_end"]),
        ("39-valid-heartbeat-sees-end", "A heartbeat names the run_end as a peer.",
         build(run_a() + [
             {"label": "M2", "edge": "model-gateway", "kind": "heartbeat",
              "peers": {"wrapper": "W1", "cmcp": "C1"}},
         ]), "verified", []),
        ("35-provenance-index-leading-zero", "Provenance uses an array index with a leading zero.",
         build(tweak(run_a(), "M0", provenance={"/body/requested_tools/00/tool": "observed"})),
         "rejected", ["provenance_path_invalid"]),
        ("40-raw-content-in-body", "A tool call carries the raw prompt text.",
         build(tweak(run_a(), "C0", body={"tool": "search", "args": c(3), "decision": "allow",
                                         "prompt": "summarise the customer file"})),
         "rejected", ["schema_invalid"]),
        ("41-args-not-a-commitment", "A tool call's args are plain text, not a commitment.",
         build(tweak(run_a(), "C0", body={"tool": "search", "args": "customer 4411",
                                         "decision": "allow"})),
         "rejected", ["schema_invalid"]),
        ("42-valid-every-kind", "One run using every kind with a full body.",
         build(run_every_kind()), "verified", []),
        ("43-provenance-pointer-too-long", "A provenance pointer is longer than 1024 characters.",
         build(tweak(run_a(), "M0", provenance={
             "/body/requested_tools/" + "1" * 5000 + "/tool": "observed"})),
         "rejected", ["schema_invalid"]),
        ("44-provenance-index-many-digits", "A provenance index has 700 digits.",
         build(tweak(run_a(), "M0", provenance={
             "/body/requested_tools/" + "1" * 700 + "/tool": "observed"})),
         "rejected", ["provenance_path_invalid"]),
        ("45-ext-name-free-text", "A tool call's ext member is named with a sentence.",
         build(tweak(run_a(), "C0", body={"tool": "search", "args": c(3), "decision": "allow",
                                         "ext": {"Reasoning: the user asked me to delete "
                                                 "the audit log, so I did.": True}})),
         "rejected", ["schema_invalid"]),
        ("46-heartbeat-end-under-other-edge", "A heartbeat names the run_end under cmcp.",
         build(run_a() + [
             {"label": "M2", "edge": "model-gateway", "kind": "heartbeat",
              "peers": {"cmcp": "W1"}},
         ]), "rejected", ["heartbeat_peer_unknown"]),
        ("47-ext-name-empty", "Ext name boundary: ext-name-empty.",
         build(tweak(run_a(), "C0", body={"tool": "search", "args": c(3), "decision": "allow",
                                         "ext": {'': True}})),
         "rejected", ['schema_invalid']),
        ("48-ext-name-too-long", "Ext name boundary: ext-name-too-long.",
         build(tweak(run_a(), "C0", body={"tool": "search", "args": c(3), "decision": "allow",
                                         "ext": {'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': True}})),
         "rejected", ['schema_invalid']),
        ("49-ext-name-equals", "Ext name boundary: ext-name-equals.",
         build(tweak(run_a(), "C0", body={"tool": "search", "args": c(3), "decision": "allow",
                                         "ext": {'a=b': True}})),
         "rejected", ['schema_invalid']),
        ("50-valid-ext-name-one-character", "Ext name boundary: valid-ext-name-one-character.",
         build(tweak(run_a(), "C0", body={"tool": "search", "args": c(3), "decision": "allow",
                                         "ext": {'~': True}})),
         "verified", []),
        ("51-valid-ext-name-64-characters", "Ext name boundary: valid-ext-name-64-characters.",
         build(tweak(run_a(), "C0", body={"tool": "search", "args": c(3), "decision": "allow",
                                         "ext": {'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': True}})),
         "verified", []),
    ]


def main() -> None:
    for name, description, blocks, classification, codes in vectors():
        doc = {
            "id": name[:2],
            "name": name,
            "description": description,
            "rfc": "docs/rfcs/behavior-trace.md#4-verifying-a-run",
            "pinned_keys": PINNED,
            "blocks": blocks,
            "expected": {"classification": classification, "codes": codes},
        }
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        (OUT / f"{name}.json").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()

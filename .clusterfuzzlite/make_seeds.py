"""Write a seed corpus zip per fuzz target into the directory given as argv[1].

Seeds are the committed example records and revocation bundles, plus one valid
input per target built with the library itself. Every target reads a mode byte
followed by JSON text, except ``fuzz_canonicalize`` which reads JSON alone; bit 0
of the mode byte asks the target to re-sign the input, so each valid seed is
written once as-is and once with that bit set.
"""

from __future__ import annotations

import json
import pathlib
import sys
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.content_marking import build_assertion
from agentrust_trace.intent_bridge import digest_jcs, sign_bridge
from agentrust_trace.provenance import FORMAT_V2, build_record

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _walk(value, found):
    if isinstance(value, dict):
        if isinstance(value.get("eat_profile"), str) and "iat" in value:
            found["record"].append(value)
        if value.get("type") == "TraceRevocationBundle/1.0":
            found["bundle"].append(value)
        for item in value.values():
            _walk(item, found)
    elif isinstance(value, list):
        for item in value:
            _walk(item, found)


def _examples():
    found = {"record": [], "bundle": []}
    for path in sorted((ROOT / "examples").rglob("*.json")):
        try:
            _walk(json.loads(path.read_text(encoding="utf-8")), found)
        except ValueError:
            continue
    return found


def _bridge_case():
    tool_call = {"name": "send_invoice", "arguments": {"invoice_id": "INV-7"}}
    declaration = {"impact": "external-side-effect", "purpose": "send invoice"}
    after = {"observation": {"status": "accepted"}, "observer": "observer-1", "observed_at": 120}
    authorization = {
        "authorization_id": "auth-7",
        "decision": "allow",
        "authorizer": "finance-policy",
        "authorizer_key_id": "authorizer-key-1",
        "authorized_at": 100,
        "expires_at": 200,
        "scope": {"tools": ["send_invoice"], "impacts": ["external-side-effect"]},
        "pic": {
            "profile": "PIC-CJSON/1.0",
            "intent_digest": "sha256:" + "1" * 64,
            "args_digest": "sha256:" + "2" * 64,
        },
        "declaration_digest": digest_jcs(declaration),
        "tool_call_digest": digest_jcs(tool_call),
        "successor_observation_digest": digest_jcs(after),
        "transcript_required": True,
    }
    # Signed with a throwaway key: bit 0 re-signs with the target's pinned key.
    bridge = sign_bridge(authorization, Ed25519PrivateKey.generate())
    return {
        "bridge": bridge,
        "declaration": declaration,
        "pic_intent_digest": authorization["pic"]["intent_digest"],
        "pic_args_digest": authorization["pic"]["args_digest"],
        "tool_call": tool_call,
        "transcript": {"before": {"tool_call": tool_call}, "after": after},
        "successor_digest": authorization["successor_observation_digest"],
    }


def _provenance_case():
    tools = [
        {
            "name": "search",
            "description": "search the docs",
            "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
            "annotations": {"readOnlyHint": True},
        }
    ]
    record = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=tools,
        artifact={"package": "acme-search", "digest": "sha256:" + "a" * 64},
        issued_at=1_785_000_000,
        format=FORMAT_V2,
    )
    return {"record": record, "tools": tools}


def _content_marking_case(record):
    text = json.dumps(record, sort_keys=True)
    assertion = build_assertion(text.encode("utf-8"), url="https://records.example/r.json")
    return {"assertion": assertion, "record": text}


def _write(out: pathlib.Path, target: str, seeds: list[bytes]) -> None:
    with zipfile.ZipFile(out / f"{target}_seed_corpus.zip", "w") as archive:
        for index, seed in enumerate(seeds):
            archive.writestr(f"seed-{index:04d}", seed)


def _moded(values) -> list[bytes]:
    seeds = []
    for value in values:
        body = json.dumps(value).encode("utf-8")
        seeds.extend([b"\x00" + body, b"\x01" + body])
    return seeds


def main(out: pathlib.Path) -> None:
    found = _examples()
    records = found["record"]
    _write(out, "fuzz_verify_record", _moded(records))
    _write(out, "fuzz_revocation_bundle", _moded(found["bundle"]))
    _write(out, "fuzz_provenance", _moded([_provenance_case()]))
    _write(out, "fuzz_intent_bridge", _moded([_bridge_case()]))
    _write(out, "fuzz_content_marking", _moded([_content_marking_case(r) for r in records[:8]]))
    _write(out, "fuzz_canonicalize", [json.dumps(r).encode("utf-8") for r in records])


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]))

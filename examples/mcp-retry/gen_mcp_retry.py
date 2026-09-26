"""Generate an informative, synthetic MCP retry packet, not a v0.3 profile.

The public seed is fixture material, never a production signing identity.
Run from the repository root after installing its development dependencies.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import key_to_jwk, sign_record

CANONICALIZATION = "example-only/jcs-safe-integers-v1"
TRANSCRIPT_FORMAT = "example-only/mcp-retry-transcript-v1"
SNAPSHOT_FORMAT = "example-only/mcp-declarations-v1"
NOW = 1790294400
SERVER = "https://inventory.example.org/mcp"
PROTOCOL = "2026-07-28"


def canonical_bytes(value: Any) -> bytes:
    """Example-local subset: JCS, with all floats and unsafe integers refused."""
    if isinstance(value, float) or (type(value) is int and abs(value) > 9007199254740991):
        raise ValueError("unsupported numeric value in example canonicalization")
    if isinstance(value, dict):
        for item in value.values():
            canonical_bytes(item)
    elif isinstance(value, list):
        for item in value:
            canonical_bytes(item)
    return rfc8785.dumps(value)


def load_json(text: str) -> Any:
    """Do not silently collapse duplicate members before making commitments."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    value = json.loads(text, object_pairs_hook=unique)
    canonical_bytes(value)
    return value


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def fixture_key() -> Ed25519PrivateKey:
    # Intentionally public and deterministic, following the other example vectors.
    seed = hashlib.sha256(b"TRACE mcp-retry example ONLY - not a secret").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def snapshot(capture_id: str) -> dict[str, Any]:
    tools = [
        {
            "name": "inventory.lookup",
            "description": "Look up a fictional stock record.",
            "inputSchema": {
                "type": "object",
                "properties": {"record_id": {"type": "string"}},
                "required": ["record_id"],
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object",
                "properties": {"stock": {"type": "integer"}},
                "required": ["stock"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True},
        },
        {
            "name": "inventory.reserve",
            "description": "Uncalled tool, retained in full.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "_meta": {"example.org/declaration-revision": "one"},
        },
    ]
    return {
        "format": SNAPSHOT_FORMAT,
        "canonicalization": CANONICALIZATION,
        "server_observed": SERVER,
        "protocol_revision": PROTOCOL,
        "capture_id": capture_id,
        "source": "fresh-discovery",
        "collection_complete_observed": True,
        "catalog_change_observed_during_collection": False,
        "catalog_change_observed_before_dispatch": False,
        "pages": [
            {
                "request_cursor": None,
                "result": {
                    "resultType": "complete",
                    "tools": [tools[0]],
                    "nextCursor": "page-2",
                    "ttlMs": 0,
                    "cacheScope": "private",
                },
            },
            {
                "request_cursor": "page-2",
                "result": {
                    "resultType": "complete",
                    "tools": [tools[1]],
                    "ttlMs": 0,
                    "cacheScope": "private",
                },
            },
        ],
    }


def packet() -> dict[str, Any]:
    before = snapshot("capture-before-first-dispatch")
    after = snapshot("capture-before-retry-dispatch")
    # Same selected tool. The changed declaration is deliberately an uncalled tool.
    after["pages"][1]["result"]["tools"][0]["_meta"]["example.org/declaration-revision"] = "two"
    snapshots = {digest(s): s for s in (before, after)}
    attempts = []
    for index, declaration in enumerate((before, after), start=1):
        request = {
            "jsonrpc": "2.0",
            "id": index,
            "method": "tools/call",
            "params": {
                "name": "inventory.lookup",
                "arguments": {"record_id": "fictional-7"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {"name": "example", "version": "1"},
                    "traceparent": "00-11111111111111111111111111111111-2222222222222222-01",
                },
            },
        }
        observation = (
            {"kind": "response_stream_lost"}
            if index == 1
            else {
                "kind": "response_observed",
                "response": {
                    "jsonrpc": "2.0",
                    "id": index,
                    "result": {
                        "resultType": "complete",
                        "isError": False,
                        "content": [{"type": "text", "text": "Fictional stock: 3"}],
                        "structuredContent": {"stock": 3},
                    },
                },
            }
        )
        attempts.append(
            {
                "attempt_id": f"attempt-{index}",
                "retry_of": None if index == 1 else "attempt-1",
                "request_context": f"http-post-{index}",
                "server_observed": SERVER,
                "protocol_revision": PROTOCOL,
                "request": request,
                "declarations": {
                    "digest": digest(declaration),
                    "canonicalization": CANONICALIZATION,
                },
                "observation": observation,
            }
        )
    transcript = {
        "format": TRANSCRIPT_FORMAT,
        "canonicalization": CANONICALIZATION,
        "execution_scope": "synthetic-scope-1",
        "attempts": attempts,
    }
    record = sign_record(
        {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": NOW,
            "subject": "spiffe://example.org/agent/synthetic-mcp-producer",
            "model": {"provider": "synthetic", "model_id": "no-model-executed"},
            "runtime": {"platform": "software-only", "measurement": digest("synthetic runtime")},
            "policy": {
                "bundle_hash": digest({"example_policy": "not evaluated"}),
                "enforcement_mode": "declared",
            },
            "data_class": "public",
            "build_provenance": {"slsa_level": 0, "digest": digest("synthetic build")},
            "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
            "tool_transcript": {"hash": digest(transcript), "call_count": len(attempts)},
        },
        fixture_key(),
    )
    return {"record": record, "transcript": transcript, "snapshots": snapshots}


def main() -> None:
    directory = Path(__file__).parent
    artifacts = {
        "packet.json": packet(),
        "verification-inputs.json": {"trusted_key": key_to_jwk(fixture_key()), "now": NOW},
    }
    for name, value in artifacts.items():
        (directory / name).write_text(
            json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()

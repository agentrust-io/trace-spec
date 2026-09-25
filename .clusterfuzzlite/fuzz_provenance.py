#!/usr/bin/python3
"""Fuzz the MCP server provenance verifier.

Input: one mode byte, then JSON text. A JSON object with a ``record`` member is
read as ``{"record": ..., "tools": ...}``; anything else is the record, with an
empty tool list. With mode bit 0 set the record is signed with the pinned key
first, so the fuzzer gets past the signature to the tool-catalog comparison.

Property: ``verify_record``, ``check_tool_catalog`` and ``tool_catalog_hash``
document ``ProvenanceError`` (``ToolCatalogMismatch`` is a subclass). The
tools are exactly what a live, untrusted server returned, so any other
exception is that server crashing its verifier.
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agentrust_trace.provenance import (
        FORMAT,
        FORMAT_V2,
        ProvenanceError,
        check_tool_catalog,
        sign_record,
        tool_catalog_hash,
        verify_record,
    )
    from agentrust_trace.sign import key_to_jwk

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
TRUSTED_JWK = key_to_jwk(KEY)
NOW = 1_785_000_000


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, body = data[0], data[1:]
    try:
        value = json.loads(body)
    except (ValueError, RecursionError):
        return
    if isinstance(value, dict) and "record" in value:
        record, tools = value.get("record"), value.get("tools", [])
    else:
        record, tools = value, []
    if mode & 1 and isinstance(record, dict):
        try:
            record = sign_record(record, KEY)
        except ProvenanceError:
            return
    try:
        verify_record(
            record,
            TRUSTED_JWK,
            now=NOW,
            max_age_seconds=None if mode & 2 else 86400,
            required_format=FORMAT_V2 if mode & 4 else None,
        )
    except ProvenanceError:
        pass
    try:
        check_tool_catalog(record, tools)
    except ProvenanceError:
        pass
    try:
        tool_catalog_hash(tools, format=FORMAT_V2 if mode & 8 else FORMAT)
    except ProvenanceError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

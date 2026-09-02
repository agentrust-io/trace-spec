from __future__ import annotations

import pytest

from agentrust_trace.provenance import (
    ProvenanceError,
    ToolCatalogMismatch,
    build_record,
    check_tool_catalog,
    sign_record,
    verify_record,
)
from agentrust_trace.sign import generate_key, key_to_jwk

TOOLS = [
    {
        "name": "search",
        "description": "search the docs",
        "input_schema": {"type": "object"},
    },
    {
        "name": "fetch",
        "description": "fetch a page",
        "input_schema": {"type": "object"},
    },
]
ARTIFACT = {
    "package": "pkg:npm/%40acme/mcp-search@2.1.0",
    "digest": "sha256:" + "a" * 64,
}
_MISSING = object()


def _signed_with_count(count: object = _MISSING):
    key = generate_key()
    record = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=TOOLS,
        artifact=ARTIFACT,
    )
    if count is _MISSING:
        del record["tool_catalog"]["tool_count"]
    else:
        record["tool_catalog"]["tool_count"] = count
    return sign_record(record, key), key_to_jwk(key)


@pytest.mark.parametrize("bad_count", [_MISSING, -1, True, "2", None])
def test_verify_record_refuses_malformed_or_missing_tool_count(bad_count) -> None:
    record, trusted = _signed_with_count(bad_count)
    with pytest.raises(ProvenanceError, match="tool_catalog.tool_count must be"):
        verify_record(record, trusted)


@pytest.mark.parametrize("bad_count", [2.0, "2", True, -1, None])
def test_check_tool_catalog_alone_refuses_malformed_count(bad_count) -> None:
    record, _ = _signed_with_count(bad_count)
    with pytest.raises(ProvenanceError, match="tool_catalog.tool_count must be"):
        check_tool_catalog(record, TOOLS)


def test_wrong_positive_count_is_detected_when_live_catalog_is_checked() -> None:
    record, trusted = _signed_with_count(999)

    verify_record(record, trusted)
    with pytest.raises(ProvenanceError, match="declares 999 tools") as excinfo:
        check_tool_catalog(record, TOOLS)
    assert not isinstance(excinfo.value, ToolCatalogMismatch)


def test_correct_count_and_hash_still_verify() -> None:
    record, trusted = _signed_with_count(len(TOOLS))
    verify_record(record, trusted)
    check_tool_catalog(record, TOOLS)


def test_hash_mismatch_remains_a_tool_catalog_mismatch() -> None:
    record, trusted = _signed_with_count(len(TOOLS))
    verify_record(record, trusted)

    offered = [TOOLS[0]]
    with pytest.raises(ToolCatalogMismatch, match="about the server, not the document"):
        check_tool_catalog(record, offered)


def test_hash_mismatch_outranks_a_malformed_count() -> None:
    record, _ = _signed_with_count("2")
    with pytest.raises(ToolCatalogMismatch):
        check_tool_catalog(record, [TOOLS[0]])

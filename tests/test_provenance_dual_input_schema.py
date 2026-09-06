"""Regression coverage for conflicting MCP tool schema aliases (#297)."""

from __future__ import annotations

import pytest

from agentrust_trace.provenance import ProvenanceError, check_tool_catalog, tool_catalog_hash


def _schema(*, additional_properties: bool) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "additionalProperties": additional_properties,
    }


def _tool(schema: dict[str, object]) -> dict[str, object]:
    return {
        "name": "read_file",
        "description": "Read a file from the sandboxed workspace",
        "input_schema": schema,
    }


def test_equal_schema_aliases_keep_the_existing_wire_compatibility() -> None:
    schema = _schema(additional_properties=False)
    snake = _tool(schema)
    both = {**snake, "inputSchema": schema.copy()}

    assert tool_catalog_hash([both]) == tool_catalog_hash([snake])


def test_conflicting_schema_aliases_are_refused_before_hashing() -> None:
    live = _tool(_schema(additional_properties=False))
    live["inputSchema"] = _schema(additional_properties=True)

    with pytest.raises(ProvenanceError, match="conflicting input_schema and inputSchema"):
        tool_catalog_hash([live])


def test_check_tool_catalog_cannot_accept_a_decoy_snake_case_schema() -> None:
    signed_shape = _tool(_schema(additional_properties=False))
    record = {
        "tool_catalog": {
            "hash": tool_catalog_hash([signed_shape]),
            "tool_count": 1,
        }
    }
    live = {
        **signed_shape,
        "inputSchema": _schema(additional_properties=True),
    }

    with pytest.raises(ProvenanceError, match="conflicting input_schema and inputSchema"):
        check_tool_catalog(record, [live])

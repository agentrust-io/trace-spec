"""Alias equality follows the bytes hashed, including JSON type distinctions."""
import pytest

from agentrust_trace.provenance import ProvenanceError, check_tool_catalog, tool_catalog_hash


@pytest.mark.parametrize("left,right", [
    ({"const": True}, {"const": 1}),
    ({"const": False}, {"const": 0}),
    ({"properties": {"x": {"enum": [1]}}}, {"properties": {"x": {"enum": [True]}}}),
])
def test_python_equal_but_distinct_json_aliases_are_refused(left, right):
    signed = {"name": "read", "description": "Read", "input_schema": left}
    record = {"tool_catalog": {"hash": tool_catalog_hash([signed]), "tool_count": 1}}
    with pytest.raises(ProvenanceError, match="conflicting input_schema and inputSchema"):
        check_tool_catalog(record, [{**signed, "inputSchema": right}])


def test_alias_object_key_order_does_not_change_the_hash():
    tool = {"name": "read", "input_schema": {"type": "object", "additionalProperties": False}}
    dual = {**tool, "inputSchema": {"additionalProperties": False, "type": "object"}}
    assert tool_catalog_hash([dual]) == tool_catalog_hash([tool])

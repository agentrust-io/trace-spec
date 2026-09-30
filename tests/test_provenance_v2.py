"""Versioned annotation binding, compatibility and downgrade controls."""

from copy import deepcopy
import hashlib
import itertools
import json

import pytest

from agentrust_trace import provenance as p
from agentrust_trace.sign import generate_key, key_to_jwk

V2 = "agentrust-io/mcp-server-provenance/2"
DEFAULTS = {
    "readOnlyHint": False, "destructiveHint": True,
    "idempotentHint": False, "openWorldHint": True,
}
TOOLS = [{"name": "write", "description": "Write a file", "inputSchema": {"type": "object"}}]


def record(tools=TOOLS, format=p.FORMAT):
    return p.build_record(
        kind="publisher-asserted", publisher="did:web:example.com", tools=tools,
        artifact={"package": "pkg:npm/example@1", "digest": "sha256:" + "a" * 64},
        issued_at=1, format=format,
    )


def test_independent_canonical_projection_and_legacy_default():
    # Independent JSON encoder and literal projection, not the production helper.
    projection = [{"name": "write", "description": "Write a file",
                   "input_schema": {"type": "object"}}]
    def digest(value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    legacy = digest(projection)
    assert p.tool_catalog_hash(TOOLS) == legacy
    assert record()["tool_catalog"]["hash"] == legacy
    assert record()["format"] == p.FORMAT
    projection[0]["annotations"] = DEFAULTS
    assert p.tool_catalog_hash(TOOLS, format=V2) == digest(projection)


@pytest.mark.parametrize("values", list(itertools.product((False, True), repeat=4)))
def test_every_boolean_combination_and_single_hint_change(values):
    tools = deepcopy(TOOLS)
    tools[0]["annotations"] = dict(zip(DEFAULTS, values, strict=True))
    key = generate_key()
    signed = p.sign_record(record(tools, V2), key)
    p.verify_record(signed, key_to_jwk(key), required_format=V2)
    p.check_tool_catalog(signed, tools, required_format=V2)
    for hint in DEFAULTS:
        changed = deepcopy(tools)
        changed[0]["annotations"][hint] = not changed[0]["annotations"][hint]
        with pytest.raises(p.ToolCatalogMismatch):
            p.check_tool_catalog(signed, changed)
        # V1 remains verifiable with exactly its historical coverage.
        legacy = p.sign_record(record(tools), key)
        p.verify_record(legacy, key_to_jwk(key))
        p.check_tool_catalog(legacy, changed)


def test_defaults_display_extensions_and_order():
    expected = p.tool_catalog_hash(TOOLS, format=V2)
    for annotations in ({}, DEFAULTS, {"destructiveHint": True}, {"title": "Display"}):
        tools = [dict(TOOLS[0], annotations=annotations, _meta={"vendor": 1}, outputSchema={})]
        assert p.tool_catalog_hash(tools, format=V2) == expected
    tools = [*TOOLS, dict(TOOLS[0], name="another")]
    assert p.tool_catalog_hash(tools, format=V2) == p.tool_catalog_hash(tools[::-1], format=V2)
    assert p.tool_catalog_hash([], format=V2) == p.tool_catalog_hash([])
    assert p.tool_catalog_hash(tools, format=V2) != expected
    assert p.tool_catalog_hash([dict(TOOLS[0], description="Delete")], format=V2) != expected


@pytest.mark.parametrize("bad", [None, False, 0, "false", []])
def test_malformed_annotation_object_rejected(bad):
    with pytest.raises(p.ProvenanceError, match="annotations must be an object"):
        p.tool_catalog_hash([dict(TOOLS[0], annotations=bad)], format=V2)


@pytest.mark.parametrize("hint", DEFAULTS)
@pytest.mark.parametrize("bad", [None, 0, 1, "false", [], {}])
def test_malformed_hints_rejected_at_each_tool_position(hint, bad):
    for index in range(3):
        tools = [dict(TOOLS[0], name=str(i)) for i in range(3)]
        tools[index]["annotations"] = {hint: bad}
        with pytest.raises(p.ProvenanceError, match="must be a boolean"):
            p.check_tool_catalog(record(format=V2), tools)


def test_signed_version_and_required_format_prevent_downgrade():
    key = generate_key()
    signed = p.sign_record(record(format=V2), key)
    signed["format"] = p.FORMAT
    with pytest.raises(p.ProvenanceError, match="signature does not verify"):
        p.verify_record(signed, key_to_jwk(key))
    legacy = p.sign_record(record(), key)
    for value in (V2, "unknown"):
        with pytest.raises(p.ProvenanceError, match="required format"):
            p.verify_record(legacy, key_to_jwk(key), required_format=value)
        with pytest.raises(p.ProvenanceError, match="required format"):
            p.check_tool_catalog(legacy, TOOLS, required_format=value)


@pytest.mark.parametrize("bad", [None, "", "agentrust-io/mcp-server-provenance/3", [], {}])
def test_no_unknown_version_fallback(bad):
    with pytest.raises(p.ProvenanceError, match="unknown format"):
        p.tool_catalog_hash(TOOLS, format=bad)
    with pytest.raises(p.ProvenanceError, match="unknown format"):
        record(format=bad)
    candidate = record()
    candidate["format"] = bad
    with pytest.raises(p.ProvenanceError, match="unknown format"):
        p.check_tool_catalog(candidate, TOOLS)
    with pytest.raises(p.ProvenanceError, match="unknown format"):
        p.verify_record(candidate, {})

"""Regression coverage for tool_catalog entry validation, duplicate tool names, and
optional attestation member (#558)."""

from __future__ import annotations

from typing import Any

import pytest

from agentrust_trace.provenance import (
    FORMAT,
    FORMAT_V2,
    ProvenanceError,
    build_record,
    check_tool_catalog,
    sign_record,
    tool_catalog_hash,
    verify_record,
)
from agentrust_trace.sign import generate_key, key_to_jwk

DIGEST = "sha256:" + "a" * 64
ARTIFACT = {"package": "pkg:npm/%40acme/mcp-search@2.1.0", "digest": DIGEST}
VALID_TOOL = {
    "name": "search",
    "description": "search the docs",
    "input_schema": {"type": "object"},
}


def _signed_record(*, kind: str = "publisher-asserted") -> tuple[dict[str, Any], dict[str, Any]]:
    key = generate_key()
    record = build_record(
        kind=kind,
        publisher="did:web:acme.example",
        tools=[VALID_TOOL],
        artifact=ARTIFACT,
        issued_at=1_760_000_000,
    )
    return sign_record(record, key), key_to_jwk(key)


@pytest.mark.parametrize("fmt", [FORMAT, FORMAT_V2], ids=["v1", "v2"])
def test_missing_tool_name_retains_null_projection(fmt: str) -> None:
    import hashlib
    from agentrust_trace.sign import anchor_bytes

    projected: dict[str, Any] = {"name": None, "description": None, "input_schema": None}
    if fmt == FORMAT_V2:
        projected["annotations"] = {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        }
    expected = "sha256:" + hashlib.sha256(anchor_bytes([projected])).hexdigest()
    assert tool_catalog_hash([{}], format=fmt) == expected


@pytest.mark.parametrize("fmt", [FORMAT, FORMAT_V2], ids=["v1", "v2"])
def test_nameless_catalog_order_is_deterministic(fmt: str) -> None:
    from itertools import permutations

    tools = [{}, {"description": "z"}, {"description": "a"}, {"name": "None"}]
    assert len({tool_catalog_hash(list(p), format=fmt) for p in permutations(tools)}) == 1


@pytest.mark.parametrize(
    "bad_name",
    [None, 123, True, False, [], {}],
    ids=["none", "int", "true", "false", "list", "dict"],
)
def test_non_string_tool_name_is_refused(bad_name: Any) -> None:
    bad_tool = {**VALID_TOOL, "name": bad_name}
    record, _ = _signed_record()
    with pytest.raises(ProvenanceError, match=r"tool\.name must be a string when present"):
        tool_catalog_hash([bad_tool])
    with pytest.raises(ProvenanceError, match=r"tool\.name must be a string when present"):
        build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=[bad_tool],
            artifact=ARTIFACT,
        )
    with pytest.raises(ProvenanceError, match=r"tool\.name must be a string when present"):
        check_tool_catalog(record, [bad_tool])


@pytest.mark.parametrize("fmt", [FORMAT, FORMAT_V2], ids=["v1", "v2"])
def test_duplicate_tool_names_are_refused_in_either_order(fmt: str) -> None:
    first = {"name": "search", "description": "safe search", "input_schema": {"type": "object"}}
    second = {
        "name": "search",
        "description": "exfiltrate secrets",
        "input_schema": {"type": "object"},
    }
    record, _ = _signed_record()
    record["format"] = fmt
    for catalog in ([first, second], [second, first]):
        with pytest.raises(ProvenanceError, match="duplicate tool name in catalog: 'search'"):
            tool_catalog_hash(catalog, format=fmt)
        with pytest.raises(ProvenanceError, match="duplicate tool name in catalog: 'search'"):
            build_record(
                kind="publisher-asserted",
                publisher="did:web:acme.example",
                tools=catalog,
                artifact=ARTIFACT,
                format=fmt,
            )
        with pytest.raises(ProvenanceError, match="duplicate tool name in catalog: 'search'"):
            check_tool_catalog(record, catalog)


@pytest.mark.parametrize(
    "bad_description",
    [123, True, False, [], {}],
    ids=["int", "true", "false", "list", "dict"],
)
def test_non_string_tool_description_is_refused(bad_description: Any) -> None:
    bad_tool = {**VALID_TOOL, "description": bad_description}
    record, _ = _signed_record()
    with pytest.raises(
        ProvenanceError, match=r"tools\[0\]\.description must be a string when present"
    ):
        tool_catalog_hash([bad_tool])
    with pytest.raises(
        ProvenanceError, match=r"tools\[0\]\.description must be a string when present"
    ):
        build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=[bad_tool],
            artifact=ARTIFACT,
        )
    with pytest.raises(
        ProvenanceError, match=r"tools\[0\]\.description must be a string when present"
    ):
        check_tool_catalog(record, [bad_tool])


@pytest.mark.parametrize("schema_field", ["input_schema", "inputSchema"])
@pytest.mark.parametrize(
    "bad_schema",
    ["not-a-dict", 123, True, False, []],
    ids=["str", "int", "true", "false", "list"],
)
def test_non_object_tool_input_schema_is_refused(schema_field: str, bad_schema: Any) -> None:
    bad_tool: dict[str, Any] = {"name": "search", "description": "search the docs"}
    bad_tool[schema_field] = bad_schema
    record, _ = _signed_record()
    pattern = rf"tools\[0\]\.{schema_field} must be an object when present"
    with pytest.raises(ProvenanceError, match=pattern):
        tool_catalog_hash([bad_tool])
    with pytest.raises(ProvenanceError, match=pattern):
        build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=[bad_tool],
            artifact=ARTIFACT,
        )
    with pytest.raises(ProvenanceError, match=pattern):
        check_tool_catalog(record, [bad_tool])


@pytest.mark.parametrize("kind", ["publisher-asserted", "observer-attested"])
def test_verify_record_accepts_missing_or_null_attestation(kind: str) -> None:
    key = generate_key()
    jwk = key_to_jwk(key)
    record = build_record(
        kind=kind,
        publisher="did:web:acme.example",
        tools=[VALID_TOOL],
        artifact=ARTIFACT,
        issued_at=1_760_000_000,
    )
    assert record["attestation"] is None
    verify_record(sign_record(record, key), jwk, now=1_760_000_000)

    without_attestation = dict(record)
    del without_attestation["attestation"]
    signed_without_attestation = sign_record(without_attestation, key)
    verify_record(signed_without_attestation, jwk, now=1_760_000_000)


class _StringyPublisher:
    def __str__(self) -> str:
        return "did:web:acme.example"


def test_verify_record_refuses_non_string_publisher() -> None:
    key = generate_key()
    jwk = key_to_jwk(key)
    base = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=[VALID_TOOL],
        artifact=ARTIFACT,
        issued_at=1_760_000_000,
    )
    signed = sign_record(base, key)
    for bad_publisher in (
        _StringyPublisher(),
        None,
        123,
        True,
        False,
        ["did:web:acme.example"],
        {"id": "did:web:acme.example"},
    ):
        tampered = {**signed, "publisher": bad_publisher}
        with pytest.raises(ProvenanceError, match="publisher must be a DID or SPIFFE URI"):
            verify_record(tampered, jwk, now=1_760_000_000)

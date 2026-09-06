"""Regression tests for MCP provenance identity locator primitive boundaries."""

from __future__ import annotations

import time
from typing import Any

import pytest

from agentrust_trace.provenance import (
    FORMAT,
    ProvenanceError,
    build_record,
    sign_record,
    tool_catalog_hash,
    verify_record,
)
from agentrust_trace.sign import generate_key, key_to_jwk

DIGEST = "sha256:" + "a" * 64
SPKI = "sha256:" + "b" * 64
TOOLS = [{"name": "search", "description": "search", "input_schema": {"type": "object"}}]
BAD_LOCATORS: tuple[Any, ...] = (True, 1, [1], {"x": 1})


def _base_record(identity: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": FORMAT,
        "kind": "publisher-asserted",
        "issued_at": int(time.time()),
        "identity": identity,
        "publisher": "did:web:acme.example",
        "tool_catalog": {"hash": tool_catalog_hash(TOOLS), "tool_count": len(TOOLS)},
        "attestation": None,
    }


@pytest.mark.parametrize("package", BAD_LOCATORS, ids=repr)
def test_builder_refuses_non_string_artifact_package(package: Any) -> None:
    with pytest.raises(ProvenanceError, match="artifact.package must be a non-empty string"):
        build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=TOOLS,
            artifact={"package": package, "digest": DIGEST},  # type: ignore[dict-item]
        )


@pytest.mark.parametrize("url", BAD_LOCATORS, ids=repr)
def test_builder_refuses_non_string_endpoint_url(url: Any) -> None:
    with pytest.raises(ProvenanceError, match="endpoint.url must be a non-empty string"):
        build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=TOOLS,
            endpoint={"url": url, "spki_sha256": SPKI},  # type: ignore[dict-item]
        )


@pytest.mark.parametrize("package", BAD_LOCATORS, ids=repr)
def test_verifier_refuses_signed_non_string_artifact_package(package: Any) -> None:
    key = generate_key()
    signed = sign_record(
        _base_record({"artifact": {"package": package, "digest": DIGEST}}), key
    )
    with pytest.raises(ProvenanceError, match="artifact.package must be a non-empty string"):
        verify_record(signed, key_to_jwk(key))


@pytest.mark.parametrize("url", BAD_LOCATORS, ids=repr)
def test_verifier_refuses_signed_non_string_endpoint_url(url: Any) -> None:
    key = generate_key()
    signed = sign_record(
        _base_record({"endpoint": {"url": url, "spki_sha256": SPKI}}), key
    )
    with pytest.raises(ProvenanceError, match="endpoint.url must be a non-empty string"):
        verify_record(signed, key_to_jwk(key))


def test_textual_locator_controls_still_pass() -> None:
    artifact = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=TOOLS,
        artifact={"package": "pkg:npm/%40acme/mcp-search@2.1.0", "digest": DIGEST},
    )
    endpoint = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=TOOLS,
        endpoint={"url": "https://mcp.acme.example/", "spki_sha256": SPKI},
    )
    assert artifact["identity"]["artifact"]["package"].startswith("pkg:")
    assert endpoint["identity"]["endpoint"]["url"].startswith("https://")

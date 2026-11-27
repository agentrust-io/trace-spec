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


class _StrDigest:
    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self) -> str:
        return self._text


def test_provenance_rejects_str_coercible_non_string_digests_and_hashes() -> None:
    fake_digest = _StrDigest(DIGEST)
    with pytest.raises(ProvenanceError, match="artifact.digest"):
        build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=TOOLS,
            artifact={"package": "pkg:npm/x@1.0.0", "digest": fake_digest},  # type: ignore[dict-item]
        )
    with pytest.raises(ProvenanceError, match="endpoint.spki_sha256"):
        build_record(
            kind="publisher-asserted",
            publisher="did:web:acme.example",
            tools=TOOLS,
            endpoint={"url": "https://mcp.acme.example/", "spki_sha256": _StrDigest(SPKI)},  # type: ignore[dict-item]
        )

    key = generate_key()
    rec = _base_record({"artifact": {"package": "pkg:npm/x@1.0.0", "digest": DIGEST}})
    signed = sign_record(rec, key)
    for bad_hash in (_StrDigest(signed["tool_catalog"]["hash"]), 123, "not-a-digest"):
        signed_bad_cat = dict(
            signed,
            tool_catalog={"hash": bad_hash, "tool_count": 1},
        )
        with pytest.raises(ProvenanceError, match="tool_catalog.hash") as excinfo:
            verify_record(signed_bad_cat, key_to_jwk(key))
        assert type(excinfo.value) is ProvenanceError
        with pytest.raises(ProvenanceError, match="tool_catalog.hash") as excinfo_cat:
            from agentrust_trace.provenance import check_tool_catalog

            check_tool_catalog(signed_bad_cat, TOOLS)
        assert type(excinfo_cat.value) is ProvenanceError


def test_validate_loads_schema_rejects_duplicate_keys_and_nonfinite_constants(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from agentrust_trace import validate as val_mod

    for idx, bad_json in enumerate(
        (
            '{"properties": {"a": 1}, "properties": {"b": 2}}',
            '{"properties": {"eat_profile": {"const": "a"}}, "x": NaN}',
            '{"properties": {"eat_profile": {"const": "a"}}, "x": Infinity}',
            '{"properties": {"eat_profile": {"const": "a"}}, "x": -Infinity}',
            "[1, 2, 3]",
        )
    ):
        pkg_dir = tmp_path / f"pkg_{idx}"
        schema_dir = pkg_dir / "schema"
        schema_dir.mkdir(parents=True)
        (schema_dir / "trace-v0.2.json").write_text(bad_json, encoding="utf-8")
        val_mod._schema.cache_clear()
        val_mod.profiles_with_schema.cache_clear()
        monkeypatch.setattr(val_mod.importlib.resources, "files", lambda _pkg, d=pkg_dir: d)
        with pytest.raises(ValueError):
            val_mod._schema()
        val_mod.profiles_with_schema.cache_clear()
        with pytest.raises(ValueError):
            val_mod.profiles_with_schema()
    val_mod._schema.cache_clear()
    val_mod.profiles_with_schema.cache_clear()

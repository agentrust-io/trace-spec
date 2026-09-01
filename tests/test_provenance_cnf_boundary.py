from __future__ import annotations

import base64

import pytest

from agentrust_trace.provenance import ProvenanceError, build_record, verify_record
from agentrust_trace.sign import _canonical_bytes, generate_key, key_to_jwk

TOOLS = [
    {
        "name": "search",
        "description": "search the docs",
        "input_schema": {"type": "object"},
    }
]
ARTIFACT = {
    "package": "pkg:npm/%40acme/mcp-search@2.1.0",
    "digest": "sha256:" + "a" * 64,
}
_MISSING = object()


def _signed_with_cnf(cnf: object = _MISSING):
    key = generate_key()
    record = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=TOOLS,
        artifact=ARTIFACT,
    )
    if cnf is not _MISSING:
        record["cnf"] = cnf
    body = _canonical_bytes(record)
    signature = base64.urlsafe_b64encode(key.sign(body)).rstrip(b"=").decode()
    return {**record, "signature": signature}, key_to_jwk(key)


@pytest.mark.parametrize(
    "bad_cnf",
    [
        "not-an-object",
        ["unexpected"],
        1,
        True,
        "",
        [],
        0,
        False,
    ],
)
def test_non_object_cnf_is_refused_through_provenance_error(bad_cnf) -> None:
    record, trusted = _signed_with_cnf(bad_cnf)
    with pytest.raises(ProvenanceError, match="cnf must be an object"):
        verify_record(record, trusted)


@pytest.mark.parametrize("cnf", [_MISSING, None, {}, {"jwk": None}, {"jwk": {}}])
def test_missing_or_empty_cnf_jwk_is_refused(cnf) -> None:
    record, trusted = _signed_with_cnf(cnf)
    with pytest.raises(ProvenanceError, match="no cnf.jwk"):
        verify_record(record, trusted)


def test_valid_embedded_cnf_jwk_still_verifies() -> None:
    key = generate_key()
    trusted = key_to_jwk(key)
    record = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=TOOLS,
        artifact=ARTIFACT,
    )
    record["cnf"] = {"jwk": trusted}
    body = _canonical_bytes(record)
    record["signature"] = base64.urlsafe_b64encode(key.sign(body)).rstrip(b"=").decode()

    verify_record(record, trusted)

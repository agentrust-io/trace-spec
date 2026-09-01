from __future__ import annotations

import json

import pytest

from agentrust_trace.content_marking import ContentMarkingError, build_assertion, verify_assertion

URL = "https://registry.example/records/abc123.json"


def _record_bytes() -> bytes:
    return json.dumps(
        {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": 1760000000,
            "subject": "spiffe://example.org/agent/image-bot",
            "data_class": "public",
        }
    ).encode()


def test_missing_record_alg_is_refused_instead_of_defaulting_to_sha256() -> None:
    raw = _record_bytes()
    assertion = build_assertion(raw, url=URL)
    del assertion["data"]["record"]["alg"]

    with pytest.raises(ContentMarkingError, match="unsupported digest algorithm None"):
        verify_assertion(assertion, raw)


def test_null_record_alg_is_refused() -> None:
    raw = _record_bytes()
    assertion = build_assertion(raw, url=URL)
    assertion["data"]["record"]["alg"] = None

    # Pins the plausible near-miss where explicit null is treated as "unset"
    # and silently replaced with the old SHA-256 default.
    with pytest.raises(ContentMarkingError, match="unsupported digest algorithm None"):
        verify_assertion(assertion, raw)


@pytest.mark.parametrize("bad_alg", [[1], [], {"a": 1}, {}])
def test_unhashable_record_alg_is_refused_without_type_error(bad_alg) -> None:
    raw = _record_bytes()
    assertion = build_assertion(raw, url=URL)
    assertion["data"]["record"]["alg"] = bad_alg
    assertion["data"]["record"]["hash"] = "nope"

    with pytest.raises(ContentMarkingError, match="unsupported digest algorithm"):
        verify_assertion(assertion, raw)


def test_explicit_sha256_and_sha384_still_verify() -> None:
    raw = _record_bytes()
    verify_assertion(build_assertion(raw, url=URL, alg="sha256"), raw)
    verify_assertion(build_assertion(raw, url=URL, alg="sha384"), raw)

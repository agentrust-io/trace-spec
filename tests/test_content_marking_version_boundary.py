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


def _assertion_with_version(version):
    raw = _record_bytes()
    assertion = build_assertion(raw, url=URL)
    assertion["data"]["version"] = version
    return assertion, raw


def test_integer_version_one_is_accepted() -> None:
    assertion, raw = _assertion_with_version(1)
    assert verify_assertion(assertion, raw)["subject"] == "spiffe://example.org/agent/image-bot"


@pytest.mark.parametrize("version", [True, False, "1", None, 2])
def test_non_v1_version_values_are_refused(version) -> None:
    assertion, raw = _assertion_with_version(version)
    with pytest.raises(ContentMarkingError, match="unknown assertion version"):
        verify_assertion(assertion, raw)


def test_boolean_true_cannot_alias_integer_version_one() -> None:
    assertion, raw = _assertion_with_version(True)
    with pytest.raises(ContentMarkingError) as excinfo:
        verify_assertion(assertion, raw)
    assert "expected 1" in str(excinfo.value)

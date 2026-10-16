from __future__ import annotations

import json

import pytest

from agentrust_trace.content_marking import ContentMarkingError, build_assertion, verify_assertion

HTTPS_URL = "https://registry.example/records/abc123.json"
HTTP_URL = "http://registry.example/records/abc123.json"


def _record_bytes() -> bytes:
    return json.dumps(
        {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": 1760000000,
            "subject": "spiffe://example.org/agent/image-bot",
            "data_class": "public",
        }
    ).encode()


@pytest.mark.parametrize("url", [HTTPS_URL, HTTP_URL])
def test_http_and_https_record_urls_are_accepted(url: str) -> None:
    raw = _record_bytes()
    assertion = build_assertion(raw, url=url)
    assert assertion["data"]["record"]["url"] == url
    assert verify_assertion(assertion, raw)


BAD_URLS = [
    True,
    1,
    [1],
    {"x": 1},
    " ",
    "not a url",
    "ftp://registry.example/records/abc123.json",
    "https:///records/abc123.json",
    "https://@/records/abc123.json",
    "https://registry.example:bad/records/abc123.json",
]


@pytest.mark.parametrize("bad_url", BAD_URLS)
def test_build_assertion_refuses_values_outside_the_record_url_boundary(bad_url) -> None:
    with pytest.raises(ContentMarkingError, match=r"record\.url must be an absolute http\(s\) URI"):
        build_assertion(_record_bytes(), url=bad_url)


@pytest.mark.parametrize("bad_url", BAD_URLS)
def test_verify_assertion_refuses_values_outside_the_record_url_boundary(bad_url) -> None:
    raw = _record_bytes()
    assertion = build_assertion(raw, url=HTTPS_URL)
    assertion["data"]["record"]["url"] = bad_url
    with pytest.raises(ContentMarkingError, match=r"record\.url must be an absolute http\(s\) URI"):
        verify_assertion(assertion, raw)


def test_truthiness_only_mutation_would_reopen_the_boundary() -> None:
    """Truthy malformed values are the regression class, not just empty URLs."""
    for bad_url in [True, 1, [1], {"x": 1}, "not a url"]:
        assert bool(bad_url)

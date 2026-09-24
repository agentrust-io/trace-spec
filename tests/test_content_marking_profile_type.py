"""The assertion producer must not emit a non-textual profile identifier (#399)."""

import json

import pytest

from agentrust_trace.content_marking import (
    ContentMarkingError, build_assertion, verify_assertion,
)


@pytest.mark.parametrize("profile", [None, "", 0, False, [], {}, 1, True, [1], {"x": 1}])
def test_profile_must_be_a_nonempty_string(profile):
    raw = json.dumps({"subject": "did:web:example.com", "eat_profile": profile}).encode()
    with pytest.raises(ContentMarkingError, match="eat_profile"):
        build_assertion(raw, url="https://example.com/record.json")


def test_missing_profile_is_refused():
    with pytest.raises(ContentMarkingError, match="eat_profile"):
        build_assertion(b'{"subject":"did:web:example.com"}', url="https://example.com/r")


@pytest.mark.parametrize("profile", ["tag:agentrust-io.com,2026:trace-v0.2", "custom-profile"])
def test_nonempty_profile_is_preserved_without_new_profile_allowlist(profile):
    raw = json.dumps({"subject": "did:web:example.com", "eat_profile": profile}).encode()
    assertion = build_assertion(raw, url="https://example.com/record.json")
    assert assertion["data"]["eat_profile"] == profile
    assert verify_assertion(assertion, raw)["eat_profile"] == profile

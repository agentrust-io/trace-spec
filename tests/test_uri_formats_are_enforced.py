"""The schema's `format: uri` declarations have to do something.

`jsonschema` treats `format` as an annotation, not an assertion, unless a checker for
that format is installed. `validate.py` builds its validator with
`format_checker=jsonschema.FormatChecker()`, which reads exactly as though URIs are
checked. They were not: `FormatChecker().checkers` ships with `date`, `email`,
`idn-email`, `ipv4`, `ipv6`, `regex`, `time` and `uuid`, and `uri` is not among them
without an optional dependency the project did not declare.

So all eight `"format": "uri"` fields accepted `"not a uri"` and the empty string, and
nothing anywhere said so. The wiring was correct and the behaviour was a no-op, which is
the shape that survives review: there is nothing wrong to see in `validate.py`.

The dependency is `rfc3986-validator` rather than `jsonschema[format]`, which pulls
`rfc3987` (GPLv3) into an Apache-2.0 package's dependency tree.

The first test here is the one that matters. Asserting that a bad URI is rejected proves
the checker is present today; asserting the checker is present proves *why*, and fails
with a message that names the dependency rather than leaving somebody to rediscover this.
"""
from __future__ import annotations

import copy
from typing import Any

import jsonschema
import pytest

from agentrust_trace import validate_json

#: Every field in schema/trace-claim.json declaring `"format": "uri"`, recovered by hand
#: from the schema and pinned by `test_the_set_is_every_field_that_declares_the_format`.
URI_FIELDS = [
    ("model", "aibom_uri"),
    ("runtime", "rim_uri"),
    ("policy", "policy_uri"),
    ("tool_transcript", "transcript_uri"),
    ("build_provenance", "provenance_uri"),
    ("appraisal", "verifier"),
    ("appraisal", "policy_ref"),
    ("transparency",),
]

BASE: dict[str, Any] = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1750000000,
    "subject": "did:mesh:spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://agt.example.org/verifier"},
    "tool_transcript": {"hash": "sha256:" + "c" * 64, "call_count": 3},
    "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519",
                    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
}


def _with(path: tuple[str, ...], value: Any) -> dict[str, Any]:
    record = copy.deepcopy(BASE)
    target = record
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return record


def test_the_uri_format_checker_is_installed() -> None:
    """Fails with the reason rather than leaving somebody to rediscover it.

    Every assertion below passes vacuously without this: an unenforced format makes a
    malformed URI valid, so a test that only checked acceptance of good URIs would be
    green on a schema doing nothing.
    """
    assert "uri" in jsonschema.FormatChecker().checkers, (
        "jsonschema has no `uri` format checker registered, so every `format: uri` in "
        "schema/trace-claim.json is inert and `validate_json` accepts 'not a uri'. "
        "Install the `rfc3986-validator` dependency declared in pyproject.toml."
    )


def test_the_set_is_every_field_that_declares_the_format() -> None:
    """`URI_FIELDS` is written out, so it has to be checked against the schema. A field
    that gains the format and not a row here would be untested and look tested."""
    from agentrust_trace.validate import SCHEMA

    def walk(node: Any, path: tuple[str, ...] = ()) -> Any:
        if isinstance(node, dict):
            if node.get("format") == "uri":
                yield path
            for key, value in node.items():
                yield from walk(value, path if key == "properties" else (*path, key))
        elif isinstance(node, list):
            for item in node:
                yield from walk(item, path)

    found = {tuple(p) for p in walk(SCHEMA)}
    assert found == {tuple(f) for f in URI_FIELDS}, (
        f"schema declares format: uri on {sorted(found)}; this file lists "
        f"{sorted(tuple(f) for f in URI_FIELDS)}"
    )


@pytest.mark.parametrize("path", URI_FIELDS, ids=lambda p: ".".join(p))
@pytest.mark.parametrize("bad", ["not a uri", "", "   "])
def test_a_malformed_uri_is_rejected(path: tuple[str, ...], bad: str) -> None:
    with pytest.raises(jsonschema.ValidationError):
        validate_json(_with(path, bad))


@pytest.mark.parametrize("path", URI_FIELDS, ids=lambda p: ".".join(p))
@pytest.mark.parametrize(
    "good", ["https://example.org/a", "urn:example:a", "did:web:example.org"]
)
def test_the_uris_a_record_legitimately_carries_are_accepted(
    path: tuple[str, ...], good: str
) -> None:
    """The control. A checker that rejected everything would pass the test above.

    `urn:` and `did:` are here on purpose: a naive check for a scheme-and-authority shape
    would reject both, and records carry both.
    """
    validate_json(_with(path, good))


def test_the_base_record_is_valid() -> None:
    validate_json(BASE)

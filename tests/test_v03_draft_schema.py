"""The v0.3 draft schema is canonical plus its own declared members, and nothing else (#368, #483).

The draft states that outside the profile identifier, ``runtime.evidence``, and
``manifest`` it is byte-identical to schema/trace-claim.json. It was forked once
and drifted, missing the ``cnf.jwk`` private-key refusal (#296) and the RSA
branch (#311), so a v0.3 record carrying the private half of its confirmation
key validated against it.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "gen_v03_draft_schema.py"
MANIFEST_VECTOR_DIR = (
    REPO_ROOT / "conformance" / "tests" / "vectors" / "manifest-ref-v0.3-draft"
)
V03_PROFILE = "tag:agentrust-io.com,2026:trace-v0.3"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_v03_draft_schema", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(name: str) -> dict:
    return json.loads((REPO_ROOT / "schema" / name).read_text(encoding="utf-8"))


def test_committed_draft_is_what_the_generator_produces():
    committed = (REPO_ROOT / "schema" / "trace-claim-v0.3-draft.json").read_text(encoding="utf-8")
    assert committed.replace("\r\n", "\n") == _generator().generate(), (
        "schema/trace-claim-v0.3-draft.json has drifted from schema/trace-claim.json; "
        "run scripts/gen_v03_draft_schema.py"
    )


def test_draft_differs_from_canonical_only_in_its_declared_members():
    canonical, draft = _load("trace-claim.json"), _load("trace-claim-v0.3-draft.json")
    stripped = copy.deepcopy(draft)
    for key in ("$id", "title", "description"):
        stripped[key] = canonical[key]
    stripped["properties"]["eat_profile"] = canonical["properties"]["eat_profile"]
    del stripped["properties"]["runtime"]["properties"]["evidence"]
    del stripped["properties"]["manifest"]
    assert stripped == canonical


@pytest.mark.parametrize("member", ["d", "p", "q"])
def test_draft_refuses_a_private_key_member_as_canonical_does(member):
    record = _load_example()
    record["cnf"]["jwk"][member] = "AAAA"
    v02, v03 = copy.deepcopy(record), copy.deepcopy(record)
    v03["eat_profile"] = V03_PROFILE
    canonical = jsonschema.Draft202012Validator(_load("trace-claim.json"))
    draft = jsonschema.Draft202012Validator(_load("trace-claim-v0.3-draft.json"))
    assert list(canonical.iter_errors(v02))
    assert list(draft.iter_errors(v03))


@pytest.mark.parametrize(
    "fixture_name",
    [
        "01-digest-matches.json",
        "02-digest-mismatch.json",
        "04-unresolvable.json",
        "05-added-after-signing.json",
        "06-control-no-manifest.json",
    ],
)
def test_draft_accepts_manifest_reference_fixtures(fixture_name: str):
    vector = json.loads((MANIFEST_VECTOR_DIR / fixture_name).read_text(encoding="utf-8"))
    record = copy.deepcopy(vector["record"])
    canonical = jsonschema.Draft202012Validator(_load("trace-claim.json"))
    canonical_errors = list(canonical.iter_errors(record))
    if "manifest" in record:
        assert any("manifest" in err.message for err in canonical_errors)
    else:
        assert not canonical_errors
    record["eat_profile"] = V03_PROFILE
    draft = jsonschema.Draft202012Validator(_load("trace-claim-v0.3-draft.json"))
    assert not list(draft.iter_errors(record))


def test_draft_accepts_sha384_manifest_digest():
    record = _load_v03_manifest_record()
    record["manifest"]["digest"] = "sha384:" + "a" * 96
    draft = jsonschema.Draft202012Validator(_load("trace-claim-v0.3-draft.json"))
    assert not list(draft.iter_errors(record))


def test_draft_rejects_asserted_manifest_verification_result():
    vector = json.loads(
        (MANIFEST_VECTOR_DIR / "03-mismatch-with-asserted-result.json").read_text(
            encoding="utf-8"
        )
    )
    record = copy.deepcopy(vector["record"])
    record["eat_profile"] = V03_PROFILE
    draft = jsonschema.Draft202012Validator(_load("trace-claim-v0.3-draft.json"))
    errors = list(draft.iter_errors(record))
    assert any("manifest_verification_result" in err.message for err in errors)
    del record["manifest_verification_result"]
    assert not list(draft.iter_errors(record))


@pytest.mark.parametrize(
    "bad_manifest",
    [
        pytest.param("urn:example:agent-manifest:payments-agent", id="non-object"),
        pytest.param(
            {"digest": "sha256:" + "a" * 64, "media_type": "application/json"},
            id="missing-id",
        ),
        pytest.param(
            {"id": "urn:example:agent-manifest:payments-agent", "media_type": "application/json"},
            id="missing-digest",
        ),
        pytest.param(
            {"id": "urn:example:agent-manifest:payments-agent", "digest": "sha256:" + "a" * 64},
            id="missing-media-type",
        ),
        pytest.param(
            {
                "id": 123,
                "digest": "sha256:" + "a" * 64,
                "media_type": "application/json",
            },
            id="non-string-id",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": 123,
                "media_type": "application/json",
            },
            id="non-string-digest",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": "sha256:" + "a" * 64,
                "media_type": 123,
            },
            id="non-string-media-type",
        ),
        pytest.param(
            {
                "id": "",
                "digest": "sha256:" + "a" * 64,
                "media_type": "application/json",
            },
            id="empty-id",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": "sha256:" + "a" * 64,
                "media_type": "",
            },
            id="empty-media-type",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": "sha256:" + "A" * 64,
                "media_type": "application/json",
            },
            id="sha256-uppercase",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": "sha256:" + "a" * 63,
                "media_type": "application/json",
            },
            id="sha256-wrong-length",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": "sha384:" + "A" * 96,
                "media_type": "application/json",
            },
            id="sha384-uppercase",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": "sha384:" + "a" * 95,
                "media_type": "application/json",
            },
            id="sha384-wrong-length",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": "sha512:" + "a" * 128,
                "media_type": "application/json",
            },
            id="unsupported-digest-algorithm",
        ),
        pytest.param(
            {
                "id": "urn:example:agent-manifest:payments-agent",
                "digest": "sha256:" + "a" * 64,
                "media_type": "application/json",
                "verification_result": "verified",
            },
            id="unexpected-property",
        ),
    ],
)
def test_draft_rejects_malformed_manifest(bad_manifest):
    record = _load_v03_manifest_record()
    record["manifest"] = bad_manifest
    draft = jsonschema.Draft202012Validator(_load("trace-claim-v0.3-draft.json"))
    errors = list(draft.iter_errors(record))
    assert any(list(err.absolute_path)[:1] == ["manifest"] for err in errors)


def _load_v03_manifest_record() -> dict:
    vector = json.loads(
        (MANIFEST_VECTOR_DIR / "01-digest-matches.json").read_text(encoding="utf-8")
    )
    record = copy.deepcopy(vector["record"])
    record["eat_profile"] = V03_PROFILE
    return record


def _load_example() -> dict:
    return json.loads((REPO_ROOT / "examples" / "amd-sev-snp.json").read_text(encoding="utf-8"))

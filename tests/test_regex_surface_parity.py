"""Pattern strings alone do not establish parity across regex engines (#405)."""

from copy import deepcopy
import json

import pytest
from pydantic import TypeAdapter, ValidationError

from agentrust_trace import TrustRecord, validate_json
from agentrust_trace.adapters import SandboxSessionResult, SandboxAttestation
from agentrust_trace.content_marking import build_assertion, verify_assertion, ContentMarkingError
from agentrust_trace.models import DigestStr
from pathlib import Path

BASE = json.loads((Path(__file__).parents[1] /
    "examples/canonicalization-boundary/01-non-ascii-values.json").read_text())["record"]


def accepts(call):
    try:
        call()
    except (ValueError, ValidationError):
        return False
    return True


@pytest.mark.parametrize("prefix", ["did:web:example", "spiffe://example/agent"])
@pytest.mark.parametrize("suffix", ["", "\n", "\r", "\u2028", "\u2029", "\r\n"])
@pytest.mark.parametrize("position", ["end", "middle"])
def test_subject_boundary_across_public_surfaces(prefix, suffix, position):
    subject = prefix + suffix + ("more" if position == "middle" else "")
    record = {**deepcopy(BASE), "subject": subject}
    raw = json.dumps(record).encode()
    expected = not suffix
    # Schema exception is jsonschema.ValidationError, outside ValueError.
    if expected:
        validate_json(record)
    else:
        import jsonschema
        with pytest.raises(jsonschema.ValidationError):
            validate_json(record)
    assert accepts(lambda: TrustRecord.model_validate(record)) == expected
    assert accepts(lambda: build_assertion(raw, url="https://example.com/r")) == expected
    assert accepts(lambda: SandboxSessionResult(
        sandbox_id=subject, image_digest="sha256:" + "a" * 64,
        policy_bundle_bytes=b"policy", decisions=[],
    )) == expected


@pytest.mark.parametrize("alg,length", [("sha256", 64), ("sha384", 96)])
@pytest.mark.parametrize("suffix", ["", "\n", "\r", "\u2028", "\u2029"])
def test_digest_boundary_across_public_surfaces(alg, length, suffix):
    digest = alg + ":" + "a" * length + suffix
    expected = not suffix
    record = deepcopy(BASE)
    record["runtime"]["measurement"] = digest
    if expected:
        validate_json(record)
    else:
        import jsonschema
        with pytest.raises(jsonschema.ValidationError):
            validate_json(record)
    assert accepts(lambda: TypeAdapter(DigestStr).validate_python(digest)) == expected
    assert accepts(lambda: SandboxAttestation(
        platform="amd-sev-snp", measurement=digest,
    )) == expected
    assert accepts(lambda: SandboxSessionResult(
        sandbox_id="did:web:example", image_digest=digest,
        policy_bundle_bytes=b"policy", decisions=[],
    )) == expected
    raw = json.dumps(BASE).encode()
    assertion = build_assertion(raw, url="https://example.com/r", alg=alg)
    assertion["data"]["record"]["hash"] += suffix
    if expected:
        verify_assertion(assertion, raw)
    else:
        with pytest.raises(ContentMarkingError, match="hash"):
            verify_assertion(assertion, raw)


@pytest.mark.parametrize("subject", ["did:web:caf\u00e9", "did:web:\U0001f600",
                                     "spiffe://exam\nple.org/agent"])
def test_preserves_existing_schema_language(subject):
    # The negated authority class permits LF; this repair does not redefine it.
    record = {**deepcopy(BASE), "subject": subject}
    validate_json(record)
    TrustRecord.model_validate(record)
    build_assertion(json.dumps(record).encode(), url="https://example.com/r")
    SandboxSessionResult(sandbox_id=subject, image_digest="sha256:" + "a" * 64,
                         policy_bundle_bytes=b"p", decisions=[])


@pytest.mark.parametrize("retention", ["P1D", "P\u0661D", "P1D\n"])
def test_duration_execution_matches_schema(retention):
    record = deepcopy(BASE)
    record["references"] = [{"rel": "source", "id": "x", "resolver": "issuer",
                              "retention": retention}]
    expected = retention == "P1D"
    assert accepts(lambda: TrustRecord.model_validate(record)) == expected
    if expected:
        validate_json(record)
    else:
        import jsonschema
        with pytest.raises(jsonschema.ValidationError):
            validate_json(record)

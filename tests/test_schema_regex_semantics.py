"""ECMA-262 boundaries for the patterns in the packaged TRACE schema."""
import copy
import json
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest

from agentrust_trace import generate_key, key_to_jwk, sign_record, validate_json, verify_record
from agentrust_trace.validate import SCHEMA, iter_errors

BASE = json.loads((Path(__file__).parents[1] /
    "examples/canonicalization-boundary/01-non-ascii-values.json").read_text())["record"]
TERMINATORS = ["\n", "\r", "\u2028", "\u2029"]


@pytest.mark.parametrize("subject", ["spiffe://example.org/agent", "did:web:example.org"])
@pytest.mark.parametrize("tail", TERMINATORS)
@pytest.mark.parametrize("position", ["end", "middle"])
def test_subject_line_terminators_are_rejected(subject, tail, position):
    record = copy.deepcopy(BASE)
    record["subject"] = subject + tail + ("more" if position == "middle" else "")
    with pytest.raises(jsonschema.ValidationError):
        validate_json(record)
    errors = iter_errors(record)
    assert any(list(e.path) == ["subject"] and e.validator == "pattern" for e in errors)


@pytest.mark.parametrize("tail", TERMINATORS)
def test_signed_subject_line_terminators_are_rejected(tail):
    body = copy.deepcopy(BASE)
    body["subject"] = "spiffe://example.org/agent" + tail
    key = generate_key()
    with pytest.raises(ValueError, match="does not conform.*subject"):
        verify_record(sign_record(body, key), key_to_jwk(key), now=body["iat"])


@pytest.mark.parametrize("tail", TERMINATORS)
def test_signed_uri_line_terminators_are_rejected(tail):
    body = copy.deepcopy(BASE)
    body["appraisal"]["verifier"] = "https://verifier.example/v1" + tail
    key = generate_key()
    with pytest.raises(ValueError, match="does not conform.*appraisal[.]verifier"):
        verify_record(sign_record(body, key), key_to_jwk(key), now=body["iat"])


@pytest.mark.parametrize("subject", [
    "spiffe://example.org/agent", "did:web:example.org", "did:web:caf\u00e9", "did:web:\U0001f600",
    # The schema's negated authority class permits line breaks. Do not add a new rule.
    "spiffe://exam\nple.org/agent",
])
def test_valid_subjects_keep_their_schema_meaning(subject):
    body = copy.deepcopy(BASE)
    body["subject"] = subject
    key = generate_key()
    verify_record(sign_record(body, key), key_to_jwk(key), now=body["iat"])


@pytest.mark.parametrize("field", ["signature", "measurement"])
def test_other_anchored_patterns_reject_final_newline(field):
    record = copy.deepcopy(BASE)
    target = record if field == "signature" else record["runtime"]
    target[field] += "\n"
    with pytest.raises(jsonschema.ValidationError):
        validate_json(record)


def _patterns(node):
    if isinstance(node, dict):
        if "pattern" in node:
            yield node["pattern"]
        for value in node.values():
            yield from _patterns(value)
    elif isinstance(node, list):
        for value in node:
            yield from _patterns(value)


def test_every_shipped_pattern_has_an_explicit_adapter():
    from agentrust_trace.validate import _ECMA_PATTERNS

    assert set(_patterns(SCHEMA)) == set(_ECMA_PATTERNS)


@pytest.mark.parametrize("value,valid", [("P1D", True), ("P\u0661D", False), ("P1D\n", False)])
def test_duration_digits_and_end_anchor(value, valid):
    from agentrust_trace.validate import _TraceValidator

    pattern = next(p for p in _patterns(SCHEMA) if p.startswith("^P"))
    assert _TraceValidator({"pattern": pattern}).is_valid(value) is valid


def test_non_strings_are_left_to_the_type_keyword():
    from agentrust_trace.validate import _TraceValidator

    assert _TraceValidator({"pattern": SCHEMA["properties"]["subject"]["pattern"]}).is_valid(42)


def test_pattern_and_format_registration_do_not_mutate_jsonschema():
    from agentrust_trace.validate import _validator

    original = jsonschema.Draft202012Validator.VALIDATORS["pattern"]
    formats = jsonschema.FormatChecker.checkers.copy()
    schema = copy.deepcopy(SCHEMA)
    _validator.cache_clear()
    validate_json(BASE)
    assert jsonschema.Draft202012Validator.VALIDATORS["pattern"] is original
    assert jsonschema.FormatChecker.checkers == formats
    assert SCHEMA == schema


def test_shipped_pattern_results_match_javascript():
    """An independent runtime checks the actual published patterns, not our rewrite."""
    from agentrust_trace.validate import _TraceValidator

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed for the independent ECMA-262 comparison")
    samples = [
        "", "spiffe://example.org/agent", "did:web:example.org", "did:web:\U0001f600",
        "spiffe://exam\nple.org/agent", "sha256:" + "a" * 64, "sha384:" + "f" * 96,
        "abc_DEF-123", "P1D", "PT2H", "P\u0661D", "P\uff11D", "P1W",
    ]
    cases = [[pattern, value + tail + suffix]
             for pattern in sorted(set(_patterns(SCHEMA)))
             for value in samples for tail in ["", *TERMINATORS] for suffix in ["", "x"]]
    result = subprocess.run(
        [node, "-e", "const fs=require('fs'); const cases=JSON.parse(fs.readFileSync(0,'utf8')); "
         "console.log(JSON.stringify(cases.map(([p,v])=>new RegExp(p).test(v))));"],
        input=json.dumps(cases), text=True, capture_output=True, check=True,
    )
    expected = json.loads(result.stdout)
    for (pattern, value), valid in zip(cases, expected, strict=True):
        assert _TraceValidator({"pattern": pattern}).is_valid(value) == valid, (pattern, value)

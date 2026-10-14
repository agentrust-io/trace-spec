"""Automated checks for the signature-vs-execution boundary example."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from agentrust_trace.revocation import VerificationResult

from agentrust_trace import jwk_thumbprint, sign_record, validate_json, verify_record

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIR = ROOT / "examples" / "signature-execution-boundary"
SCRIPT = EXAMPLE_DIR / "signature_execution_boundary.py"
README = EXAMPLE_DIR / "README.md"
GENERATOR = runpy.run_path(str(SCRIPT))


def _generate(directory: Path) -> tuple[Path, str]:
    script = directory / SCRIPT.name
    shutil.copyfile(SCRIPT, script)
    output = directory / "out"
    proc = subprocess.run(
        [sys.executable, str(script), "--out", str(output)],
        cwd=directory,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        check=True,
        capture_output=True,
        text=True,
    )
    return output, proc.stdout


@pytest.fixture(scope="module")
def generated_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str]:
    return _generate(tmp_path_factory.mktemp("sig-exec-boundary"))


@pytest.fixture
def baseline(generated_run: tuple[Path, str]) -> dict[str, Any]:
    output, _ = generated_run
    loaded: dict[str, Any] = GENERATOR["load_json"](
        (output / "baseline-record.trace.json").read_text("utf-8")
    )
    return loaded


@pytest.fixture
def invented(generated_run: tuple[Path, str]) -> dict[str, Any]:
    output, _ = generated_run
    loaded: dict[str, Any] = GENERATOR["load_json"](
        (output / "invented-execution-record.trace.json").read_text("utf-8")
    )
    return loaded


@pytest.fixture
def inputs(generated_run: tuple[Path, str]) -> dict[str, Any]:
    output, _ = generated_run
    loaded: dict[str, Any] = GENERATOR["load_json"](
        (output / "verification-inputs.json").read_text("utf-8")
    )
    return loaded


def _commitment(value: Any, expected: str) -> str:
    # Independent of GENERATOR["digest"], though both use rfc8785.
    if value is None:
        return "unavailable"
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float) or (type(item) is int and abs(item) > 9007199254740991):
            return "unsupported"
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    actual = "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()
    return "matched" if actual == expected else "mismatch"


_DEFAULT_KEY = object()


def _verify(
    record: dict[str, Any],
    inputs: dict[str, Any],
    *,
    key: Any = _DEFAULT_KEY,
    allow_embedded_key: bool = False,
) -> VerificationResult:
    resolved_key = inputs["trusted_key"] if key is _DEFAULT_KEY else key
    return verify_record(
        record,
        resolved_key,
        allow_embedded_key=allow_embedded_key,
        now=inputs["now"],
        max_age_seconds=inputs["max_age_seconds"],
        max_future_skew_seconds=inputs["max_future_skew_seconds"],
    )


def test_script_reproduces_fixed_evidence_bytes_and_stdout(
    generated_run: tuple[Path, str], tmp_path: Path
) -> None:
    output, first_stdout = generated_run
    regenerated, second_stdout = _generate(tmp_path)
    expected = {
        "baseline-record.trace.json": (
            "7e227a2d081b66e1e0374a47c9a03075abe3476e77920d0ecdbb45aaebd04dcb"
        ),
        "invented-execution-record.trace.json": (
            "24ccd0f9fee8b0aa187273a062fc8b2dd049572da42e0be29343adf4707913a1"
        ),
        "verification-inputs.json": (
            "fdb63fada561c389ff4481fac8773f2da9f95c61bb63f8c6e83d75069f10ea0d"
        ),
    }
    assert {path.name for path in output.iterdir()} == set(expected)
    assert {path.name for path in regenerated.iterdir()} == set(expected)
    for name, expected_sha256 in expected.items():
        raw = (output / name).read_bytes()
        assert raw == (regenerated / name).read_bytes()
        assert b"\r\n" not in raw
        assert hashlib.sha256(raw).hexdigest() == expected_sha256
    assert first_stdout == second_stdout
    readme_blocks = re.findall(
        r"^```text\n(.*?)^```", README.read_text(encoding="utf-8"), re.M | re.S
    )
    assert len(readme_blocks) == 1
    assert first_stdout.strip() == readme_blocks[0].strip()
    lines = first_stdout.strip().splitlines()
    assert len(lines) == 4
    assert [line.split(":")[0] for line in lines] == [
        "PASS [1/4]",
        "PASS [2/4]",
        "PASS [3/4]",
        "PASS [4/4]",
    ]


def test_signed_record_verifies_against_separately_retained_trusted_key(
    baseline: dict[str, Any], inputs: dict[str, Any]
) -> None:
    validate_json(baseline)
    result = _verify(baseline, inputs)
    assert result.profile == "tag:agentrust-io.com,2026:trace-v0.2"
    assert result.accepted_profiles == ("tag:agentrust-io.com,2026:trace-v0.2",)
    assert result.trusted_key_thumbprint == jwk_thumbprint(inputs["trusted_key"])
    assert result.revocation.outcome == "no_check_performed"
    assert result.platform_measurement.outcome == "not_attempted"
    assert all(row.outcome == "not_attempted" for row in result.citations.values())


@pytest.mark.parametrize(
    "path,new_value",
    [
        (("subject",), "spiffe://example.org/agent/tampered-subject"),
        (("iat",), 1791935990),
        (("data_class",), "public"),
        (("model", "model_id"), "tampered-model-v2"),
        (("runtime", "measurement"), "sha256:" + "1" * 64),
        (("policy", "bundle_hash"), "sha256:" + "2" * 64),
        (("policy", "enforcement_mode"), "enforce"),
        (("build_provenance", "digest"), "sha256:" + "3" * 64),
        (("appraisal", "status"), "affirming"),
        (("tool_transcript", "hash"), "sha256:" + "4" * 64),
        (("tool_transcript", "call_count"), 99),
    ],
)
def test_changing_any_signed_field_passes_schema_but_fails_signature(
    baseline: dict[str, Any],
    inputs: dict[str, Any],
    path: tuple[str, ...],
    new_value: Any,
) -> None:
    tampered = copy.deepcopy(baseline)
    target = tampered
    for key in path[:-1]:
        target = target[key]
    assert target[path[-1]] != new_value
    target[path[-1]] = new_value
    # Schema still accepts the mutated record; the signature check is what catches it.
    validate_json(tampered)
    with pytest.raises(InvalidSignature):
        _verify(tampered, inputs)


def test_verification_with_wrong_issuer_key_fails_closed(
    baseline: dict[str, Any], inputs: dict[str, Any]
) -> None:
    wrong_key = inputs["wrong_trusted_key"]
    assert jwk_thumbprint(wrong_key) != jwk_thumbprint(inputs["trusted_key"])

    # 1. Supplying the wrong trusted key fails at cnf.jwk thumbprint binding.
    with pytest.raises(ValueError, match="does not identify the trusted key"):
        _verify(baseline, inputs, key=wrong_key)

    # 2. Replacing cnf.jwk with the wrong key's JWK passes thumbprint comparison
    #    and schema validation, then fails Ed25519 signature verification because
    #    cnf.jwk is part of the signed RFC 8785 preimage.
    rebound = copy.deepcopy(baseline)
    rebound["cnf"] = {"jwk": copy.deepcopy(wrong_key)}
    validate_json(rebound)
    with pytest.raises(InvalidSignature):
        _verify(rebound, inputs, key=wrong_key)

    # 3. Omitting a trusted key without allow_embedded_key fails closed.
    with pytest.raises(ValueError, match="verify_record requires a trusted key"):
        _verify(baseline, inputs, key=None, allow_embedded_key=False)


def test_embedded_key_option_only_checks_self_consistency_not_issuer_identity(
    baseline: dict[str, Any], inputs: dict[str, Any]
) -> None:
    # A record signed by the wrong issuer key verifies if allow_embedded_key=True is
    # enabled, which is why verifiers must use a separately retained trusted key.
    unsigned = {k: v for k, v in baseline.items() if k not in ("cnf", "signature")}
    forged_by_wrong_issuer = sign_record(unsigned, GENERATOR["wrong_issuer_key"]())
    validate_json(forged_by_wrong_issuer)

    with pytest.raises(ValueError, match="does not identify the trusted key"):
        _verify(forged_by_wrong_issuer, inputs)

    with pytest.warns(UserWarning, match="internally consistent"):
        self_consistent = _verify(
            forged_by_wrong_issuer, inputs, key=None, allow_embedded_key=True
        )
    assert self_consistent.trusted_key_thumbprint == jwk_thumbprint(inputs["wrong_trusted_key"])


def test_trusted_issuer_can_sign_invented_and_contradictory_execution_claims(
    baseline: dict[str, Any], invented: dict[str, Any], inputs: dict[str, Any]
) -> None:
    # Both records carry the same subject, iat, and trusted issuer signature, yet make
    # mutually incompatible claims about policy enforcement, appraisal, SLSA level, and
    # tool calls. Both pass schema validation and verify_record() identically.
    validate_json(baseline)
    validate_json(invented)
    baseline_result = _verify(baseline, inputs)
    invented_result = _verify(invented, inputs)

    assert baseline_result == invented_result
    assert baseline["subject"] == invented["subject"]
    assert baseline["iat"] == invented["iat"]
    assert baseline["policy"]["enforcement_mode"] == "declared"
    assert invented["policy"]["enforcement_mode"] == "enforce"
    assert baseline["appraisal"]["status"] == "none"
    assert invented["appraisal"]["status"] == "affirming"
    assert baseline["build_provenance"]["slsa_level"] == 1
    assert invented["build_provenance"]["slsa_level"] == 3
    assert baseline["tool_transcript"]["call_count"] == 1
    assert invented["tool_transcript"]["call_count"] == 12

    # External evidence comparison separates the committed transcript from the
    # invented claim that never produced matching retained evidence.
    retained = inputs["retained_transcript"]
    assert _commitment(retained, baseline["tool_transcript"]["hash"]) == "matched"
    assert _commitment(retained, invented["tool_transcript"]["hash"]) == "mismatch"
    assert _commitment(None, invented["tool_transcript"]["hash"]) == "unavailable"


def test_retained_transcript_mutation_preserves_signature_but_breaks_commitment(
    baseline: dict[str, Any], inputs: dict[str, Any]
) -> None:
    inputs["retained_transcript"]["calls"][0]["result"]["quantity"] = 999
    # The record's signature still verifies, because verify_record() does not inspect
    # external transcript bytes; only the separate commitment check detects the change.
    _verify(baseline, inputs)
    assert (
        _commitment(inputs["retained_transcript"], baseline["tool_transcript"]["hash"])
        == "mismatch"
    )


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"nested":[{"k":0,"k":1}]}'])
def test_duplicate_json_members_are_refused(text: str) -> None:
    with pytest.raises(ValueError, match="duplicate JSON member"):
        GENERATOR["load_json"](text)


@pytest.mark.parametrize("entrypoint", ["load_json", "digest", "_commitment"])
@pytest.mark.parametrize(
    "number",
    [
        "1.0",
        "0.5",
        "1e0",
        "NaN",
        "Infinity",
        "-Infinity",
        "9007199254740992",
        "-9007199254740992",
    ],
)
def test_example_numeric_domain_refuses_floats_and_unsafe_integers(
    number: str, entrypoint: str
) -> None:
    text = '{"nested":[' + number + "]}"
    if entrypoint == "_commitment":
        assert _commitment(json.loads(text), "sha256:" + "0" * 64) == "unsupported"
        return
    value = text if entrypoint == "load_json" else json.loads(text)
    with pytest.raises(ValueError, match="unsupported numeric value"):
        GENERATOR[entrypoint](value)


@pytest.mark.parametrize("bad_tuple", [{"items": (1.5,)}, {"items": (9007199254740992,)}])
def test_tuple_containers_are_checked_for_unsupported_numbers(bad_tuple: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="unsupported numeric value"):
        GENERATOR["digest"](bad_tuple)
    assert GENERATOR["commitment_status"](bad_tuple, "sha256:" + "0" * 64) == "unsupported"
    assert _commitment(bad_tuple, "sha256:" + "0" * 64) == "unsupported"


@pytest.mark.parametrize("number", [1.0, 1.5, -0.0])
def test_unsupported_number_never_matches_even_its_raw_jcs_digest(number: float) -> None:
    retained = {"nested": [{"x": number}]}
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(retained)).hexdigest()
    assert _commitment(retained, expected) == "unsupported"


def test_local_canonicalization_preserves_supported_boolean_null_and_safe_integer() -> None:
    text = '{"values":[true,false,null,9007199254740991,-9007199254740991]}'
    value = GENERATOR["load_json"](text)
    assert GENERATOR["canonical_bytes"](value) == text.encode()
    expected = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    assert _commitment(value, expected) == "matched"


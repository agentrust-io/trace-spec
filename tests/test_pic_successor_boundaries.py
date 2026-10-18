"""Every published current-contract vector through reference and independent checks."""

from __future__ import annotations
import importlib.util
import json
import copy
import jsonschema
import subprocess
import sys
from pathlib import Path
import pytest
from agentrust_trace.intent_bridge import (
    IntentBridgeError,
    verify_bridge,
    verify_successor_artifact,
)
from agentrust_trace.successor_observation import evaluate_successor_observation

DIR = Path(__file__).resolve().parents[1] / "examples/pic-successor-boundaries"
CASES = sorted(DIR.glob("0*.json"))


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


independent = _module("pic_successor_independent", DIR / "independent.py")


def _reason(exc):
    message = str(exc)
    if message.endswith(" must be a sha256 digest"):
        return "pic-digest-syntax"
    if message.startswith("successor envelope is missing successor fields:"):
        return "successor-envelope-missing-fields"
    return {
        "successor artifact does not name the authorization that was verified": (
            "successor-authorization-mismatch"
        ),
        "successor envelope does not match the expected digest binding": (
            "successor-digest-mismatch"
        ),
        "successor signature is invalid": "successor-signature-invalid",
        "successor observer is not the identity the trusted observer key belongs to": (
            "successor-observer-mismatch"
        ),
        "trusted bound successor evidence satisfies the transition predicate": (
            "predicate-satisfied"
        ),
        "trusted bound successor evidence contradicts the transition predicate": (
            "predicate-contradicted"
        ),
        "transition predicate cannot decide from this observation": "predicate-undecidable",
        "successor observation is stale": "observation-stale",
        "successor observation is dated in the future": "observation-future",
    }[message]  # Unknown errors fail the adapter instead of masquerading as expected refusal.


def _reference(data, context=None):
    if context is None:
        context = json.loads((DIR / "003-established.json").read_text(encoding="utf-8"))["context"]
    result = {
        "authorization_bound": False,
        "successor_bound": None,
        "outcome": None,
        "reason": None,
    }
    try:
        auth = verify_bridge(
            data["bridge"],
            data["authorizer_jwk"],
            declaration=data["declaration"],
            pic_intent_digest=data["pic_intent_digest"],
            pic_args_digest=data["pic_args_digest"],
            tool_call=data["tool_call"],
            transcript=data["transcript"],
            now=context["now"],
        )
    except IntentBridgeError as exc:
        result["reason"] = _reason(exc)
        return result
    result["authorization_bound"] = True
    result["successor_bound"] = False
    try:
        bound = verify_successor_artifact(
            data["successor"],
            data["observer_jwk"],
            trusted_observer=context["trusted_observer"],
            authorization_id=auth["authorization_id"],
            after=data["after"],
        )
    except IntentBridgeError as exc:
        result["reason"] = _reason(exc)
        return result
    result["successor_bound"] = True
    outcome = evaluate_successor_observation(
        bound,
        expected_successor_digest=data["successor"]["successor_observation_digest"],
        trusted_observers={context["trusted_observer"]},
        executor_id=context["executor_id"],
        independence_required=context["independence_required"],
        now=context["now"],
        max_age_seconds=context["max_age_seconds"],
        predicate=lambda obs: obs.get("reachable"),
    )
    result["outcome"] = outcome.status
    result["reason"] = _reason(outcome.reason)
    return result


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_each_vector_agrees_on_all_three_axes(path):
    case = json.loads(path.read_text(encoding="utf-8"))
    independent.validate_case(case)
    assert _reference(case["inputs"], case["context"]) == case["expected"]
    assert independent.check(case["inputs"], case["context"]) == case["expected"]


def test_corpus_is_nonempty_and_three_axis_case003_split_is_present():
    assert len(CASES) == 15
    cases = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in CASES}
    assert {
        name: {k: v for k, v in cases[name]["expected"].items() if k != "reason"}
        for name in cases
        if name.startswith("003")
    } == {
        "003-established": {
            "authorization_bound": True,
            "successor_bound": True,
            "outcome": "established",
        },
        "003a-empty-envelope": {
            "authorization_bound": True,
            "successor_bound": False,
            "outcome": None,
        },
        "003b-empty-observation": {
            "authorization_bound": True,
            "successor_bound": True,
            "outcome": "not-established",
        },
        "003c-unrelated-observation": {
            "authorization_bound": True,
            "successor_bound": True,
            "outcome": "not-established",
        },
    }


@pytest.mark.parametrize("source", ["signed", "supplied"])
@pytest.mark.parametrize("field", ["intent_digest", "args_digest"])
def test_bare_hex_reaches_digest_syntax_with_valid_authorization_signature(source, field):
    case = json.loads((DIR / f"005-{source}-{field}-bare.json").read_text(encoding="utf-8"))
    data = case["inputs"]
    # These signed cases were re-signed after the edit: an earlier signature failure
    # must never masquerade as coverage of PIC digest representation.
    independent.signature(data["bridge"], data["authorizer_jwk"])
    expected_field = f"authorization.pic.{field}" if source == "signed" else field
    with pytest.raises(IntentBridgeError, match=rf"{expected_field} must be a sha256 digest"):
        verify_bridge(
            data["bridge"],
            data["authorizer_jwk"],
            declaration=data["declaration"],
            pic_intent_digest=data["pic_intent_digest"],
            pic_args_digest=data["pic_args_digest"],
            tool_call=data["tool_call"],
            transcript=data["transcript"],
            now=160,
        )


def test_the_same_authorization_survives_all_successor_observation_changes():
    split = [
        json.loads(p.read_text(encoding="utf-8"))["inputs"]["bridge"]
        for p in CASES
        if p.stem.startswith("003")
    ]
    assert all(bridge == split[0] for bridge in split)
    assert "successor_observation_digest" not in split[0]["authorization"]


def test_missing_envelope_fails_before_digest_while_empty_observation_is_bound():
    data = json.loads((DIR / "003a-empty-envelope.json").read_text(encoding="utf-8"))["inputs"]
    with pytest.raises(IntentBridgeError, match="missing successor fields"):
        verify_successor_artifact(
            data["successor"],
            data["observer_jwk"],
            trusted_observer="observer-1",
            authorization_id="auth-003",
            after=data["after"],
        )
    # Wrong implementations conflating any empty object with missing envelope are
    # distinguished by 003a (missing fields) and 003b (valid bound observation {}).
    bound = json.loads((DIR / "003b-empty-observation.json").read_text(encoding="utf-8"))["inputs"]
    assert (
        verify_successor_artifact(
            bound["successor"],
            bound["observer_jwk"],
            trusted_observer="observer-1",
            authorization_id="auth-003",
            after=bound["after"],
        )
        == bound["after"]
    )


def test_signature_and_authorization_link_mutations_are_independently_observable():
    positive = json.loads((DIR / "003-established.json").read_text(encoding="utf-8"))["inputs"]
    for name in [
        "006-wrong-authorization",
        "007-substituted-envelope",
        "008-invalid-observer-signature",
    ]:
        mutant = json.loads((DIR / (name + ".json")).read_text(encoding="utf-8"))["inputs"]
        assert _reference(positive)["successor_bound"] is True
        assert _reference(mutant)["successor_bound"] is False
        assert (
            independent.check(mutant, json.loads(CASES[0].read_text())["context"])[
                "successor_bound"
            ]
            is False
        )
    # Both always-accept and always-refuse answers disagree with the corpus.
    assert any(
        json.loads(p.read_text(encoding="utf-8"))["expected"]["successor_bound"] is False
        for p in CASES
    )
    assert any(
        json.loads(p.read_text(encoding="utf-8"))["expected"]["outcome"] == "contradicted"
        for p in CASES
    )


def test_generator_reproduces_all_published_vector_bytes(tmp_path):
    subprocess.run([sys.executable, str(DIR / "generate.py"), str(tmp_path)], check=True)
    assert {p.name for p in tmp_path.iterdir()} == {p.name for p in CASES}
    for path in CASES:
        assert path.read_bytes() == (tmp_path / path.name).read_bytes()


def test_independent_checker_has_no_reference_package_imports():
    import ast

    tree = ast.parse((DIR / "independent.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("agentrust_trace")
        elif isinstance(node, ast.Import):
            assert all(not alias.name.startswith("agentrust_trace") for alias in node.names)


def test_optimized_python_compares_every_vector_without_assert_guards():
    code = """
import importlib.util, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("bounded", root / "independent.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
paths = sorted(root.glob("0*.json"))
if len(paths) != 15:
    raise RuntimeError("missing vectors")
for path in paths:
    case = json.loads(path.read_text(encoding="utf-8"))
    m.validate_case(case)
    observed = m.check(case["inputs"], case["context"])
    if observed != case["expected"]:
        raise RuntimeError(f"{path.name}: {observed}")
"""
    subprocess.run([sys.executable, "-O", "-c", code, str(DIR)], check=True)


@pytest.mark.parametrize("field", ["schema_version", "context", "expected", "inputs", "id"])
def test_case_contract_rejects_missing_required_fields(field):
    case = json.loads(CASES[0].read_text(encoding="utf-8"))
    del case[field]
    with pytest.raises(jsonschema.ValidationError):
        independent.validate_case(case)


@pytest.mark.parametrize("edit", ["version", "reason", "unknown", "context", "input"])
def test_case_contract_rejects_invalid_or_unversioned_shapes(edit):
    case = json.loads(CASES[0].read_text(encoding="utf-8"))
    if edit == "version":
        case["schema_version"] = "2.0"
    elif edit == "reason":
        case["expected"]["reason"] = "generic-refusal"
    elif edit == "unknown":
        case["typo"] = True
    elif edit == "context":
        case["context"]["now"] = True
    else:
        case["inputs"]["after"] = []
    with pytest.raises(jsonschema.ValidationError):
        independent.validate_case(case)


def test_observer_relabel_is_resigned_and_otherwise_bound():
    case = json.loads((DIR / "009-observer-relabel.json").read_text(encoding="utf-8"))
    data = case["inputs"]
    independent.signature(data["successor"], data["observer_jwk"])
    assert independent.digest(data["after"]) == data["successor"]["successor_observation_digest"]
    assert _reference(data, case["context"])["reason"] == "successor-observer-mismatch"
    # Same bytes and key succeed only when verifier-owned identity configuration changes.
    context = {**case["context"], "trusted_observer": "observer-other"}
    assert _reference(data, context)["reason"] == "predicate-satisfied"
    assert independent.check(data, context)["reason"] == "predicate-satisfied"


@pytest.mark.parametrize(
    "name,reason",
    [
        ("010-stale-observation", "observation-stale"),
        ("011-future-observation", "observation-future"),
    ],
)
def test_freshness_refusal_is_not_a_binding_failure(name, reason):
    case = json.loads((DIR / (name + ".json")).read_text(encoding="utf-8"))
    data = case["inputs"]
    assert _reference(data, case["context"])["reason"] == reason
    assert case["expected"]["successor_bound"] is True
    fresh = {**case["context"], "now": data["after"]["observed_at"]}
    assert _reference(data, fresh)["reason"] == "predicate-satisfied"
    assert independent.check(data, fresh)["reason"] == "predicate-satisfied"


def test_reason_mismatch_is_visible_even_with_identical_axes():
    case = json.loads((DIR / "006-wrong-authorization.json").read_text(encoding="utf-8"))
    wrong = copy.deepcopy(case["expected"])
    wrong["reason"] = "successor-signature-invalid"
    assert _reference(case["inputs"], case["context"]) != wrong
    assert independent.check(case["inputs"], case["context"]) != wrong

"""Every published current-contract vector through reference and independent checks."""

from __future__ import annotations
import importlib.util
import json
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


def _reference(data):
    result = {"authorization_bound": False, "successor_bound": None, "outcome": None}
    try:
        auth = verify_bridge(
            data["bridge"],
            data["authorizer_jwk"],
            declaration=data["declaration"],
            pic_intent_digest=data["pic_intent_digest"],
            pic_args_digest=data["pic_args_digest"],
            tool_call=data["tool_call"],
            transcript=data["transcript"],
            now=160,
        )
    except IntentBridgeError:
        return result
    result["authorization_bound"] = True
    result["successor_bound"] = False
    try:
        bound = verify_successor_artifact(
            data["successor"],
            data["observer_jwk"],
            trusted_observer="observer-1",
            authorization_id=auth["authorization_id"],
            after=data["after"],
        )
    except IntentBridgeError:
        return result
    result["successor_bound"] = True
    outcome = evaluate_successor_observation(
        bound,
        expected_successor_digest=data["successor"]["successor_observation_digest"],
        trusted_observers={"observer-1"},
        executor_id="executor-1",
        independence_required=True,
        now=160,
        max_age_seconds=30,
        predicate=lambda obs: obs.get("reachable"),
    )
    result["outcome"] = outcome.status
    return result


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_each_vector_agrees_on_all_three_axes(path):
    case = json.loads(path.read_text(encoding="utf-8"))
    assert _reference(case["inputs"]) == case["expected"]
    assert independent.check(case["inputs"]) == case["expected"]


def test_corpus_is_nonempty_and_three_axis_case003_split_is_present():
    assert len(CASES) == 12
    cases = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in CASES}
    assert {name: cases[name]["expected"] for name in cases if name.startswith("003")} == {
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
        assert independent.check(mutant)["successor_bound"] is False
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
if len(paths) != 12:
    raise RuntimeError("missing vectors")
for path in paths:
    case = json.loads(path.read_text(encoding="utf-8"))
    observed = m.check(case["inputs"])
    if observed != case["expected"]:
        raise RuntimeError(f"{path.name}: {observed}")
"""
    subprocess.run([sys.executable, "-O", "-c", code, str(DIR)], check=True)

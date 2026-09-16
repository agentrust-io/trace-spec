"""Differential runner restricted to the four case-003 review vectors."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import rfc8785

from agentrust_trace import intent_bridge, successor_observation
from run_bridge_vectors import ReferenceSignalError, _normalize_reference_exception
from verify_bridge_independent import verify_case

HERE = Path(__file__).resolve().parent
REASONS = {
    "trusted bound successor evidence satisfies the transition predicate": (
        "successor_predicate_satisfied"
    ),
    "trusted bound successor evidence contradicts the transition predicate": (
        "successor_predicate_contradicted"
    ),
    "transition predicate cannot decide from this observation": "successor_predicate_undecidable",
    "successor observer is not trusted by verifier policy": "successor_observer_untrusted",
    "successor observation is dated in the future": "successor_observation_future",
    "successor observation is stale": "successor_observation_stale",
    "independent observation is required but executor identity is unavailable": (
        "successor_executor_unknown"
    ),
    "independent observation is required but observer is the executor": (
        "successor_observer_not_independent"
    ),
}


def predicate(inputs: dict[str, Any]):
    """Fixture-local predicate, with explicit unknown and contradictory evidence."""
    invoice_id = inputs["tool_call"]["arguments"]["invoice_id"]

    def evaluate(observation: dict[str, Any]) -> bool | None:
        if observation.get("invoice_id") != invoice_id:
            return None
        status = observation.get("status")
        if status == "sent":
            return True
        if status == "failed":
            return False
        return None

    return evaluate


def reference(case: dict[str, Any]) -> dict[str, Any]:
    inputs = case["inputs"]
    try:
        authorization = intent_bridge.verify_bridge(**inputs)
    except Exception as exc:
        pic_bound = None
        if type(exc) is intent_bridge.AuthorizationMismatch and str(exc) == (
            "transcript.after is missing successor fields: "
            "['observation', 'observed_at', 'observer']"
        ):
            runtime = {
                "classification": "mismatch",
                "codes": ["transcript_after_invalid"],
                "result": None,
            }
            pic_bound = True
        elif type(exc) is intent_bridge.AuthorizationMismatch and str(exc) == (
            "transcript.after does not match the expected digest binding"
        ):
            runtime = {
                "classification": "mismatch",
                "codes": ["successor_envelope_digest_mismatch"],
                "result": None,
            }
            pic_bound = True
        else:
            runtime = _normalize_reference_exception(exc)
        return {
            **runtime,
            "pic_authorization_bound": pic_bound,
            "successor_envelope_bound": False,
            "successor_outcome": None,
            "successor_reason": None,
        }

    policy = dict(case["successor_policy"])
    if policy.pop("predicate") != "invoice-sent-v1":
        raise ValueError("unknown case-003 predicate")
    outcome = successor_observation.evaluate_successor_observation(
        inputs["transcript"]["after"],
        expected_successor_digest=authorization["successor_observation_digest"],
        now=inputs["now"],
        predicate=predicate(inputs),
        **policy,
    )
    if outcome.reason not in REASONS:
        raise ReferenceSignalError(f"unmapped successor reason: {outcome.reason}")
    return {
        "classification": "accepted",
        "codes": [],
        "result": {
            "authorization_id": authorization["authorization_id"],
            "tool": inputs["tool_call"]["name"],
            "impact": inputs["declaration"]["impact"],
        },
        "pic_authorization_bound": True,
        "successor_envelope_bound": True,
        "successor_outcome": outcome.status,
        "successor_reason": REASONS[outcome.reason],
    }


def material(value: Any) -> dict[str, Any]:
    raw = rfc8785.dumps(value)
    return {
        "applicable": True,
        "canonical_preimage_base64url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        "canonical_preimage_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


def run() -> dict[str, Any]:
    schema = json.loads((HERE / "contract/case003-v1.schema.json").read_text())
    bridge_schema = json.loads((HERE.parents[1] / "schema/pic-trace-bridge-v1.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator.check_schema(bridge_schema)
    rows = []
    for path in sorted(HERE.glob("003*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        errors = []
        measured = {}
        try:
            jsonschema.validate(case, schema)
            jsonschema.validate(case["inputs"]["bridge"], bridge_schema)
            inputs = case["inputs"]
            bridge = inputs["bridge"]
            preimages = {
                "authorization_signature": {k: bridge[k] for k in ("profile", "authorization")},
                "declaration_digest": inputs["declaration"],
                "tool_call_digest": inputs["tool_call"],
                "successor_observation_digest": inputs["transcript"]["after"],
            }
            for name, value in preimages.items():
                if material(value) != case["reproducibility"][name]:
                    errors.append(f"canonical material differs: {name}")
            for name, verifier in (("reference", reference), ("independent", verify_case)):
                measured[name] = verifier(case)
                if measured[name] != case["expected"]["conformant_runtime"]:
                    errors.append(f"{name} differs from declared expectation")
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        rows.append({"id": case["id"], "passed": not errors, "errors": errors, **measured})
    ids = {r["id"] for r in rows}
    expected_ids = {"TRACE-PIC-BRIDGE-003" + suffix for suffix in ("", "a", "b", "c")}
    return {
        "scope": "case-003-only",
        "review_vectors": len(rows),
        "original_empty_after_positive_credit": "withdrawn",
        "full_corpus_certification": "held",
        "frozen_conformance_denominator": 100,
        "known_defect_rows_excluded": ["TRACE-PIC-BRIDGE-101", "TRACE-PIC-BRIDGE-102"],
        "passed": ids == expected_ids and all(row["passed"] for row in rows),
        "cases": rows,
    }

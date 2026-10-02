"""Run and differentially score the PIC/TRACE bridge corpus.

The reference adapter only normalizes observed exception class and message. It
does not read a case's expected result and does not re-run bridge semantics.
Known-defect cases are diagnostic: the independent verifier is compared with
the conformant target while the pinned reference is compared with its separately
recorded observation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from collections.abc import Sequence

import jsonschema
import rfc8785

from agentrust_trace.intent_bridge import (
    AuthorizationDenied,
    AuthorizationMismatch,
    IntentBridgeError,
    verify_bridge as verify_bridge_reference,
)
from verify_bridge_independent import (
    BRIDGE_PROFILE,
    RULES,
    RULE_CODES,
    verify_case as verify_case_independent,
)

HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
CASE_SCHEMA_PATH = HERE / "contract" / "case-v1.schema.json"
BRIDGE_SCHEMA_PATH = REPOSITORY_ROOT / "schema" / "pic-trace-bridge-v1.json"
CASE_PATTERN = "[0-9][0-9][0-9]-*.json"
KNOWN_DEFECT_TRACKER = "https://github.com/agentrust-io/trace-spec/issues/247"
REFERENCE_IMPLEMENTATION = "agentrust_trace.intent_bridge.verify_bridge"
REFERENCE_BASELINE = "3c2f96375afaea6c615c49dea21d83a7969862e3"

AUTHORIZATION_NOT_JCS_REFERENCE_SIGNAL = (
    "the authorization has no RFC 8785 canonical form, so it cannot be digested or "
    "signed: 9007199254740992 exceeds safe integer domain for JSON floats"
)
DIGEST_INPUT_NOT_JCS_REFERENCE_SIGNAL = (
    "the digest input has no RFC 8785 canonical form, so it cannot be digested or signed: "
    "9007199254740992 exceeds safe integer domain for JSON floats"
)


class ReferenceSignalError(RuntimeError):
    """The current reference emitted a signal outside the closed adapter table."""


def _runtime(
    classification: str,
    codes: list[str],
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {"classification": classification, "codes": codes, "result": result}


_EXACT_REFERENCE_SIGNALS: dict[tuple[type[BaseException], str], tuple[str, str]] = {
    (IntentBridgeError, "bridge must be an object"): ("invalid", "bridge_not_object"),
    (
        IntentBridgeError,
        "unknown bridge profile; best-effort parsing is refused",
    ): ("invalid", "bridge_profile_invalid"),
    (
        IntentBridgeError,
        "signature must be a base64url string",
    ): ("invalid", "signature_representation_invalid"),
    (
        IntentBridgeError,
        "authorization must be an object",
    ): ("invalid", "authorization_not_object"),
    (
        IntentBridgeError,
        "authorization.authorization_id must be a non-empty string",
    ): ("invalid", "authorization_id_invalid"),
    (
        IntentBridgeError,
        "authorization.authorizer must be a non-empty string",
    ): ("invalid", "authorizer_invalid"),
    (
        IntentBridgeError,
        "authorization.authorizer_key_id must be a non-empty string",
    ): ("invalid", "authorizer_key_id_invalid"),
    (
        IntentBridgeError,
        "authorization signature is invalid",
    ): ("invalid", "authorization_unverifiable"),
    (
        IntentBridgeError,
        AUTHORIZATION_NOT_JCS_REFERENCE_SIGNAL,
    ): ("invalid", "authorization_unverifiable"),
    (
        IntentBridgeError,
        DIGEST_INPUT_NOT_JCS_REFERENCE_SIGNAL,
    ): ("invalid", "execution_input_not_jcs"),
    (
        IntentBridgeError,
        "authorizer_key_id does not identify the trusted key",
    ): ("invalid", "authorizer_key_id_mismatch"),
    (
        AuthorizationDenied,
        "the signed decision is not allow",
    ): ("denied", "decision_not_allow"),
    (
        IntentBridgeError,
        "authorized_at must be a non-negative integer Unix timestamp",
    ): ("invalid", "authorized_at_invalid"),
    (
        IntentBridgeError,
        "expires_at must be a non-negative integer Unix timestamp",
    ): ("invalid", "expires_at_invalid"),
    (
        IntentBridgeError,
        "now must be a non-negative integer Unix timestamp",
    ): ("invalid", "verification_time_invalid"),
    (
        IntentBridgeError,
        "authorization is not yet valid",
    ): ("invalid", "authorization_not_yet_valid"),
    (
        IntentBridgeError,
        "expires_at must be after authorized_at",
    ): ("invalid", "authorization_window_invalid"),
    (
        IntentBridgeError,
        "authorization has expired",
    ): ("invalid", "authorization_expired"),
    (
        IntentBridgeError,
        "authorization.scope must be an object",
    ): ("invalid", "scope_not_object"),
    (
        IntentBridgeError,
        "authorization.scope.tools must be a non-empty array of non-empty strings",
    ): ("invalid", "scope_tools_invalid"),
    (
        IntentBridgeError,
        "authorization.scope.tools must not contain duplicates",
    ): ("invalid", "scope_tools_duplicate"),
    (
        IntentBridgeError,
        "authorization.scope.impacts must be a non-empty array of non-empty strings",
    ): ("invalid", "scope_impacts_invalid"),
    (
        IntentBridgeError,
        "authorization.scope.impacts must not contain duplicates",
    ): ("invalid", "scope_impacts_duplicate"),
    (
        IntentBridgeError,
        "tool_call must be an object",
    ): ("invalid", "tool_call_not_object"),
    (
        AuthorizationMismatch,
        "executed tool is outside the authorized tool scope",
    ): ("mismatch", "tool_outside_scope"),
    (
        IntentBridgeError,
        "declaration must be an object",
    ): ("invalid", "declaration_not_object"),
    (
        AuthorizationMismatch,
        "declaration impact is outside the authorized impact scope",
    ): ("mismatch", "impact_outside_scope"),
    (
        IntentBridgeError,
        "authorization.pic must be an object",
    ): ("invalid", "pic_not_object"),
    (
        IntentBridgeError,
        "authorization.pic.profile is not PIC-CJSON/1.0",
    ): ("invalid", "pic_profile_invalid"),
    (
        AuthorizationMismatch,
        "PIC intent_digest does not match the signed authorization",
    ): ("mismatch", "pic_intent_digest_mismatch"),
    (
        AuthorizationMismatch,
        "PIC args_digest does not match the signed authorization",
    ): ("mismatch", "pic_args_digest_mismatch"),
    (
        AuthorizationMismatch,
        "declaration_digest does not match the signed authorization",
    ): ("mismatch", "declaration_digest_mismatch"),
    (
        AuthorizationMismatch,
        "tool_call_digest does not match the signed authorization",
    ): ("mismatch", "tool_call_digest_mismatch"),
    (
        IntentBridgeError,
        "transcript_required must be boolean",
    ): ("invalid", "transcript_requirement_invalid"),
    (
        AuthorizationMismatch,
        "a full before/after transcript is required",
    ): ("mismatch", "transcript_incomplete"),
    (
        AuthorizationMismatch,
        "transcript.before.tool_call does not match execution",
    ): ("mismatch", "transcript_before_mismatch"),
    (
        AuthorizationMismatch,
        "transcript.after must contain the execution result",
    ): ("mismatch", "transcript_after_invalid"),
}

_PATTERN_REFERENCE_SIGNALS: tuple[tuple[type[BaseException], re.Pattern[str], str, str], ...] = (
    (
        IntentBridgeError,
        re.compile(r"^bridge contains unknown fields: \[.+\]$"),
        "invalid",
        "bridge_unknown_fields",
    ),
    (
        IntentBridgeError,
        re.compile(r"^authorization contains unknown fields: \[.+\]$"),
        "invalid",
        "authorization_unknown_fields",
    ),
    (
        IntentBridgeError,
        re.compile(r"^authorization is missing fields: \[.+\]$"),
        "invalid",
        "authorization_fields_missing",
    ),
    (
        IntentBridgeError,
        re.compile(r"^authorization\.scope contains unknown fields: \[.+\]$"),
        "invalid",
        "scope_unknown_fields",
    ),
    (
        IntentBridgeError,
        re.compile(r"^authorization\.pic contains unknown fields: \[.+\]$"),
        "invalid",
        "pic_unknown_fields",
    ),
    (
        IntentBridgeError,
        re.compile(
            r"^(?:authorization\.pic\.)?intent_digest must (?:be a sha256 digest|"
            r"contain 64 lowercase hexadecimal characters)$"
        ),
        "invalid",
        "pic_intent_digest_invalid",
    ),
    (
        IntentBridgeError,
        re.compile(
            r"^(?:authorization\.pic\.)?args_digest must (?:be a sha256 digest|"
            r"contain 64 lowercase hexadecimal characters)$"
        ),
        "invalid",
        "pic_args_digest_invalid",
    ),
    (
        IntentBridgeError,
        re.compile(
            r"^authorization\.declaration_digest must (?:be a sha256 digest|"
            r"contain 64 lowercase hexadecimal characters)$"
        ),
        "invalid",
        "declaration_digest_invalid",
    ),
    (
        IntentBridgeError,
        re.compile(
            r"^authorization\.tool_call_digest must (?:be a sha256 digest|"
            r"contain 64 lowercase hexadecimal characters)$"
        ),
        "invalid",
        "tool_call_digest_invalid",
    ),
)


def _normalize_reference_exception(exc: BaseException) -> dict[str, Any]:
    exact = _EXACT_REFERENCE_SIGNALS.get((type(exc), str(exc)))
    if exact is not None:
        classification, code = exact
        return _runtime(classification, [code])

    for exception_type, pattern, classification, code in _PATTERN_REFERENCE_SIGNALS:
        if type(exc) is exception_type and pattern.fullmatch(str(exc)):
            return _runtime(classification, [code])

    if type(exc) is ValueError and str(exc).startswith("signature is not valid base64url: "):
        return _runtime("invalid", ["signature_representation_invalid"])

    canonicalization_classes = {
        "CanonicalizationError",
        "FloatDomainError",
        "IntegerDomainError",
    }
    if (
        type(exc).__name__ in canonicalization_classes
        and type(exc).__module__.startswith("rfc8785")
    ) or isinstance(exc, UnicodeError):
        return _runtime("invalid", ["execution_input_not_jcs"])

    raise ReferenceSignalError(
        f"unmapped reference signal {type(exc).__module__}.{type(exc).__name__}: {str(exc)!r}"
    ) from exc


def reference_outcome(inputs: dict[str, Any]) -> dict[str, Any]:
    """Observe and normalize the reference without consulting expected data."""

    try:
        authorization = verify_bridge_reference(
            inputs["bridge"],
            inputs["trusted_authorizer_jwk"],
            declaration=inputs["declaration"],
            pic_intent_digest=inputs["pic_intent_digest"],
            pic_args_digest=inputs["pic_args_digest"],
            tool_call=inputs["tool_call"],
            transcript=inputs.get("transcript"),
            now=inputs["now"],
        )
    except BaseException as exc:
        return _normalize_reference_exception(exc)

    tool_call = inputs["tool_call"]
    declaration = inputs["declaration"]
    normalized = {
        "authorization_id": authorization.get("authorization_id"),
        "tool": tool_call.get("name") if isinstance(tool_call, dict) else None,
        "impact": declaration.get("impact") if isinstance(declaration, dict) else None,
        "transcript_bound": authorization.get("transcript_required") is True,
    }
    return _runtime("accepted", [], normalized)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_cases() -> list[tuple[Path, dict[str, Any]]]:
    cases: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(HERE.glob(CASE_PATTERN)):
        value = _load_json(path)
        if not isinstance(value, dict):
            raise ValueError(f"{path.name} does not contain a JSON object")
        cases.append((path, value))
    if not cases:
        raise ValueError(f"no corpus cases matched {CASE_PATTERN!r} under {HERE}")
    return cases


def _schema_result(validator: jsonschema.Draft202012Validator, value: Any) -> tuple[str, list[str]]:
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.absolute_path))
    messages = []
    for error in errors:
        location = "$" + "".join(f"[{part!r}]" for part in error.absolute_path)
        messages.append(f"{location}: {error.message}")
    return ("invalid", messages) if messages else ("valid", [])


def _metadata(value: Any) -> dict[str, str]:
    preimage = rfc8785.dumps(value)
    return {
        "canonical_preimage_base64url": base64.urlsafe_b64encode(preimage)
        .rstrip(b"=")
        .decode("ascii"),
        "canonical_preimage_sha256": "sha256:" + hashlib.sha256(preimage).hexdigest(),
    }


def _recompute_reproducibility(case: dict[str, Any]) -> list[str]:
    declared = case.get("reproducibility")
    if not isinstance(declared, dict):
        return ["reproducibility is not an object"]
    inputs = case.get("inputs")
    if not isinstance(inputs, dict):
        return ["inputs is not an object"]

    bridge = inputs.get("bridge")
    authorization = bridge.get("authorization") if isinstance(bridge, dict) else None
    values = {
        "authorization_signature": (
            {"profile": BRIDGE_PROFILE, "authorization": authorization}
            if isinstance(authorization, dict)
            else None
        ),
        "declaration_digest": inputs.get("declaration"),
        "tool_call_digest": inputs.get("tool_call"),
    }
    expected_non_applicable: dict[str, str | None] = {
        "authorization_signature": None,
        "declaration_digest": None,
        "tool_call_digest": None,
    }
    if not isinstance(bridge, dict):
        expected_non_applicable["authorization_signature"] = "bridge_not_object"
    elif bridge.get("profile") != BRIDGE_PROFILE:
        expected_non_applicable["authorization_signature"] = "bridge_profile_invalid"
    elif not isinstance(authorization, dict):
        expected_non_applicable["authorization_signature"] = "authorization_not_object"
    else:
        try:
            rfc8785.dumps(values["authorization_signature"])
        except Exception:
            expected_non_applicable["authorization_signature"] = "authorization_preimage_not_jcs"

    for name, not_object, not_jcs in (
        ("declaration_digest", "declaration_not_object", "declaration_preimage_not_jcs"),
        ("tool_call_digest", "tool_call_not_object", "tool_call_preimage_not_jcs"),
    ):
        value = values[name]
        if not isinstance(value, dict):
            expected_non_applicable[name] = not_object
            continue
        try:
            rfc8785.dumps(value)
        except Exception:
            expected_non_applicable[name] = not_jcs

    errors: list[str] = []
    for name, value in values.items():
        item = declared.get(name)
        if not isinstance(item, dict):
            errors.append(f"reproducibility.{name} is not an object")
            continue
        if item.get("applicable") is not True:
            if item.get("applicable") is not False:
                errors.append(f"reproducibility.{name}.applicable is not boolean")
                continue
            wanted_reason = expected_non_applicable[name]
            if wanted_reason is None:
                errors.append(
                    f"reproducibility.{name} is marked non-applicable although its "
                    "canonical material exists"
                )
            elif item.get("reason") != wanted_reason:
                errors.append(
                    f"reproducibility.{name}.reason differs: "
                    f"declared={item.get('reason')!r}, measured={wanted_reason!r}"
                )
            continue
        if expected_non_applicable[name] is not None:
            errors.append(
                f"reproducibility.{name} claims applicability despite "
                f"{expected_non_applicable[name]}"
            )
            continue
        try:
            measured = _metadata(value)
        except Exception as exc:
            errors.append(
                f"reproducibility.{name} claims applicability but JCS failed: "
                f"{type(exc).__name__}: {exc}"
            )
            continue
        for field, actual in measured.items():
            if item.get(field) != actual:
                errors.append(
                    f"reproducibility.{name}.{field} differs: "
                    f"declared={item.get(field)!r}, measured={actual!r}"
                )
    return errors


def _case_id(case: dict[str, Any], path: Path) -> str:
    value = case.get("id", case.get("case_id", path.stem))
    return value if isinstance(value, str) else path.stem


def _expected_case_schema(expected: dict[str, Any]) -> str:
    value = expected.get("case_schema", expected.get("case_schema_valid"))
    if value is True:
        return "valid"
    if value is False:
        return "invalid"
    return value if isinstance(value, str) else "missing"


def _expected_bridge_schema(expected: dict[str, Any]) -> str:
    value = expected.get("bridge_schema", expected.get("bridge_schema_valid"))
    if value is True:
        return "valid"
    if value is False:
        return "invalid"
    return value if isinstance(value, str) else "missing"


def _conformant_runtime(expected: dict[str, Any]) -> Any:
    return expected.get("conformant_runtime", expected.get("runtime"))


def score_case(
    path: Path,
    case: dict[str, Any],
    case_validator: jsonschema.Draft202012Validator,
    bridge_validator: jsonschema.Draft202012Validator,
) -> dict[str, Any]:
    case_id = _case_id(case, path)
    errors: list[str] = []
    expected = case.get("expected")
    if not isinstance(expected, dict):
        expected = {}
        errors.append("expected is not an object")

    case_schema, case_schema_errors = _schema_result(case_validator, case)
    errors.extend(f"case schema: {message}" for message in case_schema_errors)
    wanted_case_schema = _expected_case_schema(expected)
    if case_schema != wanted_case_schema:
        errors.append(
            f"case schema result differs: expected {wanted_case_schema}, measured {case_schema}"
        )

    inputs = case.get("inputs")
    bridge = inputs.get("bridge") if isinstance(inputs, dict) else None
    bridge_schema, bridge_schema_errors = _schema_result(bridge_validator, bridge)
    wanted_bridge_schema = _expected_bridge_schema(expected)
    if bridge_schema != wanted_bridge_schema:
        errors.append(
            "bridge schema result differs: "
            f"expected {wanted_bridge_schema}, measured {bridge_schema}: "
            + "; ".join(bridge_schema_errors)
        )

    errors.extend(_recompute_reproducibility(case))
    reference: dict[str, Any] | None = None
    independent: dict[str, Any] | None = None
    try:
        if not isinstance(inputs, dict):
            raise TypeError("inputs is not an object")
        reference = reference_outcome(inputs)
    except Exception as exc:
        errors.append(f"reference adapter failed: {type(exc).__name__}: {exc}")
    try:
        independent = verify_case_independent(case)
    except Exception as exc:
        errors.append(f"independent verifier failed: {type(exc).__name__}: {exc}")

    target = _conformant_runtime(expected)
    conformance = case.get("conformance")
    if not isinstance(conformance, dict):
        conformance = {}
        errors.append("conformance is not an object")
    status = conformance.get("status", case.get("status"))

    if status == "conformant":
        forbidden = {"tracker", "counted_as_conformance", "reference"} & set(conformance)
        if forbidden:
            errors.append(f"conformant case has known-defect fields: {sorted(forbidden)}")
        if reference != target:
            errors.append(f"reference differs: expected={target!r}, observed={reference!r}")
        if independent != target:
            errors.append(f"independent differs: expected={target!r}, observed={independent!r}")
    elif status == "known_defect":
        if conformance.get("tracker") != KNOWN_DEFECT_TRACKER:
            errors.append("known defect tracker is not issue #247")
        if conformance.get("counted_as_conformance") is not False:
            errors.append("known defect must set counted_as_conformance to false")
        recorded_reference = conformance.get("reference")
        if not isinstance(recorded_reference, dict):
            recorded_reference = {}
            errors.append("known defect reference is not an object")
        if recorded_reference.get("implementation") != REFERENCE_IMPLEMENTATION:
            errors.append("known defect reference implementation is not pinned")
        baseline = recorded_reference.get("baseline_commit")
        if baseline != REFERENCE_BASELINE:
            errors.append(
                "known defect reference baseline_commit is not the pinned corpus baseline"
            )
        observed_reference = recorded_reference.get("runtime")
        if reference != observed_reference:
            errors.append(
                "reference defect observation differs: "
                f"recorded={observed_reference!r}, observed={reference!r}"
            )
        if independent != target:
            errors.append(
                f"independent differs from conformant target: {target!r} != {independent!r}"
            )
        if observed_reference == target:
            errors.append("known defect does not record a reference/conformant divergence")
    else:
        errors.append(f"unknown conformance status: {status!r}")

    return {
        "id": case_id,
        "path": path.name,
        "status": status,
        "case_schema": case_schema,
        "bridge_schema": bridge_schema,
        "expected": target,
        "reference": reference,
        "independent": independent,
        "passed": not errors,
        "errors": errors,
    }


def run_corpus() -> dict[str, Any]:
    raise RuntimeError(
        "Full-corpus certification remains held; run --case-003 for the bounded review"
    )


def _frozen_run_corpus() -> dict[str, Any]:
    case_schema = _load_json(CASE_SCHEMA_PATH)
    bridge_schema = _load_json(BRIDGE_SCHEMA_PATH)
    jsonschema.Draft202012Validator.check_schema(case_schema)
    jsonschema.Draft202012Validator.check_schema(bridge_schema)
    case_validator = jsonschema.Draft202012Validator(case_schema)
    bridge_validator = jsonschema.Draft202012Validator(bridge_schema)
    loaded = load_cases()
    cases = [score_case(path, case, case_validator, bridge_validator) for path, case in loaded]
    conformant = [case for case in cases if case["status"] == "conformant"]
    diagnostics = [case for case in cases if case["status"] == "known_defect"]
    global_errors: list[str] = []
    if len(diagnostics) != 2:
        global_errors.append(
            f"expected exactly two known-defect diagnostics, found {len(diagnostics)}"
        )
    failed = [case for case in cases if not case["passed"]]
    return {
        "summary": {
            "total": len(cases),
            "conformant_total": len(conformant),
            "conformant_passed": sum(case["passed"] for case in conformant),
            "diagnostic_total": len(diagnostics),
            "diagnostic_passed": sum(case["passed"] for case in diagnostics),
            "failed": len(failed) + len(global_errors),
        },
        "global_errors": global_errors,
        "cases": cases,
        "passed": not failed and not global_errors,
    }


def mutation_report() -> dict[str, Any]:
    raise RuntimeError("The frozen 45-rule mutation claim is not recertified by the case-003 patch")


def _frozen_mutation_report() -> dict[str, Any]:
    cases = [
        case
        for _, case in load_cases()
        if case.get("conformance", {}).get("status") == "conformant"
    ]
    baseline = {_case_id(case, Path("unknown")): verify_case_independent(case) for case in cases}
    matrix: dict[str, list[str]] = {}
    for rule in RULES:
        changed = []
        for case in cases:
            case_id = _case_id(case, Path("unknown"))
            mutated = verify_case_independent(case, disabled_codes={rule.code})
            if mutated != baseline[case_id]:
                changed.append(case_id)
        matrix[rule.code] = sorted(changed)
    uncovered = [code for code in RULE_CODES if not matrix[code]]
    return {
        "rules": len(RULES),
        "conformant_cases": len(cases),
        "changed_by_rule": matrix,
        "uncovered_rules": uncovered,
        "passed": not uncovered,
    }


def _print_human(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(
        "PIC/TRACE bridge corpus: "
        f"{summary['conformant_passed']}/{summary['conformant_total']} conformant, "
        f"{summary['diagnostic_passed']}/{summary['diagnostic_total']} diagnostics, "
        f"{summary['failed']} failures"
    )
    for message in report["global_errors"]:
        print(f"GLOBAL: {message}")
    for case in report["cases"]:
        label = "PASS" if case["passed"] else "FAIL"
        print(f"{label} {case['id']} [{case['status']}]")
        for message in case["errors"]:
            print(f"  {message}")


def _print_mutation_human(report: dict[str, Any]) -> None:
    print(
        f"Rule-deletion matrix: {report['rules']} rules across "
        f"{report['conformant_cases']} conformant cases"
    )
    for code, cases in report["changed_by_rule"].items():
        print(f"{code}: {', '.join(cases) if cases else 'NO LOAD-BEARING CASE'}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    parser.add_argument(
        "--mutation-report",
        action="store_true",
        help="report which conformant vectors notice each deleted rule",
    )
    parser.add_argument(
        "--case-003", action="store_true", help="run only the reconciled case-003 family"
    )
    args = parser.parse_args(argv)

    try:
        if args.case_003:
            from case003_runner import run

            report = run()
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["passed"] else 1
        if args.mutation_report:
            report = mutation_report()
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                _print_mutation_human(report)
            return 0 if report["passed"] else 1

        report = run_corpus()
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            _print_human(report)
        return 0 if report["passed"] else 1
    except Exception as exc:
        if args.json:
            print(
                json.dumps(
                    {"passed": False, "fatal": f"{type(exc).__name__}: {exc}"},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"FATAL {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

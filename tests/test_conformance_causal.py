"""Causal coverage for the portable corpus: disabling a gate admits its counterexample.

For each token-level requirement, the unmodified reference must reject the named
counterexample with its expected code, and an in-memory mutant with that single
gate disabled must admit it while the requirement's positive vector still passes.
The isolation test disables each counterexample's own reason code and requires the
vector to become valid, which shows no second, order-dependent defect is present.
The working source is never modified.
"""

from __future__ import annotations

import itertools
import re
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from prototype import verifier_token as v
from tests.test_conformance_corpus import CORPUS, NON_PORTABLE, REQUIREMENTS, load, outcome, vectors

SOURCE = Path(v.__file__).read_text()
_COUNTER = itertools.count()


def disable(code: str) -> tuple[str, str, int]:
    """Replace every `raise ProfileError("code")` (with or without `from exc`) by `pass`."""
    return ("re:" + code, "pass", len(_raises(code).findall(SOURCE)))


def _raises(code: str) -> re.Pattern[str]:
    return re.compile(r'raise ProfileError\("' + re.escape(code) + r'"\)(?: from exc)?')


def mutant(changes: list[tuple[str, str, int]]) -> Any:
    source = SOURCE
    for before, after, count in changes:
        if before.startswith("re:"):
            pattern = _raises(before[3:])
            assert count >= 1 and len(pattern.findall(source)) == count, before
            source = pattern.sub(after, source)
        else:
            assert source.count(before) == count, before
            source = source.replace(before, after)
    module = types.ModuleType(f"verifier_token_conformance_mutant_{next(_COUNTER)}")
    sys.modules[module.__name__] = module
    exec(compile(source, "<conformance-mutant>", "exec"), module.__dict__)
    return module


def same(before: str, after: str) -> tuple[str, str, int]:
    return (before, after, 1)


STATUS_GATE = [same("composite.status != overall", "False")]
LOOKUP_BY_KID_ONLY = [
    same(
        "trusted = context.trusted_issuers.get((token.iss, kid))",
        "trusted = next((t for (i, k), t in context.trusted_issuers.items() if k == kid), None)",
    ),
    same("if trusted is None or trusted.issuer != token.iss:", "if trusted is None:"),
]

# (requirement, counterexample id, mutation disabling the gate that enforces it)
CAUSAL: list[tuple[str, str, list[tuple[str, str, int]]]] = [
    (
        "TR-VT-PROFILE-001",
        "VT-PROFILE-004",
        [same("or headers[PROFILE_HEADER] != profile", "or False")],
    ),
    (
        "TR-VT-PROFILE-002",
        "VT-PROFILE-007",
        [
            same(
                '    profile: Literal["urn:agentrust:trace:verifier-token:experimental-v1"]',
                "    profile: Text",
            )
        ],
    ),
    ("TR-VT-ENV-001", "VT-ENV-006", [disable("signature_invalid")]),
    ("TR-VT-ISS-001", "VT-ISS-004", LOOKUP_BY_KID_ONLY),
    ("TR-VT-ISS-002", "VT-ISS-008", LOOKUP_BY_KID_ONLY),
    ("TR-VT-CNF-001", "VT-CNF-003", [disable("issuer_holder_same_key")]),
    ("TR-VT-CNF-002", "VT-CNF-008", [disable("holder_proof_binding")]),
    ("TR-VT-TIME-001", "VT-TIME-004", [disable("token_expired_or_future")]),
    # Two gates by construction; see NO_SINGLE_GATE.
    (
        "TR-VT-TIME-002",
        "VT-TIME-007",
        [disable("token_expired_or_future"), disable("component_expired")],
    ),
    ("TR-VT-TIME-003", "VT-TIME-009", [disable("expiry_exceeds_evidence")]),
    ("TR-VT-AUD-001", "VT-AUD-003", [disable("audience_mismatch")]),
    (
        "TR-VT-ID-001",
        "VT-ID-002",
        [same("    jti: Identifier\n", "    jti: Identifier | None = None\n")],
    ),
    ("TR-VT-SUB-001", "VT-SUB-002", [disable("subject_or_instance_mismatch")]),
    ("TR-VT-SUB-002", "VT-SUB-006", [disable("subject_or_instance_mismatch")]),
    ("TR-VT-MAN-001", "VT-MAN-002", [disable("manifest_mismatch")]),
    ("TR-VT-MAN-002", "VT-MAN-006", [disable("manifest_mismatch")]),
    ("TR-VT-CTX-001", "VT-CTX-002", [disable("context_mismatch")]),
    ("TR-VT-POL-001", "VT-POL-003", [disable("policy_mismatch")]),
    ("TR-VT-REV-001", "VT-REV-002", [disable("status_not_active")]),
    ("TR-VT-PRIV-001", "VT-PRIV-002", [('extra="forbid"', 'extra="ignore"', 1)]),
    ("TR-VT-PRIV-002", "VT-PRIV-006", [disable("binding_digest_mismatch")]),
    ("TR-VT-EXT-001", "VT-EXT-002", [same("if unprotected != {} or not all(", "if not all(")]),
    ("TR-COMP-ID-001", "COMP-ID-002", [disable("duplicate_component")]),
    ("TR-COMP-ID-002", "COMP-ID-007", [disable("undeclared_component")]),
    ("TR-COMP-TYPE-001", "COMP-TYPE-004", [disable("component_type_mismatch")]),
    (
        "TR-COMP-REQ-001",
        "COMP-REQ-004",
        [same("or composite.required_components != required", "or False")],
    ),
    ("TR-COMP-REQ-002", "COMP-REQ-006", STATUS_GATE),
    ("TR-COMP-STAT-001", "COMP-STAT-003", STATUS_GATE),
    (
        "TR-COMP-STAT-002",
        "COMP-STAT-006",
        [
            same(
                '("contraindicated", "missing", "unverifiable", "not-appraised")',
                '("contraindicated", "missing")',
            )
        ],
    ),
    (
        "TR-COMP-WARN-001",
        "COMP-WARN-002",
        [
            same(
                'overall = "warning" if requirements.allow_warnings else "contraindicated"',
                'overall = "warning"',
            )
        ],
    ),
    ("TR-COMP-EVID-001", "COMP-EVID-009", [disable("evidence_profile_mismatch")]),
    ("TR-COMP-EVID-002", "COMP-EVID-006", [disable("evidence_missing")]),
    (
        "TR-COMP-AUTH-001",
        "COMP-AUTH-002",
        [same('            status = "unverifiable"', "            pass")],
    ),
    ("TR-COMP-FRESH-001", "COMP-FRESH-003", [disable("component_interval")]),
    (
        "TR-COMP-FRESH-002",
        "COMP-FRESH-006",
        [same("or composite.fresh_until != fresh_until", "or False")],
    ),
    ("TR-COMP-BIND-001", "COMP-BIND-004", [disable("undeclared_binding")]),
    ("TR-COMP-BIND-002", "COMP-BIND-007", [disable("binding_digest_mismatch")]),
    ("TR-COMP-BIND-003", "COMP-BIND-013", [disable("binding_interval")]),
    ("TR-COMP-BIND-004", "COMP-BIND-012", [disable("mixed_instance")]),
    ("TR-COMP-COMP-001", "COMP-COMP-004", [same("or composite.policy != policy", "or False")]),
    ("TR-COMP-COMP-002", "COMP-COMP-006", STATUS_GATE),
    ("TR-COMP-MCP-001", "COMP-MCP-002", [disable("component_observation_mismatch")]),
]

# Requirements without a single disableable gate at the token level.
NO_SINGLE_GATE = {
    "TR-VT-TIME-002": "Expiry is enforced twice by construction: the signed [iat, exp) window "
    "and the composite freshness boundary, which always includes exp. The causal entry "
    "disables both; the gateway-level single-gate check is "
    "test_disabling_transport_recheck_admits_expired_call.",
}
NO_SINGLE_GATE.update(
    {req: "Non-portable: " + reason for req, (reason, _tests) in NON_PORTABLE.items()}
)

# Codes whose raise can be replaced by `pass` without breaking later control flow.
CONTINUABLE = {
    "issuer_expired",
    "signature_invalid",
    "key_id_mismatch",
    "issuer_holder_same_key",
    "token_expired_or_future",
    "token_lifetime",
    "expiry_exceeds_credential",
    "audience_mismatch",
    "subject_or_instance_mismatch",
    "manifest_mismatch",
    "context_mismatch",
    "policy_mismatch",
    "status_not_active",
    "duplicate_component",
    "undeclared_component",
    "duplicate_binding",
    "undeclared_binding",
    "component_type_mismatch",
    "component_observation_mismatch",
    "mixed_instance",
    "component_interval",
    "component_age_bound",
    "evidence_missing",
    "evidence_profile_mismatch",
    "binding_digest_mismatch",
    "binding_interval",
    "expiry_exceeds_evidence",
    "component_expired",
    "composite_inconsistent",
    "holder_proof_binding",
    "holder_proof_expired",
}

# Documented cases where disabling the first code reveals a second check of the same defect.
KNOWN_SECOND_CHECK = {
    "VT-TIME-003": "component_expired",
    "VT-TIME-007": "component_expired",
    "VT-TIME-012": "component_expired",
    "LEGACY-06": "composite_inconsistent",
    "LEGACY-07": "binding_digest_mismatch",
}


def vector(vid: str) -> dict[str, Any]:
    return load(CORPUS / "vectors" / (vid + ".json"))


def first_positive(requirement: str) -> dict[str, Any]:
    return next(
        vec
        for vec in sorted(vectors(), key=lambda item: item["id"])
        if vec["kind"] == "positive"
        and requirement in vec["requirements"]
        and not vec["id"].startswith("LEGACY-")
    )


def admitted(result: dict[str, Any]) -> bool:
    return result["token"] == "valid" and result["proof"] in (None, "valid")


@pytest.mark.parametrize("requirement,vid,changes", CAUSAL, ids=[entry[0] for entry in CAUSAL])
def test_disabling_gate_admits_counterexample(requirement, vid, changes):
    counterexample = vector(vid)
    assert requirement in counterexample["requirements"]
    assert counterexample["kind"] == "counterexample"
    assert outcome(counterexample) == counterexample["expected"]
    assert not admitted(outcome(counterexample))
    module = mutant(changes)
    assert admitted(outcome(counterexample, module)), outcome(counterexample, module)
    positive = first_positive(requirement)
    assert outcome(positive, module) == positive["expected"]


def test_every_requirement_has_a_causal_check_or_a_reason():
    causal = {entry[0] for entry in CAUSAL}
    assert causal.isdisjoint(NON_PORTABLE)
    for requirement in REQUIREMENTS:
        assert requirement in causal or requirement in NO_SINGLE_GATE, requirement


def isolation_cases() -> list[str]:
    cases = []
    for vec in vectors():
        code = (
            vec["expected"]["proof"]
            if vec["expected"]["token"] == "valid"
            else vec["expected"]["token"]
        )
        if vec["kind"] == "counterexample" and code in CONTINUABLE:
            cases.append(vec["id"])
    return sorted(cases)


@pytest.mark.parametrize("vid", isolation_cases())
def test_counterexample_isolates_one_defect(vid):
    vec = vector(vid)
    code = (
        vec["expected"]["proof"]
        if vec["expected"]["token"] == "valid"
        else vec["expected"]["token"]
    )
    result = outcome(vec, mutant([disable(code)]))
    if vid in KNOWN_SECOND_CHECK:
        assert KNOWN_SECOND_CHECK[vid] in (result["token"], result["proof"]), result
    else:
        assert admitted(result), result


# Stage 4: delegated component appraisal and same-evidence-v1. Each gate names its
# counterexample and the positive vector that must still pass with the gate disabled.
STAGE4_CAUSAL: list[tuple[str, str, str, str, list[tuple[str, str, int]]]] = [
    (
        "appraisal-unexpected",
        "TR-COMP-AUTH-001",
        "COMP-AUTH-016",
        "COMP-AUTH-006",
        [disable("component_appraisal_unexpected")],
    ),
    (
        "appraisal-envelope-profile",
        "TR-COMP-AUTH-001",
        "COMP-AUTH-017",
        "COMP-AUTH-006",
        [
            same("or headers[3] != MEDIA_TYPES[profile]", "or False"),
            same("or headers[PROFILE_HEADER] != profile", "or False"),
        ],
    ),
    (
        "appraisal-validity",
        "TR-COMP-AUTH-001",
        "COMP-AUTH-012",
        "COMP-AUTH-006",
        [same("not appraiser.valid_from <= now < appraiser.valid_until", "False")],
    ),
    (
        "appraisal-signature",
        "TR-COMP-AUTH-001",
        "COMP-AUTH-007",
        "COMP-AUTH-006",
        [disable("component_appraisal_signature_invalid")],
    ),
    (
        "appraisal-mismatch",
        "TR-COMP-AUTH-001",
        "COMP-AUTH-008",
        "COMP-AUTH-006",
        [disable("component_appraisal_mismatch")],
    ),
    (
        "appraisal-grant",
        "TR-COMP-AUTH-001",
        "COMP-AUTH-010",
        "COMP-AUTH-006",
        [same("return granted and component.profile in appraiser.profiles", "return True")],
    ),
    (
        "same-evidence",
        "TR-COMP-BIND-003",
        "COMP-BIND-017",
        "COMP-BIND-015",
        [disable("binding_evidence_disjoint")],
    ),
]


@pytest.mark.parametrize(
    "gate,requirement,vid,positive_id,changes",
    STAGE4_CAUSAL,
    ids=[entry[0] for entry in STAGE4_CAUSAL],
)
def test_disabling_stage4_gate_admits_counterexample(gate, requirement, vid, positive_id, changes):
    counterexample = vector(vid)
    assert requirement in counterexample["requirements"]
    assert counterexample["kind"] == "counterexample"
    assert outcome(counterexample) == counterexample["expected"]
    assert not admitted(outcome(counterexample))
    module = mutant(changes)
    assert admitted(outcome(counterexample, module)), (gate, outcome(counterexample, module))
    positive = vector(positive_id)
    assert positive["kind"] == "positive"
    assert outcome(positive, module) == positive["expected"]


def test_every_stage4_refusal_code_has_a_causal_gate():
    codes = {
        "component_appraisal_unexpected",
        "component_appraisal_signature_invalid",
        "component_appraisal_mismatch",
        "binding_evidence_disjoint",
    }
    disabled = {
        before[3:] for *_, changes in STAGE4_CAUSAL for before, _after, _n in changes
    } & codes
    assert disabled == codes
    # component_appraisal_malformed is shown through the envelope-profile gate.
    assert vector("COMP-AUTH-017")["expected"]["token"] == "component_appraisal_malformed"

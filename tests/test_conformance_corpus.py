"""Portable RFC-0001/0002 conformance corpus replayed against the Python reference.

The vectors come from examples/verifier-token-conformance/gen_corpus.py, which
builds every envelope from primitives. This file also owns the completeness gate:
each of the 47 requirement IDs has one positive and two counterexample vectors,
or an explicit NON_PORTABLE entry naming the gateway-level tests that cover it.
"""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from prototype import verifier_token as v

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "examples/verifier-token-conformance"
VECTOR_FILES = sorted((CORPUS / "vectors").glob("*.json"))

REQUIREMENTS = [
    "TR-VT-PROFILE-001",
    "TR-VT-PROFILE-002",
    "TR-VT-ENV-001",
    "TR-VT-ISS-001",
    "TR-VT-ISS-002",
    "TR-VT-CNF-001",
    "TR-VT-CNF-002",
    "TR-VT-TIME-001",
    "TR-VT-TIME-002",
    "TR-VT-TIME-003",
    "TR-VT-AUD-001",
    "TR-VT-ID-001",
    "TR-VT-SUB-001",
    "TR-VT-SUB-002",
    "TR-VT-MAN-001",
    "TR-VT-MAN-002",
    "TR-VT-MAN-003",
    "TR-VT-CTX-001",
    "TR-VT-POL-001",
    "TR-VT-REV-001",
    "TR-VT-PRIV-001",
    "TR-VT-PRIV-002",
    "TR-VT-AUTH-001",
    "TR-VT-REC-001",
    "TR-VT-EXT-001",
    "TR-COMP-ID-001",
    "TR-COMP-ID-002",
    "TR-COMP-TYPE-001",
    "TR-COMP-REQ-001",
    "TR-COMP-REQ-002",
    "TR-COMP-STAT-001",
    "TR-COMP-STAT-002",
    "TR-COMP-WARN-001",
    "TR-COMP-EVID-001",
    "TR-COMP-EVID-002",
    "TR-COMP-AUTH-001",
    "TR-COMP-FRESH-001",
    "TR-COMP-FRESH-002",
    "TR-COMP-BIND-001",
    "TR-COMP-BIND-002",
    "TR-COMP-BIND-003",
    "TR-COMP-BIND-004",
    "TR-COMP-COMP-001",
    "TR-COMP-COMP-002",
    "TR-COMP-MCP-001",
    "TR-COMP-MCP-002",
    "TR-COMP-MIN-001",
]

GATE = "tests/test_cmcp_trace_gate.py::"
PROFILE_TESTS = "tests/test_verifier_token_profile.py::"
LOCAL = "tests/test_conformance_gateway.py::"

# Requirements whose rule lives at the gateway, manifest or disclosure layer.
NON_PORTABLE: dict[str, tuple[str, list[str]]] = {
    "TR-VT-MAN-003": (
        "Composition-only scope is decided by the Agent Manifest requirements verifier before any "
        "token exists; the token profile has no limited-scope result to vector.",
        [LOCAL + "test_composition_only_manifest_cannot_drive_requirements"],
    ),
    "TR-VT-AUTH-001": (
        "Authorization is the relying party's Cedar decision after token acceptance; a token "
        "vector cannot express the policy outcome.",
        [
            GATE + "test_real_cedar_denies_affirming_trace_without_transport",
            GATE + "test_real_proxy_allows_and_receipt_precedes_transport",
            PROFILE_TESTS + "test_one_use_challenge_and_policy_deny",
        ],
    ),
    "TR-VT-REC-001": (
        "Decision receipts are signed by the gateway key over session, call and action state "
        "that exists only inside the gateway.",
        [
            GATE + "test_real_proxy_allows_and_receipt_precedes_transport",
            GATE + "test_signed_receipts_link_across_worker_restarts",
            LOCAL + "test_receipt_binds_exact_trace_action_and_gateway_key",
        ],
    ),
    "TR-COMP-MCP-002": (
        "Server-to-catalog binding needs a relationship profile the token does not define; "
        "the gateway enforces it on the holder-proved action.",
        [
            GATE + "test_catalog_substitution_after_proof_stops_transport",
            "tests/test_cmcp_bootstrap.py::test_production_composition_requires_verified_manifest",
        ],
    ),
    "TR-COMP-MIN-001": (
        "Informative SHOULD on disclosure; there is no pass/fail wire outcome to vector.",
        [
            PROFILE_TESTS + "test_private_key_or_unknown_fields_rejected",
            "tests/test_conformance_corpus.py::test_valid_tokens_carry_digests_not_raw_material",
        ],
    ),
}

# Additional gateway-level coverage for portable requirements whose rules
# also involve session, cache or channel behavior.
GATEWAY_TESTS: dict[str, list[str]] = {
    "TR-VT-CNF-001": [GATE + "test_workers_atomically_consume_one_proof"],
    "TR-VT-CNF-002": [
        GATE + "test_proxy_refuses_without_transport",
        PROFILE_TESTS + "test_concurrent_proof_has_one_winner",
        LOCAL + "test_missing_or_cross_session_proof_is_refused",
    ],
    "TR-VT-TIME-002": [
        GATE + "test_expiry_during_receipt_commit_stops_transport",
        GATE + "test_expiry_during_provenance_await_stops_actual_send",
        GATE + "test_disabling_transport_recheck_admits_expired_call",
    ],
    "TR-VT-ID-001": [GATE + "test_token_id_collision_survives_worker_restart"],
    "TR-VT-SUB-001": [GATE + "test_http_challenge_admission_and_call_require_auth"],
    "TR-VT-REV-001": [GATE + "test_proxy_refuses_without_transport"],
    "TR-COMP-MCP-001": [
        "tests/test_cmcp_catalog_binding.py::test_merkle_root_is_not_sealed_catalog_digest"
    ],
}

# Reference behavior that differs from the requirements as first written.
DIVERGENCES = {
    "COMP-EVID-003": "The requirements as first written expected rejection when the evidence "
    "resolver is missing; the experimental profile makes resolver optional and the reference "
    "accepts it.",
}


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def build_context(block: dict[str, Any], module: Any = v) -> Any:
    """Construct a VerificationContext (in `module`'s types) from a vector context block."""
    issuers = {}
    for entry in block["trusted_issuers"]:
        key = Ed25519PublicKey.from_public_bytes(unb64url(entry["public_b64url"]))
        issuer = module.TrustedIssuer(
            entry["issuer"], key, entry["valid_from"], entry["valid_until"]
        )
        issuers[(issuer.issuer, module.key_id(key))] = issuer
    appraisers = {}
    for entry in block.get("trusted_appraisers", []):
        key = Ed25519PublicKey.from_public_bytes(unb64url(entry["public_b64url"]))
        appraiser = module.TrustedAppraiser(
            entry["authority"],
            key,
            frozenset(entry["profiles"]),
            frozenset(entry["component_types"]),
            entry["valid_from"],
            entry["valid_until"],
        )
        appraisers[(appraiser.authority, module.key_id(key))] = appraiser
    status = block["status"]

    def status_check(token: Any, now: int) -> bool:
        if status == "unavailable":
            raise OSError("status service unavailable")
        return status == "active"

    return module.VerificationContext(
        audience=block["audience"],
        subject=block["subject"],
        instance=block["instance"],
        manifest_bytes=base64.b64decode(block["manifest_b64"]),
        manifest_id=block["manifest_id"],
        manifest_valid_until=block["manifest_valid_until"],
        question_digest=block["question_digest"],
        policy=module.Policy.model_validate(block["policy"]),
        requirements=module.Requirements.model_validate(block["requirements"]),
        trusted_issuers=issuers,
        status_check=status_check,
        maximum_lifetime=block["maximum_lifetime"],
        trusted_appraisers=appraisers,
    )


def outcome(vector: dict[str, Any], module: Any = v) -> dict[str, Any]:
    """Run a vector and report {token, composite_status, proof} like `expected`."""
    raw = base64.b64decode(vector["envelope_b64"])
    context = build_context(vector["context"], module)
    try:
        token = module.verify_token(raw, context, vector["now"])
    except module.ProfileError as exc:
        return {"token": str(exc), "composite_status": None, "proof": None}
    result = {"token": "valid", "composite_status": token.composite_appraisal.status, "proof": None}
    block = vector["proof"]
    if block is not None:
        try:
            module.verify_proof(
                base64.b64decode(block["proof_b64"]),
                raw,
                token,
                nonce=block["nonce"],
                audience=block["audience"],
                session_id=block["session_id"],
                action_digest=block["action_digest"],
                challenge_issued_at=block["challenge_issued_at"],
                challenge_expires_at=block["challenge_expires_at"],
                now=vector["now"],
            )
            result["proof"] = "valid"
        except module.ProfileError as exc:
            result["proof"] = str(exc)
    return result


def vectors() -> list[dict[str, Any]]:
    return [load(path) for path in VECTOR_FILES]


@pytest.mark.parametrize("path", VECTOR_FILES, ids=lambda p: p.stem)
def test_vector(path):
    vector = load(path)
    assert vector["id"] == path.stem
    assert outcome(vector) == vector["expected"]


def test_codes_are_the_published_list():
    codes = {c["code"] for c in load(CORPUS / "codes.json")["codes"]}
    source = Path(v.__file__).read_text()
    tree = ast.parse(source)
    raised = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "ProfileError"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            raised.add(node.args[0].value)
    gateway_only = {
        "nonce_shape",
        "challenge_interval",
        "challenge_reused",
        "challenge_capacity",
        "challenge_missing_or_consumed",
        "challenge_action_or_session",
        "appraisal_not_acceptable",
        "warning_not_acceptable",
        "policy_result_invalid",
        "bytes_required",
        "payload_too_large",
    }
    assert codes == (raised - gateway_only) | {"input_invalid"}
    for vector in vectors():
        for key in ("token", "proof"):
            value = vector["expected"][key]
            assert value in (None, "valid") or value in codes, (vector["id"], value)


def test_vector_shape_is_exact():
    for vector in vectors():
        assert set(vector) == {
            "id",
            "requirements",
            "kind",
            "description",
            "context",
            "now",
            "envelope_b64",
            "proof",
            "expected",
        }
        # trusted_appraisers is optional: absent means issuer-only appraisal.
        assert set(vector["context"]) - {"trusted_appraisers"} == {
            "audience",
            "subject",
            "instance",
            "manifest_b64",
            "manifest_id",
            "manifest_valid_until",
            "question_digest",
            "policy",
            "requirements",
            "trusted_issuers",
            "status",
            "maximum_lifetime",
        }
        assert vector["kind"] in ("positive", "counterexample")
        assert set(vector["expected"]) == {"token", "composite_status", "proof"}
        if vector["expected"]["token"] != "valid":
            assert vector["expected"]["composite_status"] is None
            assert vector["proof"] is None
        if vector["kind"] == "positive":
            assert vector["expected"]["token"] == "valid"
            assert vector["expected"]["proof"] in (None, "valid")
        assert set(vector["requirements"]) <= set(REQUIREMENTS)
        text = json.dumps(vector, ensure_ascii=False)
        assert chr(0x2013) not in text and chr(0x2014) not in text


def test_base_token_is_the_legacy_valid_token():
    by_id = {vector["id"]: vector for vector in vectors()}
    assert by_id["VT-PROFILE-001"]["envelope_b64"] == by_id["LEGACY-01"]["envelope_b64"]
    assert len([i for i in by_id if i.startswith("LEGACY-")]) == 14


def coverage_from_vectors() -> dict[str, dict[str, Any]]:
    from tests.test_conformance_causal import CAUSAL

    causal_by_requirement = {entry[0]: entry[1] for entry in CAUSAL}
    table: dict[str, dict[str, Any]] = {}
    for requirement in REQUIREMENTS:
        table[requirement] = {
            "positive": [],
            "counterexamples": [],
            "causal": None,
            "gateway_tests": [],
            "non_portable_reason": None,
        }
    for vector in vectors():
        if vector["id"].startswith("LEGACY-"):
            continue
        for requirement in vector["requirements"]:
            key = "positive" if vector["kind"] == "positive" else "counterexamples"
            table[requirement][key].append(vector["id"])
    for requirement, row in table.items():
        row["positive"].sort()
        row["counterexamples"].sort()
        vector_id = causal_by_requirement.get(requirement)
        if vector_id is not None:
            row["causal"] = (
                "tests/test_conformance_causal.py::test_disabling_gate_admits_counterexample["
                + requirement
                + "]"
            )
        if requirement in NON_PORTABLE:
            reason, tests = NON_PORTABLE[requirement]
            row["non_portable_reason"] = reason
            row["gateway_tests"] = list(tests)
        row["gateway_tests"] += GATEWAY_TESTS.get(requirement, [])
    return table


def test_every_requirement_is_covered_or_explicitly_non_portable():
    table = coverage_from_vectors()
    assert len(table) == 47
    for requirement, row in table.items():
        if requirement in NON_PORTABLE:
            assert row["gateway_tests"], requirement
            continue
        assert len(row["positive"]) >= 1, requirement
        assert len(row["counterexamples"]) >= 2, requirement
        # At least two counterexamples must be refusals, not only non-affirming results.
        refusals = [
            vid
            for vid in row["counterexamples"]
            if load(CORPUS / "vectors" / (vid + ".json"))["expected"]["token"] != "valid"
            or load(CORPUS / "vectors" / (vid + ".json"))["expected"]["proof"]
            not in (None, "valid")
        ]
        assert len(refusals) >= 2, requirement


def test_named_gateway_tests_exist():
    for requirement, row in coverage_from_vectors().items():
        for name in row["gateway_tests"]:
            file, function = name.split("::")
            tree = ast.parse((ROOT / file).read_text())
            names = {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            assert function in names, (requirement, name)


def test_coverage_file_is_current():
    expected = {
        "requirements": coverage_from_vectors(),
        "legacy": sorted(v["id"] for v in vectors() if v["id"].startswith("LEGACY-")),
        "divergences": DIVERGENCES,
    }
    assert load(CORPUS / "coverage.json") == expected


def test_valid_tokens_carry_digests_not_raw_material():
    forbidden = {"d", "p", "q", "k", "prompt", "private_key", "quote", "raw", "secret"}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            assert not forbidden & set(value), sorted(forbidden & set(value))
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for vector in vectors():
        if vector["expected"]["token"] != "valid":
            continue
        raw = base64.b64decode(vector["envelope_b64"])
        token = v.read_payload(v.unpack(raw, v.PROFILE)[1], v.Token)
        walk(token.model_dump(mode="json"))
        for component in token.components:
            for ref in component.evidence_refs:
                assert ref.digest.startswith("sha256:")


def write_coverage() -> None:
    value = {
        "requirements": coverage_from_vectors(),
        "legacy": sorted(v["id"] for v in vectors() if v["id"].startswith("LEGACY-")),
        "divergences": DIVERGENCES,
    }
    (CORPUS / "coverage.json").write_text(json.dumps(value, indent=1) + "\n")


if __name__ == "__main__":
    write_coverage()

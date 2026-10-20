"""Verification tests for the Python delegation-link and A2A chain module."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from agentrust_trace import delegation, generate_key, key_to_jwk, sign_record, verify_record

VECTOR_DIR = Path(__file__).resolve().parents[1] / "examples" / "delegation-link"
VECTOR_PATHS = sorted(VECTOR_DIR.glob("*.json"))


def _load(name: str) -> dict[str, Any]:
    return dict(json.loads((VECTOR_DIR / name).read_text(encoding="utf-8")))


def test_parent_record_hash_matches_published_vectors() -> None:
    vec01 = _load("01-valid-single-hop.json")
    leaf, parent = vec01["records"][0], vec01["records"][1]
    assert delegation.parent_record_hash(leaf, "sha256") == vec01["context"]["leaf"]
    assert (
        delegation.parent_record_hash(parent, "sha256")
        == leaf["delegation"]["parent_record_hash"]
    )

    vec22 = _load("22-leaf-link-uses-sha384.json")
    leaf22, parent22 = vec22["records"][0], vec22["records"][1]
    assert (
        delegation.parent_record_hash(parent22, "sha384")
        == leaf22["delegation"]["parent_record_hash"]
    )

    vec24 = _load("24-parent-key-supplementary-plane.json")
    leaf24, parent24 = vec24["records"][0], vec24["records"][1]
    assert (
        delegation.parent_record_hash(parent24, "sha256")
        == leaf24["delegation"]["parent_record_hash"]
    )


def test_parent_record_hash_refuses_invalid_inputs() -> None:
    bad_algs: tuple[Any, ...] = ("sha512", "md5", "", 123, None)
    for bad_alg in bad_algs:
        with pytest.raises(delegation.DelegationError, match="unsupported chain digest"):
            delegation.parent_record_hash({"a": 1}, bad_alg)
    bad_records: tuple[Any, ...] = (None, "not-a-dict", [1, 2], 42)
    for bad_record in bad_records:
        with pytest.raises(delegation.DelegationError, match="JSON object"):
            delegation.parent_record_hash(bad_record)
    for uncanonical in (
        {"x": float("nan")},
        {"x": 10**20},
        {"\ud800": 1},
        {"x": "\ud800"},
    ):
        with pytest.raises(delegation.DelegationError, match="RFC 8785"):
            delegation.parent_record_hash(uncanonical)


def test_verify_delegation_link_succeeds_for_sha256_and_sha384() -> None:
    vec01 = _load("01-valid-single-hop.json")
    link01 = delegation.verify_delegation_link(vec01["records"][0], vec01["records"][1])
    assert link01 == delegation.DelegationLink(
        parent_record_hash=vec01["records"][0]["delegation"]["parent_record_hash"],
        algorithm="sha256",
        credential_id="cred:orchestrator-to-planner",
    )

    vec22 = _load("22-leaf-link-uses-sha384.json")
    link22 = delegation.verify_delegation_link(vec22["records"][0], vec22["records"][1])
    assert link22.algorithm == "sha384"
    assert (
        link22.parent_record_hash
        == vec22["records"][0]["delegation"]["parent_record_hash"]
    )


def test_verify_delegation_link_refuses_absent_malformed_unsupported_or_mismatched() -> None:
    vec01 = _load("01-valid-single-hop.json")
    leaf, parent = vec01["records"][0], vec01["records"][1]

    with pytest.raises(delegation.DelegationError, match="no delegation block"):
        delegation.verify_delegation_link(parent, leaf)

    for bad_deleg in ("not-a-dict", {}, {"parent_record_hash": "sha256:00", "credential_id": ""}):
        child = {**leaf, "delegation": bad_deleg}
        with pytest.raises(delegation.DelegationError):
            delegation.verify_delegation_link(child, parent)

    vec22 = _load("22-leaf-link-uses-sha384.json")
    with pytest.raises(delegation.DelegationError, match="does not implement"):
        delegation.verify_delegation_link(
            vec22["records"][0],
            vec22["records"][1],
            supported_digest_algorithms=("sha256",),
        )

    sha512_child = {
        **leaf,
        "delegation": {
            "parent_record_hash": "sha512:" + "a" * 128,
            "credential_id": "cred:orchestrator-to-planner",
        },
    }
    with pytest.raises(delegation.DelegationError, match="not one this build can compute"):
        delegation.verify_delegation_link(
            sha512_child,
            parent,
            supported_digest_algorithms=("sha512",),
        )

    bad_supported_cases: tuple[Any, ...] = ("sha256", b"sha256", {"sha256": 1}, (), [123])
    for bad_supported in bad_supported_cases:
        with pytest.raises(delegation.DelegationError, match="supported_digest_algorithms"):
            delegation.verify_delegation_link(
                leaf, parent, supported_digest_algorithms=bad_supported
            )

    vec05 = _load("05-link-over-signed-body.json")
    with pytest.raises(delegation.DelegationError, match="does not digest"):
        delegation.verify_delegation_link(vec05["records"][0], vec05["records"][1])


@pytest.mark.parametrize("path", VECTOR_PATHS, ids=lambda p: p.stem)
def test_verify_delegation_chain_matches_every_vector(path: Path) -> None:
    vector = json.loads(path.read_text(encoding="utf-8"))
    expected = vector["expected"]

    by_digest = delegation.verify_delegation_chain(
        vector["records"], vector["context"]["leaf"], vector["context"]
    )
    assert by_digest.classification == expected["classification"]
    assert by_digest.codes == sorted(expected["codes"])

    by_record = delegation.verify_delegation_chain(
        vector["records"], vector["records"][0], vector["context"]
    )
    assert by_record == by_digest

    reversed_records = list(reversed(vector["records"]))
    by_reversed = delegation.verify_delegation_chain(
        reversed_records, vector["context"]["leaf"], vector["context"]
    )
    assert by_reversed.classification == by_digest.classification
    assert by_reversed.codes == by_digest.codes


def test_verify_delegation_chain_refuses_malformed_caller_inputs() -> None:
    vec01 = _load("01-valid-single-hop.json")
    records = vec01["records"]
    leaf = vec01["context"]["leaf"]
    context = vec01["context"]

    bad_records_cases: tuple[Any, ...] = (
        "not-iterable-of-dicts",
        {},
        [],
        [{"subject": "x"}],
    )
    for bad_records in bad_records_cases:
        with pytest.raises(delegation.DelegationError):
            delegation.verify_delegation_chain(bad_records, leaf, context)

    bad_leaf_cases: tuple[Any, ...] = (
        None,
        123,
        "no-colon",
        "sha256:" + "0" * 64,
        {},
    )
    for bad_leaf in bad_leaf_cases:
        with pytest.raises(delegation.DelegationError):
            delegation.verify_delegation_chain(records, bad_leaf, context)

    for field_name, bad_val in (
        ("max_depth", -1),
        ("max_depth", True),
        ("supported_digest_algorithms", ("sha512",)),
        ("supported_digest_algorithms", "sha256"),
        ("data_class_lattice", "public"),
        ("trusted_root_keys", "not-a-list"),
        ("credentials", "not-a-dict"),
    ):
        bad_ctx = copy.deepcopy(context)
        bad_ctx[field_name] = bad_val
        with pytest.raises(delegation.DelegationError):
            delegation.verify_delegation_chain(records, leaf, bad_ctx)

    bad_rules_cases: tuple[Any, ...] = ("not-rules", [123])
    for bad_rules in bad_rules_cases:
        with pytest.raises(delegation.DelegationError):
            delegation.verify_delegation_chain(records, leaf, context, rules=bad_rules)


@pytest.mark.parametrize(
    ("vector_name", "lattice", "expected"),
    [
        (
            "01-valid-single-hop.json",
            ["public", "internal", "confidential", "restricted"],
            "verified",
        ),
        ("01-valid-single-hop.json", ["public"], "unverifiable"),
        ("01-valid-single-hop.json", [], "unverifiable"),
        ("18-data-class-widened-at-leaf.json", ["public"], "unverifiable"),
        ("18-data-class-widened-at-leaf.json", ["public", "internal"], "unverifiable"),
        ("18-data-class-widened-at-leaf.json", ["public", "restricted"], "unverifiable"),
    ],
)
def test_unlisted_data_class_reports_unverifiable_and_never_verified(
    vector_name: str, lattice: list[str], expected: str
) -> None:
    vector = _load(vector_name)
    vector["context"]["data_class_lattice"] = lattice
    result = delegation.verify_delegation_chain(
        vector["records"], vector["context"]["leaf"], vector["context"]
    )
    assert result.classification == expected
    assert ("data_class_unknown" in result.codes) == (expected == "unverifiable")


def test_verify_delegation_chain_decides_iat_by_value() -> None:
    """Section 3.2.2 (#404): a whole-valued float `iat` such as 1785000000.0
    has the same JCS form and signature as 1785000000, and must be accepted by
    `verify_delegation_chain` just as `verify_record` accepts it."""
    vec01 = _load("01-valid-single-hop.json")
    leaf = copy.deepcopy(vec01["records"][0])
    parent = vec01["records"][1]
    leaf["iat"] = float(leaf["iat"])
    records = [leaf, parent]

    verify_record(leaf, leaf["cnf"]["jwk"], now=vec01["context"]["now"])

    by_digest = delegation.verify_delegation_chain(
        records, vec01["context"]["leaf"], vec01["context"]
    )
    assert by_digest.classification == "verified"
    assert by_digest.codes == []

    by_dict = delegation.verify_delegation_chain(records, leaf, vec01["context"])
    assert by_dict == by_digest


def test_verify_delegation_chain_refuses_non_canonical_signature_and_unknown_members() -> None:
    """Section 3.2.2 and schema validation: a signature whose final base64url
    character has non-zero unused bits (decoding to the same 64 bytes) or a
    record carrying an unknown top-level member must be refused rather than
    reported as `verified`."""
    vec01 = _load("01-valid-single-hop.json")
    leaf, parent = vec01["records"][0], vec01["records"][1]
    context = vec01["context"]

    sig = leaf["signature"]
    assert sig.endswith("g")
    non_canonical_sig = sig[:-1] + "h"
    assert base64.urlsafe_b64decode(sig + "==") == base64.urlsafe_b64decode(
        non_canonical_sig + "=="
    )
    mutated_leaf = {**leaf, "signature": non_canonical_sig}

    assert delegation._signature_invalid(mutated_leaf) is True
    with pytest.raises(delegation.DelegationError, match="schema"):
        delegation.verify_delegation_chain([mutated_leaf, parent], mutated_leaf, context)

    key = generate_key()
    unsigned = {
        k: v for k, v in leaf.items() if k not in ("signature", "cnf")
    }
    unsigned["extra_top_level_member"] = "forbidden-by-schema"
    signed_with_extra = sign_record(unsigned, key)
    signed_with_extra["cnf"] = {"jwk": key_to_jwk(key)}
    with pytest.raises(delegation.DelegationError, match="schema"):
        delegation.verify_delegation_chain(
            [signed_with_extra, parent], signed_with_extra, context
        )



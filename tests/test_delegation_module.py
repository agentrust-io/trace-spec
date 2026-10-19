"""Verification tests for the Python delegation-link and A2A chain module."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

try:
    from agentrust_trace import delegation as _delegation
except ImportError:
    pytest.fail("unimplemented")

VECTOR_DIR = Path(__file__).resolve().parents[1] / "examples" / "delegation-link"
VECTOR_PATHS = sorted(VECTOR_DIR.glob("*.json"))


def _mod() -> Any:
    if _delegation is None:
        pytest.fail("unimplemented")
    return _delegation


def _load(name: str) -> dict[str, Any]:
    return dict(json.loads((VECTOR_DIR / name).read_text(encoding="utf-8")))


def test_parent_record_hash_matches_published_vectors() -> None:
    mod = _mod()
    vec01 = _load("01-valid-single-hop.json")
    leaf, parent = vec01["records"][0], vec01["records"][1]
    assert mod.parent_record_hash(leaf, "sha256") == vec01["context"]["leaf"]
    assert (
        mod.parent_record_hash(parent, "sha256")
        == leaf["delegation"]["parent_record_hash"]
    )

    vec22 = _load("22-leaf-link-uses-sha384.json")
    leaf22, parent22 = vec22["records"][0], vec22["records"][1]
    assert (
        mod.parent_record_hash(parent22, "sha384")
        == leaf22["delegation"]["parent_record_hash"]
    )

    vec24 = _load("24-parent-key-supplementary-plane.json")
    leaf24, parent24 = vec24["records"][0], vec24["records"][1]
    assert (
        mod.parent_record_hash(parent24, "sha256")
        == leaf24["delegation"]["parent_record_hash"]
    )


def test_parent_record_hash_refuses_invalid_inputs() -> None:
    mod = _mod()
    for bad_alg in ("sha512", "md5", "", 123, None):
        with pytest.raises(mod.DelegationError, match="unsupported chain digest"):
            mod.parent_record_hash({"a": 1}, bad_alg)
    for bad_record in (None, "not-a-dict", [1, 2], 42):
        with pytest.raises(mod.DelegationError, match="JSON object"):
            mod.parent_record_hash(bad_record)
    for uncanonical in (
        {"x": float("nan")},
        {"x": 10**20},
        {"\ud800": 1},
        {"x": "\ud800"},
    ):
        with pytest.raises(mod.DelegationError, match="RFC 8785"):
            mod.parent_record_hash(uncanonical)


def test_verify_delegation_link_succeeds_for_sha256_and_sha384() -> None:
    mod = _mod()
    vec01 = _load("01-valid-single-hop.json")
    link01 = mod.verify_delegation_link(vec01["records"][0], vec01["records"][1])
    assert link01 == mod.DelegationLink(
        parent_record_hash=vec01["records"][0]["delegation"]["parent_record_hash"],
        algorithm="sha256",
        credential_id="cred:orchestrator-to-planner",
    )

    vec22 = _load("22-leaf-link-uses-sha384.json")
    link22 = mod.verify_delegation_link(vec22["records"][0], vec22["records"][1])
    assert link22.algorithm == "sha384"
    assert (
        link22.parent_record_hash
        == vec22["records"][0]["delegation"]["parent_record_hash"]
    )


def test_verify_delegation_link_refuses_absent_malformed_unsupported_or_mismatched() -> None:
    mod = _mod()
    vec01 = _load("01-valid-single-hop.json")
    leaf, parent = vec01["records"][0], vec01["records"][1]

    with pytest.raises(mod.DelegationError, match="no delegation block"):
        mod.verify_delegation_link(parent, leaf)

    for bad_deleg in ("not-a-dict", {}, {"parent_record_hash": "sha256:00", "credential_id": ""}):
        child = {**leaf, "delegation": bad_deleg}
        with pytest.raises(mod.DelegationError):
            mod.verify_delegation_link(child, parent)

    vec22 = _load("22-leaf-link-uses-sha384.json")
    with pytest.raises(mod.DelegationError, match="does not implement"):
        mod.verify_delegation_link(
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
    with pytest.raises(mod.DelegationError, match="not one this build can compute"):
        mod.verify_delegation_link(
            sha512_child,
            parent,
            supported_digest_algorithms=("sha512",),
        )

    for bad_supported in ("sha256", b"sha256", {"sha256": 1}, (), [123]):
        with pytest.raises(mod.DelegationError, match="supported_digest_algorithms"):
            mod.verify_delegation_link(
                leaf, parent, supported_digest_algorithms=bad_supported
            )

    vec05 = _load("05-link-over-signed-body.json")
    with pytest.raises(mod.DelegationError, match="does not digest"):
        mod.verify_delegation_link(vec05["records"][0], vec05["records"][1])


@pytest.mark.parametrize("path", VECTOR_PATHS, ids=lambda p: p.stem)
def test_verify_delegation_chain_matches_every_vector(path: Path) -> None:
    mod = _mod()
    vector = json.loads(path.read_text(encoding="utf-8"))
    expected = vector["expected"]

    by_digest = mod.verify_delegation_chain(
        vector["records"], vector["context"]["leaf"], vector["context"]
    )
    assert by_digest.classification == expected["classification"]
    assert by_digest.codes == sorted(expected["codes"])

    by_record = mod.verify_delegation_chain(
        vector["records"], vector["records"][0], vector["context"]
    )
    assert by_record == by_digest

    reversed_records = list(reversed(vector["records"]))
    by_reversed = mod.verify_delegation_chain(
        reversed_records, vector["context"]["leaf"], vector["context"]
    )
    assert by_reversed.classification == by_digest.classification
    assert by_reversed.codes == by_digest.codes


def test_verify_delegation_chain_refuses_malformed_caller_inputs() -> None:
    mod = _mod()
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
        with pytest.raises(mod.DelegationError):
            mod.verify_delegation_chain(bad_records, leaf, context)

    bad_leaf_cases: tuple[Any, ...] = (
        None,
        123,
        "no-colon",
        "sha256:" + "0" * 64,
        {},
    )
    for bad_leaf in bad_leaf_cases:
        with pytest.raises(mod.DelegationError):
            mod.verify_delegation_chain(records, bad_leaf, context)

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
        with pytest.raises(mod.DelegationError):
            mod.verify_delegation_chain(records, leaf, bad_ctx)

    for bad_rules in ("not-rules", [123]):
        with pytest.raises(mod.DelegationError):
            mod.verify_delegation_chain(records, leaf, context, rules=bad_rules)


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
    mod = _mod()
    vector = _load(vector_name)
    vector["context"]["data_class_lattice"] = lattice
    result = mod.verify_delegation_chain(
        vector["records"], vector["context"]["leaf"], vector["context"]
    )
    assert result.classification == expected
    assert ("data_class_unknown" in result.codes) == (expected == "unverifiable")


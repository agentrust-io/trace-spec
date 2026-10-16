"""Portable TR-ANC-002 fixtures for trace-spec#448 row 22."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from trace_tests.inclusion import canonical_claim_bytes, parse_receipt, verify_inclusion
from trace_tests.modules import tr_anc

VECTOR_DIR = Path(__file__).parent / "vectors" / "anchor-inclusion"
VECTORS = [json.loads(p.read_text()) for p in sorted(VECTOR_DIR.glob("[0-9][0-9]-*.json"))]


@pytest.mark.level2
@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_portable_inclusion_vector(vector):
    finding = next(
        f
        for f in tr_anc.check(vector["claim"], receipt=vector["receipt"])
        if f.code == "TR-ANC-002"
    )
    assert finding.status.value == vector["expected"]["tr_anc_002"]
    if "construction" in vector:
        canonical = canonical_claim_bytes(vector["claim"])
        assert canonical == vector["construction"]["canonical_ascii"].encode("ascii")
        assert (
            "sha256:" + hashlib.sha256(b"\x00" + canonical).hexdigest()
            == vector["construction"]["leaf_hash"]
        )
        assert verify_inclusion(vector["claim"], *parse_receipt(vector["receipt"]))


def test_fixtures_are_reproducible_and_have_positive_twins():
    spec = importlib.util.spec_from_file_location("anchor_generator", VECTOR_DIR / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.vectors() == VECTORS
    by_name = {v["name"]: v for v in VECTORS}
    assert len(VECTORS) == 27
    assert {v["expected"]["tr_anc_002"] for v in VECTORS} == {"pass", "fail"}
    for v in VECTORS:
        if v["expected"]["tr_anc_002"] == "fail":
            assert by_name[v["positive_twin"]]["expected"]["tr_anc_002"] == "pass"

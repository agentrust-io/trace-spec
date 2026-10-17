"""Deterministic receipt-harness regressions without requiring Atheris."""

import contextlib
import json
import runpy
import sys
import types
from pathlib import Path

import pytest


@pytest.fixture
def harness(monkeypatch):
    # Exercise the real fuzz callback's raw-JSON branch; only instrumentation
    # and byte selection are replaced, not the parser, verifier, or assertions.
    class DataProvider:
        def __init__(self, data):
            self.data = data

        def ConsumeIntInRange(self, lower, upper):
            return 3  # The genuine fixture's target claim.

        def ConsumeBool(self):
            return False

        def remaining_bytes(self):
            return len(self.data)

        def ConsumeBytes(self, length):
            return self.data[:length]

    stub = types.ModuleType("atheris")
    stub.instrument_imports = contextlib.nullcontext
    stub.FuzzedDataProvider = DataProvider
    monkeypatch.setitem(sys.modules, "atheris", stub)
    path = Path(__file__).parents[1] / ".clusterfuzzlite" / "fuzz_receipt.py"
    return runpy.run_path(str(path))


@pytest.mark.parametrize(
    "omitted",
    [(), ("leaf_count",), ("merkle_root",), ("leaf_count", "merkle_root")],
)
def test_pass_oracle_accepts_entry_backed_proofs(harness, omitted):
    receipt = {k: v for k, v in harness["_RECEIPT"].items() if k not in omitted}
    claim = harness["_CLAIMS"][harness["_TARGET"]]
    findings = harness["tr_anc"].check(claim, receipt=receipt, entry=harness["_ENTRY"])
    assert any(f.code == "TR-ANC-002" and f.passed() for f in findings)
    harness["TestOneInput"](json.dumps(receipt).encode())


def test_pass_oracle_independently_replays_proof(harness, monkeypatch):
    receipt = {"leaf_index": harness["_TARGET"], "audit_path": []}
    fake_pass = types.SimpleNamespace(code="TR-ANC-002", passed=lambda: True)
    monkeypatch.setattr(harness["tr_anc"], "check", lambda *a, **kw: [fake_pass])
    with pytest.raises(AssertionError, match="not reproduced against the supplied entry"):
        harness["TestOneInput"](json.dumps(receipt).encode())

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


def _entry_lane(harness, monkeypatch, entry):
    provider = harness["atheris"].FuzzedDataProvider

    class EntryProvider(provider):
        def __init__(self, data):
            super().__init__(data)
            self.choices = iter((True, False))

        def ConsumeBool(self):
            return next(self.choices)

    monkeypatch.setattr(harness["atheris"], "FuzzedDataProvider", EntryProvider)
    harness["TestOneInput"](json.dumps(entry).encode())


def test_entry_lane_reaches_parser_and_checker(harness, monkeypatch):
    entry = {**harness["_ENTRY"], "producer": "other/1.0.0"}
    seen = []
    parse = harness["parse_entry"]
    check = harness["tr_anc"].check
    globals_ = harness["TestOneInput"].__globals__

    def observe_parse(value):
        seen.append(("parse", value))
        return parse(value)

    def observe_check(*args, **kwargs):
        seen.append(("check", kwargs["entry"]))
        return check(*args, **kwargs)

    monkeypatch.setitem(globals_, "parse_entry", observe_parse)
    monkeypatch.setattr(harness["tr_anc"], "check", observe_check)
    _entry_lane(harness, monkeypatch, entry)
    assert ("parse", entry) in seen
    assert ("check", entry) in seen


@pytest.mark.parametrize("missing", ["ts", "merkle_root", "leaf_count", "producer", "batch_id"])
def test_entry_missing_fields_refuse(harness, monkeypatch, missing):
    entry = dict(harness["_ENTRY"])
    del entry[missing]
    with pytest.raises(harness["InclusionError"], match="missing required"):
        harness["parse_entry"](entry)
    _entry_lane(harness, monkeypatch, entry)


@pytest.mark.parametrize("field", ["ts", "producer", "batch_id"])
@pytest.mark.parametrize("value", [None, True, 7, [], {}])
def test_entry_nonstring_fields_refuse(harness, monkeypatch, field, value):
    entry = {**harness["_ENTRY"], field: value}
    with pytest.raises(harness["InclusionError"], match="non-empty string"):
        harness["parse_entry"](entry)
    _entry_lane(harness, monkeypatch, entry)


def test_entry_lane_valid_twin_and_no_fixture_mutation(harness, monkeypatch):
    before = json.dumps(harness["_ENTRY"], sort_keys=True)
    _entry_lane(harness, monkeypatch, dict(harness["_ENTRY"]))
    assert json.dumps(harness["_ENTRY"], sort_keys=True) == before


def test_entry_lane_false_pass_is_caught(harness, monkeypatch):
    entry = {**harness["_ENTRY"], "merkle_root": "sha256:" + "00" * 32}
    fake_pass = types.SimpleNamespace(code="TR-ANC-002", passed=lambda: True)
    monkeypatch.setattr(harness["tr_anc"], "check", lambda *a, **kw: [fake_pass])
    with pytest.raises(AssertionError, match="another root"):
        _entry_lane(harness, monkeypatch, entry)


@pytest.mark.parametrize("kind", range(5))
def test_structured_entry_lane_mutates_selected_field(harness, monkeypatch, kind):
    seen = []
    check = harness["tr_anc"].check
    provider = harness["atheris"].FuzzedDataProvider

    class EntryProvider(provider):
        def __init__(self, data):
            super().__init__(data)
            self.ints = iter((harness["_TARGET"], kind, 7))
            self.bools = iter((True, True, False))

        def ConsumeIntInRange(self, lower, upper):
            return next(self.ints)

        def ConsumeBool(self):
            return next(self.bools)

        def PickValueInList(self, values):
            return "producer"

        def ConsumeUnicode(self, length):
            return "changed/1.0.0"

    def observe(*args, **kwargs):
        seen.append(kwargs["entry"])
        return check(*args, **kwargs)

    monkeypatch.setattr(harness["atheris"], "FuzzedDataProvider", EntryProvider)
    monkeypatch.setattr(harness["tr_anc"], "check", observe)
    harness["TestOneInput"](b"")
    expected = dict(harness["_ENTRY"])
    if kind == 0:
        del expected["producer"]
    else:
        expected["producer"] = {1: "changed/1.0.0", 2: 7, 3: None, 4: False}[kind]
    assert seen == [expected]
    assert harness["_ENTRY"]["producer"] == "fuzz/1.0.0"


def test_nonobject_entry_reaches_direct_parser(harness, monkeypatch):
    seen = []
    parse = harness["parse_entry"]

    def observe(value):
        seen.append(value)
        return parse(value)

    monkeypatch.setitem(harness["TestOneInput"].__globals__, "parse_entry", observe)
    _entry_lane(harness, monkeypatch, [])
    assert seen == [[]]

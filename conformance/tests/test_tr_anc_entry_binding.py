"""TR-ANC-002 binds the receipt to the registry entry (trace-spec#464).

Before this, the receipt supplied both the proof and the root and count it was
judged against, so nothing tied a passing proof to any registry entry. These are
the four worlds from the original report (trace-tests#92), plus the entry left
out. The receipt's ``merkle_root`` and ``leaf_count`` must equal the supplied
entry's; with no entry, Level 2 is not earned.

The signed URI is resolved through verifier-controlled evidence, and the
resolved entry's canonical ``log_id``/``entry_id`` identity must match before
inclusion can pass. A presenter-supplied entry remains useful for diagnostics
but cannot earn Level 2.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from trace_tests.cli import main
from trace_tests.inclusion import canonical_claim_bytes
from trace_tests.modules import tr_anc
from trace_tests.result import Status
from trace_tests.runner import run

LEAF = b"\x00"
NODE = b"\x01"
VECTORS = Path(__file__).parent / "vectors"


def _leaf(claim: dict[str, Any]) -> bytes:
    return hashlib.sha256(LEAF + canonical_claim_bytes(claim)).digest()


def _receipt(claims: list[dict[str, Any]], index: int) -> dict[str, Any]:
    """An RFC 6962 receipt for claims[index], with promoted odd nodes."""
    level = [_leaf(c) for c in claims]
    path, idx = [], index
    while len(level) > 1:
        sib = idx ^ 1
        if sib < len(level):
            path.append("sha256:" + level[sib].hex())
        nxt = [
            hashlib.sha256(NODE + level[i] + level[i + 1]).digest()
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            nxt.append(level[-1])
        level, idx = nxt, idx // 2
    return {
        "leaf_index": index,
        "leaf_count": len(claims),
        "audit_path": path,
        "merkle_root": "sha256:" + level[0].hex(),
    }


def _entry(receipt: dict[str, Any]) -> dict[str, Any]:
    """The registry-anchor-v1 section 4 line sealed with the receipt."""
    return {
        "ts": "2026-10-15T00:00:00Z",
        "merkle_root": receipt["merkle_root"],
        "leaf_count": receipt["leaf_count"],
        "producer": "binding-test/1.0.0",
        "batch_id": "binding-1",
        "log_id": "https://log.example.com/entries",
        "entry_id": "binding-1",
    }


def _claims() -> list[dict[str, Any]]:
    return [
        {"transparency": "https://log.example.com/entries/binding-1", "iat": 1000 + i,
         "subject": f"agent-{i}"}
        for i in range(5)
    ]


def _anc002(trace, receipt, entry):
    resolver = None if entry is None else lambda _uri: json.dumps(entry).encode()
    return next(
        f
        for f in tr_anc.check(
            trace,
            receipt=receipt,
            entry=entry,
            entry_resolver=resolver,
            entry_source_authenticated=True,
        )
        if f.code == "TR-ANC-002"
    )


_OTHER_ROOT = "sha256:" + "ab" * 32


def _world(name: str) -> tuple[dict, dict, dict | None]:
    claims = _claims()
    receipt = _receipt(claims, 3)
    entry = _entry(receipt)
    if name == "wrong-caller-root":
        receipt["merkle_root"] = _OTHER_ROOT
    elif name == "paired-entry-root-changed":
        entry["merkle_root"] = _OTHER_ROOT
    elif name == "paired-entry-count-changed":
        entry["leaf_count"] = 6
    elif name == "entry-absent":
        entry = None
    return claims[3], receipt, entry


@pytest.mark.parametrize(
    ("world", "expected"),
    [
        ("matching-sealed-entry", Status.PASS),
        ("wrong-caller-root", Status.FAIL),
        ("paired-entry-root-changed", Status.FAIL),
        ("paired-entry-count-changed", Status.FAIL),
        ("entry-absent", Status.FAIL),
    ],
)
def test_the_four_worlds_and_the_absent_entry(world: str, expected: Status) -> None:
    assert _anc002(*_world(world)).status is expected


def test_each_refusal_names_its_reason() -> None:
    assert "merkle_root" in _anc002(*_world("wrong-caller-root")).message
    assert "binding-1" in _anc002(*_world("paired-entry-root-changed")).message
    assert "leaf_count" in _anc002(*_world("paired-entry-count-changed")).message
    absent = _anc002(*_world("entry-absent")).message
    assert "no registry entry supplied" in absent and "Level 2 is not earned" in absent


def test_the_pass_states_the_resolved_entry_binding() -> None:
    message = _anc002(*_world("matching-sealed-entry")).message
    assert "binding-test/1.0.0 binding-1" in message
    assert "signed transparency URI resolved to this exact log entry" in message


def test_an_unresolved_presenter_entry_cannot_earn_level_2() -> None:
    trace, receipt, entry = _world("matching-sealed-entry")
    finding = next(
        f for f in tr_anc.check(trace, receipt=receipt, entry=entry)
        if f.code == "TR-ANC-002"
    )
    assert finding.status is Status.UNVERIFIED
    assert "presenter-supplied entry cannot earn Level 2" in finding.message


def test_an_unverified_resolver_cannot_earn_level_2() -> None:
    trace, receipt, entry = _world("matching-sealed-entry")
    finding = next(
        finding for finding in tr_anc.check(
            trace,
            receipt=receipt,
            entry_resolver=lambda _uri: json.dumps(entry).encode("utf-8"),
        ) if finding.code == "TR-ANC-002"
    )
    assert finding.status is Status.UNVERIFIED
    assert "source was not independently authenticated" in finding.message


def test_a_truthy_nonboolean_cannot_assert_source_authentication() -> None:
    trace, receipt, entry = _world("matching-sealed-entry")
    finding = next(
        finding for finding in tr_anc.check(
            trace,
            receipt=receipt,
            entry_resolver=lambda _uri: json.dumps(entry).encode("utf-8"),
            entry_source_authenticated="yes",  # type: ignore[arg-type]
        ) if finding.code == "TR-ANC-002"
    )
    assert finding.status is Status.UNVERIFIED


def test_a_valid_proof_from_another_named_log_is_rejected() -> None:
    trace, receipt, entry = _world("matching-sealed-entry")
    entry["log_id"] = "https://other-log.example/entries"
    finding = _anc002(trace, receipt, entry)
    assert finding.status is Status.FAIL
    assert "another log or checkpoint" in finding.message


def test_an_unmapped_signed_entry_is_unverified_not_a_pass() -> None:
    trace, receipt, _ = _world("matching-sealed-entry")
    finding = next(
        f
        for f in tr_anc.check(
            trace,
            receipt=receipt,
            entry_resolver=lambda uri: (_ for _ in ()).throw(KeyError(uri)),
        )
        if f.code == "TR-ANC-002"
    )
    assert finding.status is Status.UNVERIFIED
    assert "could not resolve the signed transparency URI" in finding.message


def test_the_entry_does_not_rescue_a_record_outside_the_tree() -> None:
    claims = _claims()
    receipt = _receipt(claims, 3)
    tampered = dict(claims[3], subject="agent-elsewhere")
    assert _anc002(tampered, receipt, _entry(receipt)).status is Status.FAIL


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda e: e.pop("batch_id"), "missing required field(s): batch_id"),
        (lambda e: e.pop("log_id"), "missing required field(s): log_id"),
        (lambda e: e.pop("entry_id"), "missing required field(s): entry_id"),
        (lambda e: e.pop("ts"), "missing required field(s): ts"),
        (lambda e: e.update(producer=""), "producer must be a non-empty string"),
        (
            lambda e: e.update(log_id="https://LOG.example.com/entries"),
            "authority is not canonical",
        ),
        (
            lambda e: e.update(log_id="HTTPS://log.example.com/entries"),
            "canonical HTTPS base URI",
        ),
        (lambda e: e.update(entry_id="../other"), "entry_id must contain only"),
        (
            lambda e: e.update(log_id="https://log.example.com/entries/./other"),
            "log_id path is not canonical",
        ),
        (
            lambda e: e.update(log_id="https://log.example.com/entries/../other"),
            "log_id path is not canonical",
        ),
        (
            lambda e: e.update(log_id="https://log.example.com/entries?"),
            "canonical HTTPS base URI",
        ),
        (
            lambda e: e.update(log_id="https://log.example.com/entries#"),
            "canonical HTTPS base URI",
        ),
        (lambda e: e.update(leaf_count=True), "leaf_count must be an integer"),
        (lambda e: e.update(leaf_count=0), "leaf_count must be an integer"),
        (lambda e: e.update(merkle_root="sha256:XYZ"), "malformed hash value"),
    ],
    ids=[
        "no-batch-id", "no-log-id", "no-entry-id", "no-ts", "empty-producer",
        "uppercase-host", "uppercase-scheme", "non-canonical-entry-id",
        "current-directory-segment", "parent-directory-segment",
        "empty-query", "empty-fragment", "bool-count",
        "zero-count", "bad-root",
    ],
)
def test_a_malformed_entry_is_reported_as_malformed(mutate, reason: str) -> None:
    trace, receipt, entry = _world("matching-sealed-entry")
    mutate(entry)
    finding = _anc002(trace, receipt, entry)
    assert finding.status is Status.FAIL
    assert "malformed resolved entry" in finding.message and reason in finding.message


def test_a_non_object_entry_is_malformed() -> None:
    trace, receipt, _ = _world("matching-sealed-entry")
    assert "must resolve to one registry entry object" in _anc002(
        trace, receipt, ["not", "an", "entry"]
    ).message


def test_fields_beyond_section_4_are_ignored() -> None:
    trace, receipt, entry = _world("matching-sealed-entry")
    entry["canonicalization_id"] = "sorted-key"
    assert _anc002(trace, receipt, entry).status is Status.PASS


# --- the entry reaches TR-ANC through the runner and the CLI ----------------

def _anchored_level0(load_vector) -> tuple[dict, dict, dict]:
    record = copy.deepcopy(load_vector("valid_level0.json"))
    record["transparency"] = "https://log.example.com/entries/binding-1"
    receipt = _receipt([record], 0)
    return record, receipt, _entry(receipt)


def _runner_anc002(record, receipt, entry) -> Status:
    resolver = None if entry is None else lambda _uri: json.dumps(entry).encode()
    results = run(
        record,
        "trace",
        2,
        receipt=receipt,
        entry=entry,
        entry_resolver=resolver,
        entry_source_authenticated=True,
    )
    return next(f for f in results["TR-ANC"] if f.code == "TR-ANC-002").status


def test_the_runner_passes_the_entry_through(load_vector) -> None:
    record, receipt, entry = _anchored_level0(load_vector)
    assert _runner_anc002(record, receipt, entry) is Status.PASS
    assert _runner_anc002(record, receipt, None) is Status.FAIL


def test_the_cli_reads_entry(load_vector, tmp_path: Path) -> None:
    record, receipt, entry = _anchored_level0(load_vector)
    paths = {}
    for name, value in (("record", record), ("receipt", receipt), ("entry", entry)):
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(value), encoding="utf-8")
    args = ["report", "--record", str(paths["record"]), "--receipt", str(paths["receipt"]),
            "--json", str(tmp_path / "out.json")]

    def report(extra: list[str]) -> str:
        result = CliRunner().invoke(main, args + extra)
        assert result.exit_code == 0, result.output
        return (tmp_path / "out.json").read_text(encoding="utf-8")

    entry_dir = tmp_path / "entry-resolution"
    entry_dir.mkdir()
    resolved_entry = entry_dir / "entry.json"
    resolved_entry.write_text(json.dumps(entry), encoding="utf-8")
    (entry_dir / "entries.json").write_text(
        json.dumps({record["transparency"]: "entry.json"}), encoding="utf-8"
    )

    with_entry = report(["--entry-dir", str(entry_dir)])
    assert "source was not independently authenticated" in with_entry
    assert "signed transparency URI resolved to this exact log entry" not in with_entry
    assert "no registry entry supplied" not in with_entry
    unresolved = report(["--entry", str(paths["entry"])])
    assert "presenter-supplied entry cannot earn Level 2" in unresolved
    assert "signed transparency URI resolved to this exact log entry" not in unresolved


def _proof_only(receipt: dict[str, Any]) -> dict[str, Any]:
    """The section 5 proof alone: what a producer hands a claim holder."""
    return {"leaf_index": receipt["leaf_index"], "audit_path": receipt["audit_path"]}


def test_proof_only_receipt_anchors_against_its_entry() -> None:
    claims = _claims()
    receipt = _receipt(claims, 2)
    finding = tr_anc._check_inclusion(claims[2], _proof_only(receipt), _entry(receipt))
    assert finding.status is Status.PASS, finding.message


def test_proof_only_receipt_is_refused_against_another_batch() -> None:
    claims = _claims()
    receipt = _receipt(claims, 2)
    other = _receipt([{"transparency": "https://log.example.com/entries/other", "iat": 1}] * 3, 0)
    finding = tr_anc._check_inclusion(claims[2], _proof_only(receipt), _entry(other))
    assert finding.status is Status.FAIL
    assert "does not reproduce the committed merkle_root" in finding.message


@pytest.mark.parametrize("field", ["leaf_index", "audit_path"])
def test_receipt_without_the_section_5_proof_is_malformed(field: str) -> None:
    claims = _claims()
    receipt = _receipt(claims, 1)
    receipt.pop(field)
    finding = tr_anc._check_inclusion(claims[1], receipt, _entry(_receipt(claims, 1)))
    assert finding.status is Status.FAIL
    assert f"missing required field(s): {field}" in finding.message


@pytest.mark.parametrize("value", [None, "3", 3.0, True])
def test_a_receipt_carried_leaf_count_that_is_not_an_integer_is_malformed(value: object) -> None:
    claims = _claims()
    receipt = _receipt(claims, 1)
    receipt["leaf_count"] = value
    finding = tr_anc._check_inclusion(claims[1], receipt, _entry(_receipt(claims, 1)))
    assert finding.status is Status.FAIL
    assert "leaf_count must be an integer" in finding.message

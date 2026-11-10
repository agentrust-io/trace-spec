"""Behavioral boundary checks for conformance inclusion profile and receipt parsing (#625)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

_CONFORMANCE_SRC = str(Path(__file__).resolve().parents[1] / "conformance" / "src")
if sys.path[:1] != [_CONFORMANCE_SRC]:
    sys.path.insert(0, _CONFORMANCE_SRC)

from trace_tests.inclusion import (  # type: ignore[import-untyped] # noqa: E402
    InclusionError,
    canonical_claim_bytes,
    parse_entry,
    parse_proof,
    parse_receipt,
)

_RECEIPT: dict[str, Any] = {
    "leaf_index": 0,
    "audit_path": [],
    "leaf_count": 1,
    "merkle_root": "sha256:" + "0" * 64,
}
_ENTRY: dict[str, Any] = {
    "ts": "2026-10-15T00:00:00Z",
    "merkle_root": "sha256:" + "0" * 64,
    "leaf_count": 1,
    "producer": "unit-test/1.0.0",
    "batch_id": "unit-1",
}


@pytest.mark.parametrize(
    ("claim", "expected"),
    [
        ({"s": "\ud800"}, "surrogate"),
        ({"nested": ("\udfff",)}, "surrogate"),
        ({"\ud800key": 1}, "surrogate"),
        ({1: "val"}, "non-string object key"),  # type: ignore[dict-item]
    ],
    ids=["surrogate-value", "surrogate-tuple", "surrogate-key", "int-key"],
)
def test_canonical_claim_bytes_rejects_surrogates_and_non_string_keys(
    claim: dict[str, Any], expected: str
) -> None:
    with pytest.raises(InclusionError, match=expected):
        canonical_claim_bytes(claim)


def test_canonical_claim_bytes_rejects_cycles_and_allows_shared_acyclic() -> None:
    import threading

    shared = {"k": 1}
    assert canonical_claim_bytes({"a": shared, "b": shared}) == b'{"a":{"k":1},"b":{"k":1}}'

    cyc_dict: dict[str, Any] = {}
    cyc_dict["self"] = cyc_dict
    caught: list[BaseException] = []

    def _run_cyclic() -> None:
        try:
            canonical_claim_bytes(cyc_dict)
        except BaseException as exc:
            caught.append(exc)

    worker = threading.Thread(target=_run_cyclic, daemon=True)
    worker.start()
    worker.join(timeout=0.25)
    assert not worker.is_alive(), "canonical_claim_bytes hung on a circular reference"
    assert len(caught) == 1 and isinstance(caught[0], InclusionError)
    assert "circular reference" in str(caught[0])


@pytest.mark.parametrize(
    ("bad_receipt", "expected_match"),
    [
        ({**_RECEIPT, "leaf_index": True}, "receipt leaf_index must be a non-negative integer"),
        ({**_RECEIPT, "leaf_index": "0"}, "receipt leaf_index must be a non-negative integer"),
        ({**_RECEIPT, "leaf_index": -1}, "receipt leaf_index must be a non-negative integer"),
        ({**_RECEIPT, "leaf_index": 2**53}, "receipt leaf_index must be a non-negative integer"),
        ({**_RECEIPT, "leaf_count": 0}, "receipt leaf_count must be an integer >= 1"),
        ({**_RECEIPT, "leaf_count": -1}, "receipt leaf_count must be an integer >= 1"),
        ({**_RECEIPT, "leaf_count": 2**53}, "receipt leaf_count must be an integer >= 1"),
        ({**_RECEIPT, "leaf_index": 1, "leaf_count": 1}, "must be less than leaf_count"),
    ],
)
def test_parse_proof_and_receipt_reject_invalid_leaf_index_or_count(
    bad_receipt: dict[str, Any], expected_match: str
) -> None:
    assert parse_receipt(_RECEIPT)[0] == 0
    assert parse_proof({"leaf_index": 2**53 - 1, "audit_path": []})[0] == 2**53 - 1
    assert (
        parse_receipt({**_RECEIPT, "leaf_index": 2**53 - 2, "leaf_count": 2**53 - 1})[2]
        == 2**53 - 1
    )
    with pytest.raises(InclusionError, match=expected_match):
        parse_proof(bad_receipt)
    with pytest.raises(InclusionError, match=expected_match):
        parse_receipt(bad_receipt)


def test_parse_proof_without_leaf_count_rejects_leaf_index_above_safe_int() -> None:
    assert parse_proof({"leaf_index": 2**53 - 1, "audit_path": []})[0] == 2**53 - 1
    with pytest.raises(
        InclusionError, match="receipt leaf_index must be a non-negative integer"
    ):
        parse_proof({"leaf_index": 2**53, "audit_path": []})


@pytest.mark.parametrize(
    "bad_entry",
    [
        {**_ENTRY, "producer": "   "},
        {**_ENTRY, "producer": "prod\n1.0"},
        {**_ENTRY, "producer": "prod\x7f1.0"},
        {**_ENTRY, "batch_id": "batch\x001"},
        {**_ENTRY, "batch_id": "batch\x7f1"},
        {**_ENTRY, "leaf_count": 2**53},
    ],
)
def test_parse_entry_rejects_whitespace_control_chars_and_unsafe_leaf_count(
    bad_entry: dict[str, Any],
) -> None:
    assert parse_entry(_ENTRY)[1] == 1
    assert parse_entry({**_ENTRY, "producer": "Example Gateway 1.0"})[2] == "Example Gateway 1.0"
    assert parse_entry({**_ENTRY, "leaf_count": 2**53 - 1})[1] == 2**53 - 1
    with pytest.raises(InclusionError):
        parse_entry(bad_entry)

"""Canonicalization boundary vectors (spec section 3.2.2).

The spec requires an RFC 8785-conformant library and names
``json.dumps(sort_keys=True)`` as insufficient. On every other record in this
repository the two agree byte-for-byte, so nothing distinguished an implementation
that complied from one that did not. These vectors are the records on which they
disagree: schema-valid, correctly signed, and rejected by any verifier whose
canonicalizer is one of the ad-hoc forms below.

Each fixture declares ``diverges_under``. The declaration is recomputed here, not
trusted: a vector that stopped diverging would otherwise keep documenting a
distinction it no longer makes.

RFC 8785's third divergence, number serialization, is in
``tests/test_safe_integer_range.py``. No vector can carry it: a positive vector is
a schema-valid record, and the records that reach that divergence are exactly the
ones the schema rejects.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import rfc8785

from agentrust_trace import verify_record
from agentrust_trace.validate import validate_json

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_DIR = REPO_ROOT / "examples" / "canonicalization-boundary"
FIXTURE_PATHS = sorted(FIXTURE_DIR.glob("*.json"))

# The ladder of ad-hoc canonicalizations, least careful first. Each rung fixes the
# previous rung's divergence and still fails on at least one vector; the last is
# json.dumps with every option set as well as it can be.
ADHOC: dict[str, Callable[[Any], bytes]] = {
    "sort_keys_default": lambda o: json.dumps(o, sort_keys=True).encode(),
    "sort_keys_compact": lambda o: json.dumps(
        o, sort_keys=True, separators=(",", ":")
    ).encode(),
    "sort_keys_compact_utf8": lambda o: json.dumps(
        o, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode(),
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _signing_input(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "signature"}


def test_vector_set_is_complete() -> None:
    assert [path.name for path in FIXTURE_PATHS] == [
        "01-non-ascii-values.json",
        "02-non-bmp-values.json",
        "03-utf16-key-order.json",
        "04-utf16-key-order-nested.json",
    ]


@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=lambda p: p.stem)
def test_vector_is_schema_valid_and_verifies(path: Path) -> None:
    """The record is an ordinary valid Trust Record; only its bytes are unusual.

    A vector that failed schema validation would let an implementation reject it for
    the wrong reason and still look conformant.
    """
    fixture = _load(path)
    validate_json(fixture["record"])
    verify_record(
        fixture["record"],
        fixture["trusted_key"],
        # iat is fixed for reproducibility; canonicalization, not freshness, is the
        # property under test.
        max_age_seconds=None,
    )  # must not raise


@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=lambda p: p.stem)
def test_declared_divergence_is_the_measured_divergence(path: Path) -> None:
    """``diverges_under`` is recomputed, never trusted."""
    fixture = _load(path)
    body = _signing_input(fixture["record"])
    canonical = rfc8785.dumps(body)
    measured = sorted(
        name for name, dumps in ADHOC.items() if dumps(body) != canonical
    )
    assert measured == sorted(fixture["diverges_under"]), (
        f"{path.name}: declared divergence does not match measurement. A verifier "
        "reading the declaration would draw the wrong conclusion about which "
        "canonicalizers this vector can catch."
    )


def test_every_adhoc_form_is_caught_by_some_vector() -> None:
    """The set as a whole must kill every rung of the ladder.

    If the most careful form ever stops diverging on all vectors, the set can no
    longer distinguish a conformant canonicalizer from json.dumps, and the spec's
    MUST is back to being unenforced.
    """
    killed = {name for path in FIXTURE_PATHS for name in _load(path)["diverges_under"]}
    assert killed == set(ADHOC)


def test_every_adhoc_form_is_caught_by_at_least_two_vectors() -> None:
    """Covered once is covered until that vector changes.

    `sort_keys_compact_utf8` is the form a careful implementer actually reaches, and
    it was separated by `03` alone: weaken or retire that one vector and the closest
    non-conformant canonicalizer passes the whole set, with every other assertion
    here still green. This is the margin rule of agentrust-io/trace-spec#124 applied
    to the set that measures the section 3.2.2 MUST.

    `04` is the second vector, and it is a distinct defect rather than a restatement:
    it moves the divergence inside a nested object, so a canonicalizer that sorts by
    UTF-16 code units at the outer levels and by code points below them passes `03`
    and fails `04`.
    """
    counts = Counter(name for path in FIXTURE_PATHS
                     for name in _load(path)["diverges_under"])
    assert set(counts) == set(ADHOC), "a form is separated by no vector at all"
    thin = {name: n for name, n in counts.items() if n < 2}
    assert not thin, (
        f"separated by a single vector: {thin}. One vector is coverage until that "
        "vector changes; two are required per boundary."
    )

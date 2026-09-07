"""Canonicalization boundary vectors (spec section 3.2.2).

The spec requires an RFC 8785-conformant library and names
``json.dumps(sort_keys=True)`` as insufficient. ASCII-only values and fixed object
keys can conceal escaping and key-order differences. These vectors deliberately
exercise those differences. The four positive vectors are signed over JCS and
must be accepted.
Two negative vectors carry the same schema-valid payloads but signatures over
alternate serializations and must be rejected specifically for their signatures.
Together they distinguish exact JCS verification from accepting everything or
falling back to a second serialization after JCS verification fails.

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
import base64
import runpy
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace import verify_record
from agentrust_trace.validate import validate_json

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_DIR = REPO_ROOT / "examples" / "canonicalization-boundary"
FIXTURE_PATHS = sorted(FIXTURE_DIR.glob("*.json"))
POSITIVE_PATHS = [path for path in FIXTURE_PATHS if path.name[:2] in {"01", "02", "03", "04"}]
NEGATIVE_CASES = [
    (
        FIXTURE_DIR / "05-ascii-escaped-signature.json",
        FIXTURE_DIR / "01-non-ascii-values.json",
        "sort_keys_compact",
    ),
    (
        FIXTURE_DIR / "06-codepoint-order-signature.json",
        FIXTURE_DIR / "03-utf16-key-order.json",
        "sort_keys_compact_utf8",
    ),
]

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


def _verify(fixture: dict[str, Any]) -> None:
    """Exercise the public API with real schema, trust, age and revocation inputs."""
    validate_json(fixture["record"])
    result = verify_record(
        fixture["record"],
        fixture["trusted_key"],
        allow_embedded_key=False,
        max_age_seconds=60,
        max_future_skew_seconds=0,
        revocation=frozenset(),
        now=fixture["record"]["iat"],
    )
    assert result.revocation.outcome == "verified"
    assert result.revocation.evidence == {"source": "store"}


def _b64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_preimage(fixture: dict[str, Any], preimage: bytes) -> None:
    """Independent cryptography operation, with no TRACE canonicalizer involved."""
    trusted = fixture["trusted_key"]
    assert trusted["kty"] == "OKP" and trusted["crv"] == "Ed25519"
    public_key = Ed25519PublicKey.from_public_bytes(_b64u(trusted["x"]))
    public_key.verify(_b64u(fixture["record"]["signature"]), preimage)


def test_vector_set_is_complete() -> None:
    assert [path.name for path in FIXTURE_PATHS] == [
        "01-non-ascii-values.json",
        "02-non-bmp-values.json",
        "03-utf16-key-order.json",
        "04-utf16-key-order-nested.json",
        "05-ascii-escaped-signature.json",
        "06-codepoint-order-signature.json",
    ]


@pytest.mark.parametrize("path", POSITIVE_PATHS, ids=lambda p: p.stem)
def test_vector_is_schema_valid_and_verifies(path: Path) -> None:
    """The record is an ordinary valid Trust Record; only its bytes are unusual.

    A vector that failed schema validation would let an implementation reject it for
    the wrong reason and still look conformant.
    """
    fixture = _load(path)
    assert fixture["expected"] == {"outcome": "verified"}
    # iat is fixed for reproducibility. Pin evaluation time rather than disabling
    # freshness: a signature failure must not hide behind an unrelated refusal.
    _verify(fixture)


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
    killed = {name for path in POSITIVE_PATHS for name in _load(path)["diverges_under"]}
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
    counts = Counter(name for path in POSITIVE_PATHS
                     for name in _load(path)["diverges_under"])
    assert set(counts) == set(ADHOC), "a form is separated by no vector at all"
    thin = {name: n for name, n in counts.items() if n < 2}
    assert not thin, (
        f"separated by a single vector: {thin}. One vector is coverage until that "
        "vector changes; two are required per boundary."
    )


@pytest.mark.parametrize(
    "path,positive_path,form", NEGATIVE_CASES,
    ids=["ascii-escaped-signature", "codepoint-order-signature"],
)
def test_negative_preimages_are_exact_and_signature_failure_is_isolated(
    path: Path, positive_path: Path, form: str,
) -> None:
    """Only the signed bytes differ; malformed schema/key/time is not the reason."""
    fixture, positive = _load(path), _load(positive_path)
    assert fixture["expected"] == {"outcome": "rejected", "failure": "signature_invalid"}
    assert fixture["signing_form"] == form
    assert fixture["trusted_key"] == positive["trusted_key"]
    body = _signing_input(fixture["record"])
    assert body == _signing_input(positive["record"])
    alternate = ADHOC[form](body)
    canonical = rfc8785.dumps(body)
    assert fixture["signed_input_utf8"].encode("utf-8") == alternate
    assert fixture["canonical_input_utf8"].encode("utf-8") == canonical
    assert alternate != canonical
    # These are genuine Ed25519 signatures over the declared non-JCS preimages,
    # not random signature corruption that could pass for the wrong reason.
    _verify_preimage(fixture, alternate)
    with pytest.raises(InvalidSignature):
        _verify_preimage(fixture, canonical)
    validate_json(fixture["record"])
    with pytest.raises(InvalidSignature):
        _verify(fixture)
    _verify(positive)


@pytest.mark.parametrize(
    "path,positive_path,form", NEGATIVE_CASES,
    ids=["ascii-escaped-signature", "codepoint-order-signature"],
)
def test_same_negative_payload_resigned_over_jcs_passes(
    path: Path, positive_path: Path, form: str,
) -> None:
    """Use the published deterministic fixture key, never a production key."""
    generator = runpy.run_path(str(FIXTURE_DIR / "gen_boundary_vectors.py"))
    fixture = _load(path)
    assert fixture["signing_form"] == form
    repaired = generator["signed"](_signing_input(fixture["record"]))
    assert _signing_input(repaired) == _signing_input(fixture["record"])
    # Ed25519 is deterministic; this is exactly the existing positive record.
    assert repaired == _load(positive_path)["record"]
    _verify({**fixture, "record": repaired})


def _accepted(fixture: dict[str, Any]) -> bool:
    try:
        _verify(fixture)
    except InvalidSignature:
        return False
    return True


def _mismatches(verifier: Callable[[dict[str, Any]], bool]) -> set[str]:
    return {
        path.name for path in FIXTURE_PATHS
        if verifier(_load(path)) != (_load(path)["expected"]["outcome"] == "verified")
    }


def test_both_unconditional_verifiers_are_killed() -> None:
    """Adding only positives or only negatives cannot pin this boundary."""
    assert _mismatches(lambda _: True) == {case[0].name for case in NEGATIVE_CASES}
    assert _mismatches(lambda _: False) == {path.name for path in POSITIVE_PATHS}
    assert _mismatches(_accepted) == set()


@pytest.mark.parametrize(
    "form,incorrectly_accepted",
    [
        ("sort_keys_compact", "05-ascii-escaped-signature.json"),
        ("sort_keys_compact_utf8", "06-codepoint-order-signature.json"),
    ],
    ids=["fallback-accepts-ascii-escaping", "fallback-accepts-codepoint-key-order"],
)
def test_each_alternate_fallback_is_a_distinct_killed_defect(
    form: str, incorrectly_accepted: str,
) -> None:
    """Controlled test mutants, not a claim that the public verifier falls back.

    Each mutant still accepts all four positive records. It admits just one of
    the two wrong-preimage signatures, so neither negative substitutes for the
    other. This measures independent failure mechanisms rather than trusting
    their names or merely counting two instances of signature_invalid.
    """
    def fallback(fixture: dict[str, Any]) -> bool:
        if _accepted(fixture):
            return True
        alternate = ADHOC[form](_signing_input(fixture["record"]))
        try:
            _verify_preimage(fixture, alternate)
        except InvalidSignature:
            return False
        return True

    assert _mismatches(fallback) == {incorrectly_accepted}

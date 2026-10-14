"""Unit tests for TR-ANC module."""

from typing import Any

import pytest

from trace_tests.inclusion import InclusionError, canonical_claim_bytes
from trace_tests.modules.tr_anc import check
from trace_tests.result import Status

_RECEIPT: dict[str, Any] = {
    "leaf_index": 0,
    "audit_path": [],
    "leaf_count": 1,
    "merkle_root": "sha256:" + "0" * 64,
}


def _nested(depth: int = 100_000) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth):
        value = [value]
    return value


def test_https_transparency_passes_the_shape_check_only():
    """A well-formed URI clears TR-ANC-001 and cannot clear TR-ANC-002 alone.

    Before #70 this asserted every finding passed, which is what let
    ``https://example.invalid/nothing-here`` earn a Level 2 badge. The URI says
    where the anchor lives; only a receipt shows the record is in it.
    """
    findings = check({"transparency": "https://scitt.example.org/receipts/abc123"})
    by_code = {f.code: f for f in findings}
    assert by_code["TR-ANC-001"].passed()
    assert by_code["TR-ANC-002"].failed()


def test_http_transparency_fails():
    failed = [
        f
        for f in check({"transparency": "http://scitt.example.org/receipts/abc123"})
        if f.failed()
    ]
    assert any(f.code == "TR-ANC-001" for f in failed), (
        "plain http transparency URI must be rejected; https only"
    )


def test_missing_transparency_fails():
    failed = [f for f in check({}) if f.failed()]
    assert any(f.code == "TR-ANC-001" for f in failed)


def test_non_string_transparency_fails():
    failed = [f for f in check({"transparency": 42}) if f.failed()]
    assert any(f.code == "TR-ANC-001" for f in failed)


def test_non_uri_scheme_fails():
    failed = [f for f in check({"transparency": "ftp://example.org/log"}) if f.failed()]
    assert any(f.code == "TR-ANC-001" for f in failed)


def test_unparseable_transparency_uri_fails():
    """A URI that raises during parsing, rather than parsing to a wrong scheme.

    `https://[` raises ValueError (Invalid IPv6 URL) inside urlparse. This is the
    only input that reaches the except branch, which measured margin 0: deleting
    that handler turned a clean FAIL into an uncaught exception with no test
    noticing.
    """
    failed = [f for f in check({"transparency": "https://["}) if f.failed()]
    assert any(f.code == "TR-ANC-001" for f in failed)
    assert any("could not parse" in f.message for f in failed)


def test_deeply_nested_claim_raises_inclusion_error_and_fails_tr_anc_002():
    claim = {
        "transparency": "https://registry.example.org/claim/1",
        "cnf": {
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                "ext": _nested(100_000),
            }
        },
    }
    with pytest.raises(InclusionError, match="nests too deeply"):
        canonical_claim_bytes(claim)

    findings = check(claim, receipt=dict(_RECEIPT))
    by_code = {f.code: f for f in findings}
    assert by_code["TR-ANC-002"].status is Status.FAIL
    assert "nests too deeply" in by_code["TR-ANC-002"].message


def test_non_json_serializable_claim_raises_inclusion_error_and_fails_tr_anc_002():
    claim = {
        "transparency": "https://registry.example.org/claim/1",
        "extra": object(),
    }
    with pytest.raises(InclusionError, match="not JSON serializable"):
        canonical_claim_bytes(claim)

    findings = check(claim, receipt=dict(_RECEIPT))
    by_code = {f.code: f for f in findings}
    assert by_code["TR-ANC-002"].status is Status.FAIL
    assert "not JSON serializable" in by_code["TR-ANC-002"].message


@pytest.mark.parametrize(
    ("claim", "expected"),
    [
        ({"a": (1.5,)}, "non-integer number"),
        ({"a": (2**53,)}, "outside the safe-integer range"),
    ],
    ids=["tuple-float", "tuple-unsafe-int"],
)
def test_tuple_outside_anchor_profile_raises_inclusion_error_and_fails_tr_anc_002(
    claim: dict[str, Any], expected: str
):
    with pytest.raises(InclusionError, match=expected):
        canonical_claim_bytes(claim)

    trace = {"transparency": "https://registry.example.org/claim/1", **claim}
    findings = check(trace, receipt=dict(_RECEIPT))
    by_code = {f.code: f for f in findings}
    assert by_code["TR-ANC-002"].status is Status.FAIL
    assert expected in by_code["TR-ANC-002"].message


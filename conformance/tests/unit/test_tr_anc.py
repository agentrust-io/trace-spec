"""Unit tests for TR-ANC module."""

from trace_tests.modules.tr_anc import check


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
    failed = [f for f in check({"transparency": "http://scitt.example.org/receipts/abc123"}) if f.failed()]
    assert any(f.code == "TR-ANC-001" for f in failed), "plain http transparency URI must be rejected; https only"


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

"""Both pointer surfaces enforce host/port shape without network policy."""

import pytest

from trace_tests.modules import tr_anc, tr_rte
from trace_tests.result import Status


def pointer_status(uri: str, surface: str) -> Status:
    if surface == "rim":
        findings = tr_rte.check({"runtime": {"platform": "software-only", "rim_uri": uri}})
        target = "TR-RTE-003"
    else:
        findings = tr_anc.check({"transparency": uri})
        target = "TR-ANC-001"
    return next(f.status for f in findings if f.code == target)


@pytest.mark.parametrize("surface", ["rim", "anchor"])
@pytest.mark.parametrize("uri", [
    "https://example.invalid/rim", "https://example.invalid:443/rim",
    "https://[::1]:443/rim", "https://user@example.invalid/rim",
])
def test_valid_pointer_authorities(uri: str, surface: str) -> None:
    assert pointer_status(uri, surface) is Status.PASS


@pytest.mark.parametrize("surface", ["rim", "anchor"])
@pytest.mark.parametrize("uri", [
    "https://:443/rim", "https://user@/rim", "https://example.invalid:bad/rim",
    "https://example.invalid:65536/rim", "https://[::1/rim",
    "https://[::1]suffix/rim",
])
def test_invalid_pointer_authorities(uri: str, surface: str) -> None:
    assert pointer_status(uri, surface) is Status.FAIL

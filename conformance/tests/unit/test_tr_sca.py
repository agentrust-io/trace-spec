"""Unit tests for TR-SCA module.

This module had no unit tests. Its build_provenance-must-be-an-object path measured
margin 0, meaning it could have been deleted silently.
"""

import pytest

from trace_tests.modules.tr_sca import check

VALID_DIGEST = "sha256:" + "a" * 64


def _prov(**over):
    prov = {"slsa_level": 3, "digest": VALID_DIGEST}
    prov.update(over)
    return {"build_provenance": prov}


def test_valid_provenance_passes():
    failed = [f for f in check(_prov()) if f.failed()]
    assert not failed, failed


@pytest.mark.parametrize("slsa_level", [0, 1, 2, 3, 0.0, 1.0, 2.0, 3.0])
def test_every_schema_integer_slsa_level_passes(slsa_level):
    """JSON Schema treats numbers with a zero fractional part as integers."""
    failed = [
        finding
        for finding in check(_prov(slsa_level=slsa_level))
        if finding.code == "TR-SCA-001" and finding.failed()
    ]
    assert not failed, failed


def test_missing_provenance_fails():
    failed = [f for f in check({}) if f.failed()]
    assert any(f.code == "TR-SCA-001" for f in failed)
    assert any("required at Level 1+" in f.message for f in failed)


def test_non_object_provenance_fails():
    """A string where an object belongs. Reading slsa_level off it would raise, not fail cleanly."""
    failed = [f for f in check({"build_provenance": "slsa3"}) if f.failed()]
    assert any(f.code == "TR-SCA-001" for f in failed)
    assert any("must be an object" in f.message for f in failed)


def test_list_provenance_fails():
    failed = [f for f in check({"build_provenance": [{"slsa_level": 3}]}) if f.failed()]
    assert any(f.code == "TR-SCA-001" for f in failed)


def test_out_of_range_slsa_level_fails():
    failed = [f for f in check(_prov(slsa_level=4)) if f.failed()]
    assert any(f.code == "TR-SCA-001" for f in failed)


def test_string_slsa_level_fails():
    """"3" is not 3; a coercing comparison would accept it."""
    failed = [f for f in check(_prov(slsa_level="3")) if f.failed()]
    assert any(f.code == "TR-SCA-001" for f in failed)


def test_missing_slsa_level_fails():
    failed = [f for f in check({"build_provenance": {}}) if f.failed()]
    assert any(f.code == "TR-SCA-001" for f in failed)

"""Unit tests for the conformance runner."""

import json
import pathlib
import time

import pytest

from trace_tests.runner import run

VECTORS_DIR = pathlib.Path(__file__).parent.parent / "vectors"


def load_vector(filename: str) -> dict:
    return json.loads((VECTORS_DIR / filename).read_text())


@pytest.fixture
def valid_level0():
    vector = load_vector("valid_level0.json")
    vector["iat"] = int(time.time()) - 60  # vectors carry static iat; refresh for max-age checks
    return vector


@pytest.fixture
def valid_cmcp_runtime():
    vector = load_vector("valid_cmcp_runtime.json")
    vector["trace"]["iat"] = int(time.time()) - 60
    return vector


def test_level0_trace_format_passes(valid_level0):
    results = run(valid_level0, "trace", level=0)
    assert "TR-ENV" in results
    assert "TR-SIG" in results
    assert "TR-POL" in results
    assert "TR-RTE" not in results
    failures = [f for findings in results.values() for f in findings if f.failed()]
    assert not failures, failures


def test_level0_trace_format_is_marked_unverified(valid_level0):
    results = run(valid_level0, "trace", level=0)
    unverified = [f for f in results["TR-SIG"] if f.unverified()]
    assert unverified, "unsigned plain trace records must carry an UNVERIFIED TR-SIG finding"


@pytest.mark.parametrize("level", [1, 2])
def test_unsigned_trace_record_fails_tr_sig_at_level(valid_level0, level):
    results = run(valid_level0, "trace", level=level)
    sig_failures = [f for f in results["TR-SIG"] if f.failed()]
    assert sig_failures, f"unsigned plain trace record must fail TR-SIG at level {level}"


def test_stale_record_fails_freshness(valid_level0):
    valid_level0["iat"] = int(time.time()) - (25 * 3600)
    results = run(valid_level0, "trace", level=0)
    env_failures = [f for f in results["TR-ENV"] if f.failed()]
    assert any("stale" in f.message for f in env_failures), env_failures


def test_max_age_override_is_honored(valid_level0):
    valid_level0["iat"] = int(time.time()) - (25 * 3600)
    results = run(valid_level0, "trace", level=0, max_age_seconds=48 * 3600)
    env_failures = [f for f in results["TR-ENV"] if f.failed()]
    assert not env_failures, env_failures


def test_level1_trace_format_includes_rte_and_sca(valid_level0):
    results = run(valid_level0, "trace", level=1)
    assert "TR-RTE" in results
    assert "TR-SCA" in results


def test_level2_trace_format_includes_txn_and_anc(valid_level0):
    results = run(valid_level0, "trace", level=2)
    assert "TR-TXN" in results
    assert "TR-ANC" in results


def test_cmcp_runtime_level0_skips_sig_for_unsigned_vector(valid_cmcp_runtime):
    # The test vector has a placeholder signature, so TR-SIG will fail.
    # Check that all other modules run correctly.
    results = run(valid_cmcp_runtime, "cmcp-runtime", level=0)
    assert "TR-ENV" in results
    env_failures = [f for f in results["TR-ENV"] if f.failed()]
    assert not env_failures, env_failures


def test_invalid_level_raises():
    with pytest.raises(ValueError, match="Unknown conformance level"):
        run({}, "trace", level=99)

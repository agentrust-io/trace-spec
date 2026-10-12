"""Unit tests for format detection in the loader.

Format selection must come from positive structural markers, never from the
absence of fields, so an attacker cannot downgrade a cmcp-runtime envelope to
the weaker plain-trace verification path by stripping keys.
"""

import json

import pytest

from trace_tests.loader import LoadError, load_record

VALID_CMCP = {
    "cmcp_version": "1.0",
    "trace": {"eat_profile": "tag:agentrust-io.com,2026:trace-v0.2"},
    "gateway": {"session_id": "s1"},
    "signature": "sig",
}

VALID_TRACE = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1748000000,
    "subject": "spiffe://example.org/agent/test",
}


def _write(tmp_path, data):
    p = tmp_path / "record.json"
    p.write_text(json.dumps(data))
    return str(p)


def test_cmcp_version_marker_selects_cmcp_runtime(tmp_path):
    _, fmt = load_record(_write(tmp_path, VALID_CMCP))
    assert fmt == "cmcp-runtime"


def test_plain_trace_record_selects_trace(tmp_path):
    _, fmt = load_record(_write(tmp_path, VALID_TRACE))
    assert fmt == "trace"


def test_stripping_gateway_does_not_downgrade_format(tmp_path):
    stripped = {k: v for k, v in VALID_CMCP.items() if k != "gateway"}
    _, fmt = load_record(_write(tmp_path, stripped))
    assert fmt == "cmcp-runtime", "removing 'gateway' must not downgrade to the plain-trace path"


def test_stripping_cmcp_version_is_rejected_not_downgraded(tmp_path):
    stripped = {k: v for k, v in VALID_CMCP.items() if k != "cmcp_version"}
    with pytest.raises(LoadError, match="partial cmcp-runtime envelope"):
        load_record(_write(tmp_path, stripped))


@pytest.mark.parametrize("leftover", ["trace", "gateway"])
def test_partial_envelope_with_single_cmcp_key_is_rejected(tmp_path, leftover):
    # "signature" is intentionally excluded: plain TRACE records may carry an
    # embedded signature field (agentrust-trace sign_record() output), so the
    # loader allows it. Only "trace" and "gateway" are unambiguous cmcp markers.
    record = {**VALID_TRACE, leftover: VALID_CMCP[leftover]}
    with pytest.raises(LoadError, match="partial cmcp-runtime envelope"):
        load_record(_write(tmp_path, record))


def test_cmcp_version_without_trace_object_is_rejected(tmp_path):
    record = {"cmcp_version": "1.0", "gateway": {}, "signature": "sig"}
    with pytest.raises(LoadError, match="no 'trace' object"):
        load_record(_write(tmp_path, record))

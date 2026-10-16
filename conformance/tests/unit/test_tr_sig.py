"""Unit tests for TR-SIG module."""

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trace_tests.modules.tr_sig import check
from trace_tests.result import Status


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _canonical_json(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _make_signed_record() -> dict:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes_raw()
    x = _b64url(pub_raw)
    kid = f"test-{pub_raw[:4].hex()}"

    record = {
        "cmcp_version": "1.0",
        "trace": {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": 1748000000,
            "subject": "spiffe://cmcp.gateway/session/unit-test",
            "runtime": {
                "platform": "tpm2",
                "measurement": "sha256:a" * 0 + "sha256:" + "a" * 64,
            },
            "policy": {
                "bundle_hash": "sha256:" + "b" * 64,
                "enforcement_mode": "enforce",
            },
            "data_class": "internal",
            "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}},
        },
        "gateway": {"session_id": "unit-test"},
        "signature": "",
    }

    body = _canonical_json({k: v for k, v in record.items() if k != "signature"})
    sig = priv.sign(body)
    record["signature"] = _b64url(sig)
    return record


def test_valid_ed25519_signature_passes():
    record = _make_signed_record()
    trace = record["trace"]
    findings = check(trace, record, "cmcp-runtime")
    assert all(f.passed() for f in findings), findings


def test_tampered_body_fails():
    record = _make_signed_record()
    record["trace"]["iat"] = 1748000001  # tamper
    trace = record["trace"]
    findings = check(trace, record, "cmcp-runtime")
    assert any(f.failed() and "TR-SIG-001" in f.code for f in findings)


def test_missing_signature_fails():
    record = _make_signed_record()
    record["signature"] = ""
    trace = record["trace"]
    findings = check(trace, record, "cmcp-runtime")
    assert any(f.failed() for f in findings)


def test_trace_format_level0_is_unverified_never_pass_only():
    trace = {
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "test", "y": "test"}},
    }
    findings = check(trace, trace, "trace", level=0)
    statuses = {f.status for f in findings}
    assert Status.UNVERIFIED in statuses, "plain trace records must be marked UNVERIFIED"
    assert Status.SKIP not in statuses, "missing crypto must not be reported as a benign skip"
    assert Status.FAIL not in statuses


@pytest.mark.parametrize("level", [1, 2])
def test_trace_format_fails_at_signature_requiring_levels(level):
    trace = {
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "test", "y": "test"}},
    }
    findings = check(trace, trace, "trace", level=level)
    failed = [f for f in findings if f.failed()]
    assert any("TR-SIG-005" in f.code for f in failed), (
        f"plain trace record must FAIL TR-SIG at level {level}: {findings}"
    )


def test_trace_format_missing_kty_fails():
    trace = {"cnf": {"jwk": {}}}
    findings = check(trace, trace, "trace")
    assert any(f.failed() for f in findings)


def test_plain_trace_embedded_ed25519_signature_passes():
    """plain TRACE record signed with agentrust-trace sign_record() gets TR-SIG-005 PASS."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    x = _b64url(pub.public_bytes_raw())

    trace: dict = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": 1748000000,
        "subject": "did:mesh:spiffe://example.org/agent/test",
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "a" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x}},
        "signature": "",
    }
    body = _canonical_json({k: v for k, v in trace.items() if k != "signature"})
    trace["signature"] = _b64url(priv.sign(body))

    findings = check(trace, trace, "trace")
    sig_findings = [f for f in findings if f.code == "TR-SIG-005"]
    assert sig_findings, "TR-SIG-005 finding expected"
    assert all(f.passed() for f in sig_findings), sig_findings


def test_plain_trace_tampered_embedded_signature_fails():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    x = _b64url(pub.public_bytes_raw())

    trace: dict = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": 1748000000,
        "subject": "did:mesh:spiffe://example.org/agent/test",
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "a" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x}},
        "signature": "",
    }
    body = _canonical_json({k: v for k, v in trace.items() if k != "signature"})
    trace["signature"] = _b64url(priv.sign(body))
    trace["iat"] = 1748000001  # tamper after signing

    findings = check(trace, trace, "trace")
    sig_findings = [f for f in findings if f.code == "TR-SIG-005"]
    assert any(f.failed() for f in sig_findings), sig_findings


# --- the four TR-SIG paths that measured margin 0 --------------------------
#
# Each of these sites could have been deleted with no test failing. The two
# check_cmcp_runtime key-shape sites matter most: they are the guard that stops a
# record being read as Ed25519-verified when it carries some other key entirely.


def test_cmcp_runtime_non_ed25519_key_fails():
    """kty/crv is not OKP/Ed25519. Deleting this site would let the verifier
    proceed toward an Ed25519 verification on a key that is not one."""
    record = _make_signed_record()
    record["trace"]["cnf"]["jwk"] = {"kty": "EC", "crv": "P-256", "x": "irrelevant"}
    failed = [f for f in check(record["trace"], record, "cmcp-runtime") if f.failed()]
    assert any(f.code == "TR-SIG-002" for f in failed), failed


def test_cmcp_runtime_ed25519_without_x_fails():
    """Right key type, no public key. Separated from the case above because an
    implementation that checks kty/crv without checking x passes one and fails
    the other, which is what makes them two vectors rather than one."""
    record = _make_signed_record()
    record["trace"]["cnf"]["jwk"] = {"kty": "OKP", "crv": "Ed25519"}
    failed = [f for f in check(record["trace"], record, "cmcp-runtime") if f.failed()]
    assert any(f.code == "TR-SIG-002" for f in failed), failed


def test_unsupported_key_type_fails():
    """kty present and not in the supported set, as distinct from kty absent."""
    record = _make_signed_record()
    trace = record["trace"]
    trace["cnf"]["jwk"] = {"kty": "RSA", "n": "...", "e": "AQAB"}
    failed = [f for f in check(trace, record, "trace") if f.failed()]
    assert any(f.code == "TR-SIG-004" for f in failed), failed
    assert any("unsupported key type" in f.message for f in failed)


def test_signature_present_with_wrong_key_type_fails():
    """A signature that cannot be checked must fail, never quietly go unverified.
    Distinct from the no-signature path, which is UNVERIFIED at Level 0."""
    record = _make_signed_record()
    trace = record["trace"]
    trace["signature"] = record["signature"]
    trace["cnf"]["jwk"] = {"kty": "EC", "crv": "P-256", "x": "irrelevant"}
    sig_findings = [f for f in check(trace, record, "trace") if f.code == "TR-SIG-005"]
    assert sig_findings, "TR-SIG-005 must be reported when a signature is present"
    assert any(f.failed() for f in sig_findings), sig_findings
    assert not any(f.status == Status.UNVERIFIED for f in sig_findings)


@pytest.mark.parametrize("value", [9007199254740992.0, -9007199254740992.0, 1.0e21, -1.0e21])
def test_whole_float_past_safe_integer_range_is_refused_in_canonicalization(value):
    import rfc8785

    from trace_tests.modules.tr_sig import _canonical_json

    for container in ({"n": value}, {"a": [{"n": value}]}, {"a": ({"n": value},)}):
        with pytest.raises(rfc8785.IntegerDomainError):
            _canonical_json(container)

    record = _make_signed_record()
    record["trace"]["extra"] = value
    cmcp_findings = [
        f for f in check(record["trace"], record, "cmcp-runtime") if f.code == "TR-SIG-001"
    ]
    assert len(cmcp_findings) == 1
    assert cmcp_findings[0].failed()
    assert "no RFC 8785 canonical form" in cmcp_findings[0].message

    trace = dict(record["trace"])
    trace["signature"] = record["signature"]
    plain_findings = [f for f in check(trace, trace, "trace") if f.code == "TR-SIG-005"]
    assert len(plain_findings) == 1
    assert plain_findings[0].failed()
    assert "no RFC 8785 canonical form" in plain_findings[0].message


def test_whole_float_inside_safe_integer_range_canonicalizes_by_value():
    from trace_tests.modules.tr_sig import _canonical_json

    assert _canonical_json({"n": 9007199254740991.0}) == b'{"n":9007199254740991}'
    assert _canonical_json({"n": -9007199254740991.0}) == b'{"n":-9007199254740991}'
    assert _canonical_json({"n": 1785000000.0}) == b'{"n":1785000000}'
    assert _canonical_json({"n": 1.785e9}) == b'{"n":1785000000}'


def test_deeply_nested_record_fails_closed_without_raising():
    nested: dict = {}
    cursor = nested
    for _ in range(1500):
        cursor["a"] = {}
        cursor = cursor["a"]

    record = _make_signed_record()
    record["trace"]["nested"] = nested
    cmcp_findings = [
        f for f in check(record["trace"], record, "cmcp-runtime") if f.code == "TR-SIG-001"
    ]
    assert len(cmcp_findings) == 1
    assert cmcp_findings[0].failed()
    assert "nests too deeply" in cmcp_findings[0].message

    trace = dict(record["trace"])
    trace["signature"] = record["signature"]
    plain_findings = [f for f in check(trace, trace, "trace") if f.code == "TR-SIG-005"]
    assert len(plain_findings) == 1
    assert plain_findings[0].failed()
    assert "nests too deeply" in plain_findings[0].message


def test_number_spelling_vectors_match_expected_conformance_verdicts():
    import pathlib

    from trace_tests.runner import run

    vectors_dir = pathlib.Path(__file__).resolve().parents[3] / "examples" / "number-spelling"
    expected_by_name = {
        "01-integer-spelling-verified.json": ("pass", "skip", "pass"),
        "02-fraction-spelling-verified.json": ("pass", "skip", "pass"),
        "03-exponent-spelling-verified.json": ("pass", "skip", "pass"),
        "04-fractional-value-rejected.json": ("fail", "skip", "pass"),
        "05-fractional-value-exponent-spelling-rejected.json": ("fail", "skip", "pass"),
        "06-above-range-integer-spelling-rejected.json": ("pass", "fail", "fail"),
        "07-above-range-exponent-spelling-rejected.json": ("pass", "fail", "fail"),
    }
    paths = sorted(vectors_dir.glob("*.json"))
    assert [p.name for p in paths] == list(expected_by_name)
    for path in paths:
        vec = json.loads(path.read_text(encoding="utf-8"))
        res = run(dict(vec["record"]), "trace", level=0, max_age_seconds=10**12)
        env_iat = next(f for f in res["TR-ENV"] if f.code == "TR-ENV-002").status.value
        apr_ts = next(f for f in res["TR-APR"] if f.code == "TR-APR-004").status.value
        sig = next(f for f in res["TR-SIG"] if f.code == "TR-SIG-005").status.value
        assert (env_iat, apr_ts, sig) == expected_by_name[path.name], path.name

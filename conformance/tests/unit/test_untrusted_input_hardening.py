"""Regressions for defects found on untrusted input, each confirmed failing first.

* A digest or subject with a trailing newline passed the format checks, because
  Python's ``$`` matches before a final ``\\n``. JSON Schema patterns are ECMA-262,
  where it does not, so the suite was passing values the schema forbids.
* A non-ASCII ``runtime.nonce`` raised ``TypeError`` out of
  ``hmac.compare_digest`` instead of producing a TR-RTE-004 finding.
* A signature was accepted in any spelling that decoded to the right bytes:
  the standard alphabet, padding, stray characters, nonzero trailing bits. The
  field is outside the signed body, so every such spelling is a different record
  that still verifies.
* TR-ANC-002 proved inclusion of claims that registry-anchor-v1 section 1
  puts outside the anchor-leaf profile (non-integer numbers, integers outside
  the safe range), whose leaf bytes only Python's ``json.dumps`` writes.
* ``load_record`` let ``RecursionError``, ``UnicodeDecodeError`` and ``OSError``
  escape its documented ``LoadError``, and silently kept the last of two
  duplicate member names.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
from typing import Any

import pytest
from click.testing import CliRunner

from trace_tests import inclusion
from trace_tests.cli import main
from trace_tests.loader import LoadError, load_record
from trace_tests.modules import tr_anc, tr_env, tr_pol, tr_rte, tr_sca, tr_sig, tr_txn
from trace_tests.result import Status

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors"
_D256 = "sha256:" + "a" * 64


def _signed_root() -> dict[str, Any]:
    return json.loads((VECTORS / "signed_root.json").read_text(encoding="utf-8"))


def _status(findings: list[Any], code: str) -> Status:
    (found,) = [f for f in findings if f.code == code]
    return found.status


# -- trailing newline ---------------------------------------------------------


def test_measurement_with_trailing_newline_fails_tr_rte_002() -> None:
    findings = tr_rte.check({"runtime": {"platform": "intel-tdx", "measurement": _D256 + "\n"}})
    assert _status(findings, "TR-RTE-002") is Status.FAIL


def test_provenance_digest_with_trailing_newline_fails_tr_sca_002() -> None:
    findings = tr_sca.check({"build_provenance": {"slsa_level": 1, "digest": _D256 + "\n"}})
    assert _status(findings, "TR-SCA-002") is Status.FAIL


def test_transcript_hash_with_trailing_newline_fails_tr_txn_001() -> None:
    findings = tr_txn.check({"tool_transcript": {"hash": _D256 + "\n"}})
    assert _status(findings, "TR-TXN-001") is Status.FAIL


def test_bundle_hash_with_trailing_newline_fails_tr_pol_001() -> None:
    findings = tr_pol.check(
        {"policy": {"bundle_hash": _D256 + "\n", "enforcement_mode": "enforce"}}
    )
    assert _status(findings, "TR-POL-001") is Status.FAIL


def test_subject_with_trailing_newline_fails_tr_env_003() -> None:
    findings = tr_env.check({"subject": "spiffe://example.org/agent\n"})
    assert _status(findings, "TR-ENV-003") is Status.FAIL


def test_receipt_hash_with_trailing_newline_is_malformed() -> None:
    with pytest.raises(inclusion.InclusionError):
        inclusion.decode_hash(_D256 + "\n")


# -- nonce comparison ---------------------------------------------------------


@pytest.mark.parametrize(
    ("actual", "expected", "status"),
    [
        ("é", "abc", Status.FAIL),
        ("abc", "é", Status.FAIL),
        ("nönce", "nönce", Status.PASS),
        ("\ud800", "abc", Status.FAIL),
    ],
)
def test_non_ascii_nonce_is_a_finding_not_an_exception(
    actual: str, expected: str, status: Status
) -> None:
    trace = {"runtime": {"platform": "intel-tdx", "measurement": _D256, "nonce": actual}}
    findings = tr_rte.check(trace, 1, expected_nonce=expected)
    assert _status(findings, "TR-RTE-004") is status


# -- signature encoding -------------------------------------------------------


def test_the_vector_verifies_as_published() -> None:
    rec = _signed_root()
    assert _status(tr_sig.check(rec, rec, "trace", 1), "TR-SIG-005") is Status.PASS


def _respelled(sig: str) -> list[str]:
    raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    last = sig[-1]
    # 64 bytes is 86 characters with 4 unused low bits in the last one.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    other_bits = alphabet[alphabet.index(last) ^ 0b0001]
    return [
        base64.b64encode(raw).decode(),  # standard alphabet, padded
        base64.urlsafe_b64encode(raw).decode(),  # base64url, padded
        sig[:10] + "!!!!" + sig[10:],  # characters outside the alphabet
        sig[:-1] + other_bits,  # nonzero trailing bits
        " " + sig,
    ]


@pytest.mark.parametrize("index", range(5))
def test_signature_respelled_to_the_same_bytes_is_refused(index: int) -> None:
    rec = _signed_root()
    rec["signature"] = _respelled(rec["signature"])[index]
    assert _status(tr_sig.check(rec, rec, "trace", 1), "TR-SIG-005") is Status.FAIL


def test_jwk_x_respelled_is_refused() -> None:
    rec = _signed_root()
    x = rec["cnf"]["jwk"]["x"]
    rec["cnf"]["jwk"]["x"] = x + "="
    # The signed body changed too, so the result was already FAIL; what matters
    # is the reason: the key is refused as a key, not as a bad signature.
    (finding,) = [f for f in tr_sig.check(rec, rec, "trace", 1) if f.code == "TR-SIG-005"]
    assert finding.status is Status.FAIL
    assert "cnf.jwk.x" in finding.message


def test_cmcp_signature_respelled_is_refused() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    x = base64.urlsafe_b64encode(key.public_key().public_bytes_raw()).rstrip(b"=").decode()
    rec: dict[str, Any] = {
        "cmcp_version": "0.1",
        "trace": {"cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}},
    }
    sig = key.sign(tr_sig._canonical_json(rec))
    rec["signature"] = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    assert _status(tr_sig.check_cmcp_runtime(rec), "TR-SIG-001") is Status.PASS

    rec["signature"] = base64.urlsafe_b64encode(sig).decode()  # padded
    assert _status(tr_sig.check_cmcp_runtime(rec), "TR-SIG-001") is Status.FAIL


# -- loader -------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        b"[" * 100_000 + b"]" * 100_000,
        b'{"a":' * 100_000 + b"1" + b"}" * 100_000,
        b"\xff\xfe{\x00}\x00",
        b'{"iat": "\xc3"}',
    ],
    ids=["deep-array", "deep-object", "utf16", "bad-utf8"],
)
def test_loader_raises_only_load_error(tmp_path: pathlib.Path, content: bytes) -> None:
    path = tmp_path / "record.json"
    path.write_bytes(content)
    with pytest.raises(LoadError):
        load_record(str(path))


def test_loader_on_a_directory_raises_load_error(tmp_path: pathlib.Path) -> None:
    with pytest.raises(LoadError):
        load_record(str(tmp_path))


@pytest.mark.parametrize(
    "text",
    [
        '{"subject": "spiffe://a/b", "subject": "spiffe://c/d"}',
        '{"policy": {"bundle_hash": "x", "bundle_hash": "y"}}',
        '{"cnf": {"jwk": [{"kty": "OKP", "kty": "EC"}]}}',
    ],
)
def test_loader_refuses_duplicate_member_names(tmp_path: pathlib.Path, text: str) -> None:
    path = tmp_path / "record.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(LoadError, match="duplicate"):
        load_record(str(path))


def test_duplicate_member_cannot_ride_a_valid_signature(tmp_path: pathlib.Path) -> None:
    """The signature covers the last value; another parser may read the first."""
    rec = _signed_root()
    body = json.dumps(rec)
    injected = '{"subject": "spiffe://attacker.example/agent", ' + body[1:]
    path = tmp_path / "record.json"
    path.write_text(injected, encoding="utf-8")
    result = CliRunner().invoke(main, ["verify", "--record", str(path)])
    assert result.exit_code == 2
    assert "duplicate" in result.output


@pytest.mark.parametrize("option", ["--receipt", "--policy-dir"])
@pytest.mark.parametrize(
    "content",
    [b"\xff\xfe{\x00}\x00", b"[" * 100_000, b'{"a": "x.json", "a": "y.json"}'],
    ids=["utf16", "deep", "duplicate"],
)
def test_cli_side_inputs_exit_2_not_traceback(
    tmp_path: pathlib.Path, option: str, content: bytes
) -> None:
    record = VECTORS / "valid_level0.json"
    if option == "--receipt":
        side = tmp_path / "receipt.json"
        arg = str(side)
    else:
        side = tmp_path / "resolutions.json"
        arg = str(tmp_path)
    side.write_bytes(content)
    result = CliRunner().invoke(main, ["verify", "--record", str(record), option, arg])
    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


# -- anchor-leaf profile ------------------------------------------------------


def _single_leaf_receipt(claim: dict[str, Any]) -> dict[str, Any]:
    """A one-leaf tree built the way the registry builds it: plain json.dumps."""
    leaf = json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    root = hashlib.sha256(b"\x00" + leaf.encode("ascii")).hexdigest()
    return {"leaf_index": 0, "leaf_count": 1, "audit_path": [], "merkle_root": "sha256:" + root}


@pytest.mark.parametrize(
    "value",
    [1.5, 2**53, -(2**53), float("nan"), float("inf"), [{"x": 0.1}]],
    ids=["float", "above-safe", "below-safe", "nan", "inf", "nested-float"],
)
def test_claim_outside_the_anchor_profile_is_not_proven(value: Any) -> None:
    """registry-anchor-v1 section 1 puts these outside the leaf profile.

    Their leaf bytes differ across implementations of the same four rules, so a
    proof over them proves inclusion of bytes only Python's json.dumps writes.
    """
    claim = {"transparency": "https://log.example.com/e/1", "extra": value}
    findings = tr_anc.check(claim, receipt=_single_leaf_receipt(claim))
    assert _status(findings, "TR-ANC-002") is Status.FAIL


def test_claim_inside_the_anchor_profile_is_proven() -> None:
    claim = {
        "transparency": "https://log.example.com/e/1",
        "n": 2**53 - 1,
        "m": -(2**53 - 1),
        "ok": True,
        "none": None,
    }
    findings = tr_anc.check(claim, receipt=_single_leaf_receipt(claim))
    assert _status(findings, "TR-ANC-002") is Status.PASS


# -- found by the ClusterFuzzLite targets, run locally before landing ---------


def test_lone_surrogate_in_a_key_is_a_finding_not_an_exception(tmp_path: pathlib.Path) -> None:
    """fuzz_signature: rfc8785 raises UnicodeEncodeError, not CanonicalizationError.

    A lone surrogate in a string *value* was already covered. In a *key* the
    library fails while sorting, with an exception outside its own hierarchy, and
    that reached the CLI as a traceback.
    """
    rec = _signed_root()
    rec["\ud800"] = 1
    (finding,) = [f for f in tr_sig.check(rec, rec, "trace", 1) if f.code == "TR-SIG-005"]
    assert finding.status is Status.FAIL
    assert "canonical form" in finding.message

    envelope: dict[str, Any] = {
        "cmcp_version": "0.1",
        "\udc00": 1,
        "trace": {"cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43}}},
        "signature": "A" * 86,
    }
    assert _status(tr_sig.check_cmcp_runtime(envelope), "TR-SIG-001") is Status.FAIL

    path = tmp_path / "record.json"
    path.write_text(json.dumps(rec), encoding="utf-8")
    result = CliRunner().invoke(main, ["verify", "--record", str(path), "--level", "1"])
    assert result.exit_code == 1, result.output


@pytest.mark.parametrize("value", [{"uri": "https://a.b/c"}, ["https://a.b/c"], 5, True])
def test_non_string_transparency_renders(tmp_path: pathlib.Path, value: Any) -> None:
    """fuzz_record: to_html passed the raw value to html.escape, which needs a str."""
    rec = json.loads((VECTORS / "valid_level0.json").read_text(encoding="utf-8"))
    rec["transparency"] = value
    path = tmp_path / "record.json"
    path.write_text(json.dumps(rec), encoding="utf-8")
    html_out = tmp_path / "report.html"
    result = CliRunner().invoke(
        main, ["report", "--record", str(path), "--html", str(html_out)]
    )
    assert result.exit_code == 0, result.output
    assert "Transparency anchor" in html_out.read_text(encoding="utf-8")

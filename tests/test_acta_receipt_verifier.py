"""Unit tests for tools/acta_receipt_verifier.py.

Each rule the verifier adds over the checks ``tests/test_acta_fixtures.py``
already made has a test here that fails when that rule is switched off:

* Section 6.6, a ``signature`` member in the payload:
  ``test_a_payload_carrying_a_signature_member_is_refused``;
* Section 9.2, the key's validity window:
  ``test_issued_at_before_valid_from_is_refused`` and
  ``test_issued_at_at_valid_until_is_refused``;
* Section 6.7, the ``sha256:`` link: ``test_a_prefixed_link_is_accepted``;
  a link naming another algorithm:
  ``test_a_link_naming_another_algorithm_is_refused``; and a receipt presented
  after a predecessor it does not link to:
  ``test_a_missing_link_after_a_known_predecessor_is_refused``.

Receipts here are signed with a fixed test key, so the file needs nothing beyond
rfc8785 and cryptography and runs on every Python version in the CI matrix.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tools.acta_receipt_verifier import (
    IssuerKey,
    envelope_hash,
    jcs,
    main,
    verify_envelope,
)

ACTA_DIR = Path(__file__).resolve().parents[1] / "examples" / "action-receipts" / "acta"
EXPECTED = json.loads((ACTA_DIR / "expected.json").read_text())

KID = "test:acta-verifier:ed25519"
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEY = IssuerKey(SIGNER.public_key())


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def _payload(**extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": "protectmcp:decision",
        "issued_at": "2026-03-01T00:00:00Z",
        "issuer_id": KID,
        "tool_name": "files.read",
        "decision": "allow",
    }
    payload.update(extra)
    return payload


def _sign(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "payload": payload,
        "signature": {"alg": "EdDSA", "kid": KID, "sig": SIGNER.sign(jcs(payload)).hex()},
    }


def _window(valid_from: str | None, valid_until: str | None) -> IssuerKey:
    return IssuerKey(
        KEY.public_key,
        valid_from=_utc(valid_from) if valid_from else None,
        valid_until=_utc(valid_until) if valid_until else None,
    )


# --- the committed fixtures --------------------------------------------------


def _fixture_verdict(result: dict[str, str]) -> tuple[str, str | None]:
    if result["signature"] == "fail":
        return "invalid", "signature_invalid"
    if result["chain"] == "fail":
        return "invalid", "chain_link_mismatch"
    return "valid", None


@pytest.mark.parametrize("name", sorted(EXPECTED["results"]))
def test_every_fixture_gets_the_verdict_expected_json_declares(name: str) -> None:
    """Signature and chain columns only: freshness and binding are the caller's comparisons."""
    signer = IssuerKey(
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(EXPECTED["signer_public_key_hex"]))
    )
    envelope = json.loads((ACTA_DIR / name).read_text())
    predecessor_name = EXPECTED["chain"].get(name)
    predecessor = (
        json.loads((ACTA_DIR / predecessor_name).read_text()) if predecessor_name else None
    )
    assert verify_envelope(envelope, signer, predecessor) == _fixture_verdict(
        EXPECTED["results"][name]
    )


# --- Section 6.6 -------------------------------------------------------------


@pytest.mark.parametrize("member", [None, "", "00" * 64])
def test_a_payload_carrying_a_signature_member_is_refused(member: Any) -> None:
    """The signature verifies over these bytes; only the Section 6.6 rule refuses it."""
    envelope = _sign(_payload(signature=member))
    assert verify_envelope(envelope, KEY) == ("invalid", "signature_in_signing_input")


def test_a_signature_over_the_prehashed_payload_does_not_verify() -> None:
    payload = _payload()
    envelope = _sign(payload)
    envelope["signature"]["sig"] = SIGNER.sign(hashlib.sha256(jcs(payload)).digest()).hex()
    assert verify_envelope(envelope, KEY) == ("invalid", "signature_invalid")


def test_a_payload_altered_after_signing_does_not_verify() -> None:
    envelope = _sign(_payload())
    envelope["payload"]["decision"] = "deny"
    assert verify_envelope(envelope, KEY) == ("invalid", "signature_invalid")


# --- Section 9.2 -------------------------------------------------------------


def test_issued_at_before_valid_from_is_refused() -> None:
    key = _window("2026-04-01T00:00:00Z", None)
    assert verify_envelope(_sign(_payload()), key) == ("invalid", "key_outside_validity_window")


def test_issued_at_at_valid_until_is_refused() -> None:
    key = _window(None, "2026-03-01T00:00:00Z")
    assert verify_envelope(_sign(_payload()), key) == ("invalid", "key_outside_validity_window")


def test_issued_at_at_valid_from_is_accepted() -> None:
    key = _window("2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z")
    assert verify_envelope(_sign(_payload()), key) == ("valid", None)


def test_a_key_with_no_window_is_not_checked_against_one() -> None:
    envelope = _sign(_payload(issued_at="1999-01-01T00:00:00Z"))
    assert verify_envelope(envelope, KEY) == ("valid", None)


# --- Section 6.7 -------------------------------------------------------------


def test_a_prefixed_link_is_accepted() -> None:
    first = _sign(_payload())
    second = _sign(_payload(previousReceiptHash="sha256:" + envelope_hash(first)))
    assert verify_envelope(second, KEY, first) == ("valid", None)


def test_a_bare_hex_link_from_revision_02_is_accepted() -> None:
    first = _sign(_payload())
    second = _sign(_payload(previousReceiptHash=envelope_hash(first)))
    assert verify_envelope(second, KEY, first) == ("valid", None)


def test_a_link_naming_another_receipt_is_refused() -> None:
    first = _sign(_payload())
    other = _sign(_payload(tool_name="files.write"))
    second = _sign(_payload(previousReceiptHash="sha256:" + envelope_hash(other)))
    assert verify_envelope(second, KEY, first) == ("invalid", "chain_link_mismatch")


def test_a_missing_link_after_a_known_predecessor_is_refused() -> None:
    first = _sign(_payload())
    assert verify_envelope(_sign(_payload()), KEY, first) == ("invalid", "chain_link_mismatch")


def test_a_link_naming_another_algorithm_is_refused() -> None:
    first = _sign(_payload())
    digest = hashlib.sha512(jcs(first)).hexdigest()
    second = _sign(_payload(previousReceiptHash="sha512:" + digest))
    assert verify_envelope(second, KEY) == ("invalid", "unsupported_chain_hash_algorithm")


# --- what cannot be decided -----------------------------------------------


def test_an_object_that_is_not_an_envelope_is_undecidable() -> None:
    flat = copy.deepcopy(_payload())
    flat["signature"] = SIGNER.sign(jcs(_payload())).hex()
    assert verify_envelope(flat, KEY) == ("undecidable", "not_an_envelope")


def test_an_algorithm_other_than_eddsa_is_undecidable() -> None:
    envelope = _sign(_payload())
    envelope["signature"]["alg"] = "ES256"
    assert verify_envelope(envelope, KEY) == ("undecidable", "unsupported_algorithm")


# --- the command line ----------------------------------------------------------


def _jwks(tmp_path: Path, **window: str) -> Path:
    x = KEY.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": KID,
        "x": base64.urlsafe_b64encode(x).decode().rstrip("="),
    }
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": [{**jwk, **window}]}))
    return path


def _run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], receipt: Any
) -> tuple[int, dict[str, Any]]:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt))
    status = main([str(path)])
    last = capsys.readouterr().out.strip().splitlines()[-1]
    return status, json.loads(last)


def test_the_command_line_reads_the_key_from_the_key_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AEV_RECEIPT_JWKS", str(_jwks(tmp_path)))
    monkeypatch.delenv("AEV_RECEIPT_CONTEXT", raising=False)
    assert _run(tmp_path, capsys, _sign(_payload())) == (0, {"verdict": "valid", "code": None})


def test_the_command_line_applies_the_key_sets_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AEV_RECEIPT_JWKS", str(_jwks(tmp_path, valid_from="2026-04-01T00:00:00Z")))
    monkeypatch.delenv("AEV_RECEIPT_CONTEXT", raising=False)
    status, answer = _run(tmp_path, capsys, _sign(_payload()))
    assert (status, answer) == (1, {"verdict": "invalid", "code": "key_outside_validity_window"})


def test_the_command_line_reads_the_predecessor_from_the_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    first = _sign(_payload())
    first_path = tmp_path / "first.json"
    first_path.write_text(json.dumps(first))
    context = tmp_path / "context.json"
    context.write_text(json.dumps({"chain": [str(first_path)]}))
    monkeypatch.setenv("AEV_RECEIPT_JWKS", str(_jwks(tmp_path)))
    monkeypatch.setenv("AEV_RECEIPT_CONTEXT", str(context))
    status, answer = _run(tmp_path, capsys, _sign(_payload()))
    assert (status, answer) == (1, {"verdict": "invalid", "code": "chain_link_mismatch"})


def test_an_unknown_kid_is_undecidable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AEV_RECEIPT_JWKS", str(_jwks(tmp_path)))
    monkeypatch.delenv("AEV_RECEIPT_CONTEXT", raising=False)
    envelope = _sign(_payload())
    envelope["signature"]["kid"] = "test:somebody-else"
    assert _run(tmp_path, capsys, envelope) == (
        2,
        {"verdict": "undecidable", "code": "unknown_kid"},
    )


def test_no_key_set_is_undecidable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("AEV_RECEIPT_JWKS", raising=False)
    status, answer = _run(tmp_path, capsys, _sign(_payload()))
    assert (status, answer) == (2, {"verdict": "undecidable", "code": "no_key_set"})

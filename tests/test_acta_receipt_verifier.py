"""Unit tests for tools/acta_receipt_verifier.py.

Each rule the verifier adds over the checks ``tests/test_acta_fixtures.py``
already made has a test here that fails when that rule is switched off:

* Section 6.6, a ``signature`` member in the payload:
  ``test_a_payload_carrying_a_signature_member_is_refused``;
* Section 6.6, a ``signature.sig`` that is not 128 lowercase hex characters:
  ``test_a_non_canonical_signature_hex_is_refused``;
* Section 9.2, the key's validity window:
  ``test_issued_at_before_valid_from_is_refused`` and
  ``test_issued_at_at_valid_until_is_refused``;
* Section 6.7, the ``sha256:`` link: ``test_a_prefixed_link_is_accepted``;
  a link naming another algorithm:
  ``test_a_link_naming_another_algorithm_is_refused``; and a receipt presented
  after a predecessor it does not link to:
  ``test_a_missing_link_after_a_known_predecessor_is_refused``;
* Section 5.3, JWK Set resolution:
  ``test_a_jwk_carrying_private_key_material_is_refused`` and
  ``test_a_jwk_with_non_canonical_base64url_x_is_refused``;
* JSON input and JCS hardening:
  ``test_duplicate_json_keys_are_undecidable``,
  ``test_deeply_nested_json_is_undecidable``, and
  ``test_an_uncanonicalizable_predecessor_or_deep_payload_does_not_crash``.

All eleven committed fixtures are checked here under the key and validity window
that ``acta-keys.json`` publishes. Among them, 08 carries a ``sha256:`` link and 09
a link to the hash of its predecessor's payload alone (Section 6.7), 10 carries a
``signature`` member (Section 6.6), and 11 is dated before the key's
``valid_from`` (Section 9.2).

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
    Undecidable,
    envelope_hash,
    issuer_key,
    jcs,
    main,
    signature_verifies,
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


def _load(name: str) -> dict[str, Any]:
    return json.loads((ACTA_DIR / name).read_text(encoding="utf-8"))


def _committed_key(kid: str) -> IssuerKey:
    """The key the committed key set publishes under ``kid`` (Section 5.3), window included."""
    (jwk,) = [key for key in _load(EXPECTED["key_set"])["keys"] if key["kid"] == kid]
    x = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    return IssuerKey(
        Ed25519PublicKey.from_public_bytes(x),
        valid_from=_utc(jwk["valid_from"]),
        valid_until=_utc(jwk["valid_until"]),
    )


def _fixture_verdict(result: dict[str, str]) -> tuple[str, str | None]:
    if result["signing_input"] == "fail":
        return "invalid", "signature_in_signing_input"
    if result["signature"] == "fail":
        return "invalid", "signature_invalid"
    if result["key_window"] == "fail":
        return "invalid", "key_outside_validity_window"
    if result["chain"] == "fail":
        return "invalid", "chain_link_mismatch"
    return "valid", None


@pytest.mark.parametrize("name", sorted(EXPECTED["results"]))
def test_every_fixture_gets_the_verdict_expected_json_declares(name: str) -> None:
    """The verdict and code each fixture's columns imply, freshness and binding aside.

    Those two are the caller's comparisons. The key and its Section 9.2 window come
    from the committed key set, found by the fixture's ``kid``.
    """
    envelope = _load(name)
    predecessor_name = EXPECTED["chain"].get(name)
    predecessor = _load(predecessor_name) if predecessor_name else None
    key = _committed_key(envelope["signature"]["kid"])
    assert verify_envelope(envelope, key, predecessor) == _fixture_verdict(
        EXPECTED["results"][name]
    )


@pytest.mark.parametrize(
    ("name", "taken_away"),
    [("09-payload-only-chain-link.json", "predecessor"), ("11-outside-key-window.json", "window")],
)
def test_a_revision_03_negative_verifies_once_its_rule_has_nothing_to_check(
    name: str, taken_away: str
) -> None:
    """With no predecessor to compare (09) or no window on the key (11), each verifies.

    So the rule each one names is the only one that refuses it. 10 has no input like
    this to take away: the Section 6.6 rule reads the payload itself.
    """
    envelope = _load(name)
    key = _committed_key(envelope["signature"]["kid"])
    if taken_away == "window":
        key = IssuerKey(key.public_key)
    assert verify_envelope(envelope, key) == ("valid", None)  # no predecessor passed


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


@pytest.mark.parametrize(
    "transform",
    [
        "uppercase",
        "mixed_case",
        "leading_space",
        "trailing_newline",
        "internal_space",
        "uppercase_and_whitespace",
    ],
)
def test_a_non_canonical_signature_hex_is_refused(transform: str) -> None:
    """``bytes.fromhex`` accepts uppercase hex and whitespace; ``signature_verifies`` must not."""
    envelope = _sign(_payload())
    sig = envelope["signature"]["sig"]
    forms = {
        "uppercase": sig.upper(),
        "mixed_case": sig[0].upper() + sig[1:],
        "leading_space": "  " + sig,
        "trailing_newline": sig + "\n",
        "internal_space": sig[:64] + " " + sig[64:],
        "uppercase_and_whitespace": "  " + sig.upper() + "\n",
    }
    envelope["signature"]["sig"] = forms[transform]
    assert not signature_verifies(envelope, KEY.public_key)
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


@pytest.mark.parametrize(
    "link",
    [
        "sha256:not-a-digest",
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 63,
        "sha256:",
        "a" * 65,
        7,
    ],
)
def test_a_malformed_link_is_refused_without_a_predecessor(link: Any) -> None:
    second = _sign(_payload(previousReceiptHash=link))
    assert verify_envelope(second, KEY) == ("invalid", "malformed_chain_link")


def test_a_malformed_link_is_refused_before_the_predecessor_is_compared() -> None:
    first = _sign(_payload())
    second = _sign(_payload(previousReceiptHash="sha256:not-a-digest"))
    assert verify_envelope(second, KEY, first) == ("invalid", "malformed_chain_link")


def test_a_well_formed_link_with_no_predecessor_is_accepted() -> None:
    second = _sign(_payload(previousReceiptHash="sha256:" + "0" * 64))
    assert verify_envelope(second, KEY) == ("valid", None)


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


@pytest.mark.parametrize(
    ("name", "status", "code"),
    [
        ("07-valid-inside-key-window.json", 0, None),
        ("11-outside-key-window.json", 1, "key_outside_validity_window"),
    ],
)
def test_the_command_line_reads_the_committed_key_set(
    name: str,
    status: int,
    code: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``acta-keys.json`` works as published: its ``kid`` resolves and its window applies."""
    monkeypatch.setenv("AEV_RECEIPT_JWKS", str(ACTA_DIR / EXPECTED["key_set"]))
    monkeypatch.delenv("AEV_RECEIPT_CONTEXT", raising=False)
    verdict = "valid" if code is None else "invalid"
    assert _run(tmp_path, capsys, _load(name)) == (status, {"verdict": verdict, "code": code})


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


# --- Section 5.3 JWK hardening and JSON/JCS input hardening ------------------


CANONICAL_X = (
    base64.urlsafe_b64encode(KEY.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    .rstrip(b"=")
    .decode("ascii")
)


def _public_jwk(**extra: Any) -> dict[str, Any]:
    return {"kty": "OKP", "crv": "Ed25519", "kid": KID, "x": CANONICAL_X, **extra}


@pytest.mark.parametrize("param", ["d", "p", "q", "dp", "dq", "qi", "oth", "k"])
def test_a_jwk_carrying_private_key_material_is_refused(param: str) -> None:
    """RFC 7517 / RFC 7518 / RFC 8037 private or symmetric key parameters are refused."""
    with pytest.raises(Undecidable, match=r"^malformed_key_set\Z"):
        issuer_key({"keys": [_public_jwk(**{param: "secret"})]}, KID)


@pytest.mark.parametrize(
    "bad_x",
    [
        CANONICAL_X + "=",
        CANONICAL_X + "====",
        "+" + CANONICAL_X[1:],
        CANONICAL_X.replace("_", "/"),
        "    " + CANONICAL_X,
        CANONICAL_X + "   \n",
        CANONICAL_X + "....",
        CANONICAL_X[:-1] + "h",
        CANONICAL_X[:-1] + "i",
        CANONICAL_X[:-1] + "j",
    ],
)
def test_a_jwk_with_non_canonical_base64url_x_is_refused(bad_x: str) -> None:
    """Padded, standard-alphabet, whitespace/ignored, or non-zero-trailing-bit ``x`` is refused."""
    with pytest.raises(Undecidable, match=r"^malformed_key_set\Z"):
        issuer_key({"keys": [_public_jwk(x=bad_x)]}, KID)


@pytest.mark.parametrize("target", ["receipt_payload", "receipt_envelope", "jwks", "context"])
def test_duplicate_json_keys_are_undecidable(
    target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Duplicate JSON object keys in the receipt, key set, or context are refused as malformed."""
    jwks_path = _jwks(tmp_path)
    monkeypatch.setenv("AEV_RECEIPT_JWKS", str(jwks_path))
    monkeypatch.delenv("AEV_RECEIPT_CONTEXT", raising=False)
    envelope = _sign(_payload())
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(envelope), encoding="utf-8")

    if target == "receipt_payload":
        payload_body = json.dumps(envelope["payload"])[1:]
        dup_payload = '{"decision": "deny", ' + payload_body
        sig_json = json.dumps(envelope["signature"])
        raw = '{"payload": ' + dup_payload + ', "signature": ' + sig_json + "}"
        receipt_path.write_text(raw, encoding="utf-8")
    elif target == "receipt_envelope":
        raw = (
            '{"payload": {}, "payload": '
            + json.dumps(envelope["payload"])
            + ', "signature": '
            + json.dumps(envelope["signature"])
            + "}"
        )
        receipt_path.write_text(raw, encoding="utf-8")
    elif target == "jwks":
        jwk_json = json.dumps(_public_jwk())
        jwks_path.write_text('{"keys": [], "keys": [' + jwk_json + "]}", encoding="utf-8")
    elif target == "context":
        first = _sign(_payload())
        second = _sign(_payload(previousReceiptHash="sha256:" + envelope_hash(first)))
        receipt_path.write_text(json.dumps(second), encoding="utf-8")
        first_path = tmp_path / "first.json"
        first_path.write_text(json.dumps(first), encoding="utf-8")
        context_path = tmp_path / "context.json"
        chain_json = json.dumps([str(first_path)])
        context_path.write_text('{"chain": [], "chain": ' + chain_json + "}", encoding="utf-8")
        monkeypatch.setenv("AEV_RECEIPT_CONTEXT", str(context_path))

    status = main([str(receipt_path)])
    last = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert (status, last) == (2, {"verdict": "undecidable", "code": "malformed"})


@pytest.mark.parametrize("target", ["receipt", "jwks", "context"])
def test_deeply_nested_json_is_undecidable(
    target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Deeply nested JSON raising ``RecursionError`` in ``json.loads`` is refused as malformed."""
    jwks_path = _jwks(tmp_path)
    monkeypatch.setenv("AEV_RECEIPT_JWKS", str(jwks_path))
    monkeypatch.delenv("AEV_RECEIPT_CONTEXT", raising=False)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(_sign(_payload())), encoding="utf-8")
    deep_json = "[" * 200_000 + "]" * 200_000

    if target == "receipt":
        receipt_path.write_text(deep_json, encoding="utf-8")
    elif target == "jwks":
        jwks_path.write_text(deep_json, encoding="utf-8")
    elif target == "context":
        context_path = tmp_path / "context.json"
        context_path.write_text(deep_json, encoding="utf-8")
        monkeypatch.setenv("AEV_RECEIPT_CONTEXT", str(context_path))

    status = main([str(receipt_path)])
    last = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert (status, last) == (2, {"verdict": "undecidable", "code": "malformed"})


@pytest.mark.parametrize(
    "kind",
    [
        "deep_payload",
        "unsafe_int_predecessor",
        "nan_predecessor",
        "surrogate_predecessor",
        "deep_predecessor",
    ],
)
def test_an_uncanonicalizable_predecessor_or_deep_payload_does_not_crash(kind: str) -> None:
    """``verify_envelope`` handles ``RecursionError`` and ``CanonicalizationError`` cleanly."""
    deep: Any = "leaf"
    for _ in range(1500):
        deep = {"a": deep}

    if kind == "deep_payload":
        envelope = _sign(_payload())
        envelope["payload"]["nested"] = deep
        assert verify_envelope(envelope, KEY) == ("invalid", "signature_invalid")
        return

    second = _sign(_payload(previousReceiptHash="sha256:" + "0" * 64))
    predecessors: dict[str, Any] = {
        "unsafe_int_predecessor": {"payload": {"n": 2**53}, "signature": {}},
        "nan_predecessor": {"payload": {"n": float("nan")}, "signature": {}},
        "surrogate_predecessor": {"payload": {"s": "\ud800"}, "signature": {}},
        "deep_predecessor": deep,
    }
    assert verify_envelope(second, KEY, predecessors[kind]) == ("invalid", "chain_link_mismatch")

"""Signature-encoding vectors (spec section 3.2.2, proposal #247).

An Ed25519 or ES256 embedded signature is 64 bytes; base64url without padding
spends 86 characters (516 bits) on those 512 bits, so the final character
carries 4 bits nothing signs. RFC 4648 section 3.5 requires those unused bits
to be zero. `examples/signature-encoding/` carries three vectors that share the
same 64 decoded bytes and differ only in the final character's unused bits:
`01-canonical-signature.json` (zero, canonical), and two non-canonical
respellings, `02-non-canonical-respelling-low-bit.json` (binary 0001) and
`03-non-canonical-respelling-all-bits.json` (binary 1111). Two rejecting
respellings, not one: `tests/test_adequacy_all_sets.py` (criterion 2, "no
margin") flags a boundary a single vector covers, because an implementation
that special-cased that one bad string would pass it without implementing the
rule.

Every fact this module checks is recomputed from the committed bytes rather
than trusted from the fixtures' own declarations, matching
`tests/test_canonicalization_boundary.py`: that the three signatures decode to
the same 64 bytes, and which of the three spellings is canonical.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import ValidationError as SchemaValidationError
from pydantic import ValidationError as ModelValidationError

from agentrust_trace import TrustRecord, validate_json, verify_record

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_DIR = REPO_ROOT / "examples" / "signature-encoding"
CANONICAL_PATH = FIXTURE_DIR / "01-canonical-signature.json"
NON_CANONICAL_PATHS = [
    FIXTURE_DIR / "02-non-canonical-respelling-low-bit.json",
    FIXTURE_DIR / "03-non-canonical-respelling-all-bits.json",
]
ALL_PATHS = [CANONICAL_PATH, *NON_CANONICAL_PATHS]


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _b64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _is_canonical(value: str) -> bool:
    """RFC 4648 section 3.5, checked directly: re-encoding always emits zero for
    the unused bits, so a value that round-trips through decode/re-encode had
    them at zero already."""
    return base64.urlsafe_b64encode(_b64u(value)).rstrip(b"=").decode() == value


def _verify(fixture: dict[str, Any]) -> Any:
    """Exercise the public API with real schema, trust and age inputs, `iat`
    pinned as "now" so the vector reproduces regardless of when the suite runs."""
    validate_json(fixture["record"])
    return verify_record(
        fixture["record"],
        fixture["trusted_key"],
        allow_embedded_key=False,
        max_age_seconds=60,
        max_future_skew_seconds=0,
        now=fixture["record"]["iat"],
    )


def test_vector_set_is_complete() -> None:
    assert sorted(path.name for path in FIXTURE_DIR.glob("*.json")) == [
        "01-canonical-signature.json",
        "02-non-canonical-respelling-low-bit.json",
        "03-non-canonical-respelling-all-bits.json",
    ]


@pytest.mark.parametrize("path", NON_CANONICAL_PATHS, ids=lambda p: p.stem)
def test_every_respelling_decodes_to_the_same_64_bytes_as_canonical(path: Path) -> None:
    """A respelling of one signature, not a different signature."""
    canonical = _load(CANONICAL_PATH)
    non_canonical = _load(path)

    canonical_sig = canonical["record"]["signature"]
    non_canonical_sig = non_canonical["record"]["signature"]
    canonical_raw = _b64u(canonical_sig)
    non_canonical_raw = _b64u(non_canonical_sig)

    assert len(canonical_raw) == 64, "not a 64-byte signature; the vector premise is wrong"
    assert canonical_raw == non_canonical_raw
    assert canonical_raw.hex() == canonical["decoded_signature_hex"]
    assert non_canonical_raw.hex() == non_canonical["decoded_signature_hex"]

    # Differ in exactly the final character, and nowhere else.
    assert canonical_sig != non_canonical_sig
    assert canonical_sig[:-1] == non_canonical_sig[:-1]
    assert canonical_sig[-1] != non_canonical_sig[-1]

    # The two records are otherwise byte-identical: only `signature` differs.
    canonical_record_no_sig = {k: v for k, v in canonical["record"].items() if k != "signature"}
    non_canonical_record_no_sig = {
        k: v for k, v in non_canonical["record"].items() if k != "signature"
    }
    assert canonical_record_no_sig == non_canonical_record_no_sig


def test_the_two_respellings_differ_from_each_other_too() -> None:
    """Two distinct bad strings, not the same one committed twice under two names."""
    low_bit = _load(NON_CANONICAL_PATHS[0])["record"]["signature"]
    all_bits = _load(NON_CANONICAL_PATHS[1])["record"]["signature"]
    assert low_bit != all_bits
    assert low_bit[:-1] == all_bits[:-1]
    assert low_bit[-1] != all_bits[-1]


def test_declared_encoding_matches_recomputed_canonicality() -> None:
    """`encoding` is recomputed here, never trusted from the fixture."""
    canonical = _load(CANONICAL_PATH)
    assert canonical["encoding"] == "canonical"
    assert _is_canonical(canonical["record"]["signature"]) is True

    for path in NON_CANONICAL_PATHS:
        fixture = _load(path)
        assert fixture["encoding"] == "non_canonical"
        assert _is_canonical(fixture["record"]["signature"]) is False


def test_canonical_signature_is_schema_valid_and_verifies() -> None:
    fixture = _load(CANONICAL_PATH)
    assert fixture["expected"] == {"outcome": "verified", "failure": None}

    result = _verify(fixture)
    assert result.profile == fixture["record"]["eat_profile"]
    TrustRecord.model_validate(fixture["record"])  # the model agrees


@pytest.mark.parametrize("path", NON_CANONICAL_PATHS, ids=lambda p: p.stem)
def test_non_canonical_respelling_is_rejected_by_the_tightened_pattern(path: Path) -> None:
    fixture = _load(path)
    assert fixture["expected"] == {
        "outcome": "rejected",
        "failure": "signature_not_canonical",
    }

    with pytest.raises(SchemaValidationError):
        validate_json(fixture["record"])

    # Not `_verify()`: that helper calls `validate_json` directly, ahead of
    # `verify_record`'s own try/except, so the raw `SchemaValidationError` above
    # would reach here unwrapped instead of the `ValueError` `verify_record`
    # documents for every rejection.
    with pytest.raises(ValueError, match="does not conform.*signature"):
        verify_record(
            fixture["record"],
            fixture["trusted_key"],
            allow_embedded_key=False,
            max_age_seconds=60,
            max_future_skew_seconds=0,
            now=fixture["record"]["iat"],
        )

    with pytest.raises(ModelValidationError):
        TrustRecord.model_validate(fixture["record"])


@pytest.mark.parametrize("path", NON_CANONICAL_PATHS, ids=lambda p: p.stem)
def test_the_underlying_ed25519_signature_still_verifies_either_spelling(path: Path) -> None:
    """The respelling is refused for its spelling, not because the bytes are wrong.

    Independent of the TRACE schema, the model, and this library's own
    `_b64url_decode`: decoded with the standard library alone and checked with
    `cryptography` alone, a non-canonical respelling verifies exactly like the
    canonical spelling, because both decode to the same 64 bytes over the same
    RFC 8785 preimage. This isolates the tightened pattern, not a broken
    signature, as the reason `verify_record` now refuses it.
    """
    canonical = _load(CANONICAL_PATH)
    non_canonical = _load(path)
    trusted = canonical["trusted_key"]
    assert trusted == non_canonical["trusted_key"]
    assert trusted["kty"] == "OKP" and trusted["crv"] == "Ed25519"

    public_key = Ed25519PublicKey.from_public_bytes(_b64u(trusted["x"]))
    preimage = rfc8785.dumps(
        {k: v for k, v in canonical["record"].items() if k != "signature"}
    )

    public_key.verify(_b64u(canonical["record"]["signature"]), preimage)
    public_key.verify(_b64u(non_canonical["record"]["signature"]), preimage)

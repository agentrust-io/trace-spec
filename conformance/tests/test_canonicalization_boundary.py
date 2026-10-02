"""Records on which RFC 8785 and a careful ``json.dumps`` disagree.

Specification §3.2.2: "Implementations MUST use an RFC 8785-conformant library.
Using ``json.dumps(sort_keys=True)`` (Python) or equivalent ad-hoc sorting is
insufficient." Until these vectors arrived this suite verified signatures with
``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`` and every
test passed, because the two forms agree byte-for-byte on ASCII records and every
record here was ASCII. The suite that scores conformance was failing the one
requirement it could not see itself failing.

The vectors are copied from trace-spec's ``examples/canonicalization-boundary/``
rather than vendored, and nothing here compares them to the originals — a guard
that needs another repository checked out is a guard that gets skipped. Instead
each vector is held to the two properties that make it worth having:

  it is genuinely valid — the signature verifies over the record's RFC 8785 bytes;
  it is genuinely a boundary — the signature does *not* verify over the bytes each
  ad-hoc form in ``diverges_under`` produces.

A vector edited into something that is no longer a boundary fails the second
assertion rather than sitting in the directory looking like coverage.

``diverges_under`` names rungs of a ladder, each needing a sharper record to reach:

  ``sort_keys_default``      ``json.dumps(sort_keys=True)`` — spaces after separators
  ``sort_keys_compact``      adds ``separators=(",", ":")`` — escapes non-ASCII
  ``sort_keys_compact_utf8`` adds ``ensure_ascii=False`` — still sorts by code point,
                             where RFC 8785 sorts by UTF-16 code unit
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from trace_tests.modules import tr_sig
from trace_tests.runner import run as run_conformance

VECTOR_DIR = Path(__file__).parent / "vectors" / "canonicalization"
VECTORS = sorted(VECTOR_DIR.glob("*.json"))

# The ad-hoc serializers §3.2.2 rules out, as the vectors name them.
AD_HOC = {
    "sort_keys_default": lambda d: json.dumps(d, sort_keys=True).encode(),
    "sort_keys_compact": lambda d: json.dumps(
        d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(),
    "sort_keys_compact_utf8": lambda d: json.dumps(
        d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
}

# Old enough that the freshness bound never decides one of these tests.
MAX_AGE = 100 * 365 * 24 * 3600


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _b64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verifies_over(record: dict[str, Any], body: bytes) -> bool:
    key = Ed25519PublicKey.from_public_bytes(_b64u(record["cnf"]["jwk"]["x"]))
    try:
        key.verify(_b64u(record["signature"]), body)
    except InvalidSignature:
        return False
    return True


def _body(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "signature"}


def test_the_vector_set_is_present() -> None:
    """A directory that lost its contents passes every test parametrised on it."""
    assert [p.name for p in VECTORS] == [
        "01-non-ascii-values.json",
        "02-non-bmp-values.json",
        "03-utf16-key-order.json",
        "04-utf16-key-order-nested.json",
    ]


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_the_record_is_genuinely_valid(path: Path) -> None:
    """Half of what makes a boundary vector a boundary. Without this the vector
    could be rejected by everything, including a correct verifier, and the test
    below would still pass."""
    record = _load(path)["record"]
    assert _verifies_over(record, rfc8785.dumps(_body(record))), (
        f"{path.name} does not verify over its own RFC 8785 bytes; it is not a "
        "valid record and cannot demonstrate anything about a verifier"
    )


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_the_record_is_genuinely_a_boundary(path: Path) -> None:
    """The other half: each named ad-hoc form must actually fail on this record.

    A vector whose divergences have quietly stopped diverging is a vector that no
    longer separates a conformant verifier from a non-conformant one, and it would
    keep passing every other test in this file.
    """
    vector = _load(path)
    record = vector["record"]
    for name in vector["diverges_under"]:
        assert not _verifies_over(record, AD_HOC[name](_body(record))), (
            f"{path.name} still verifies under {name!r}, so it no longer "
            "distinguishes that serializer from RFC 8785"
        )


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_the_runner_accepts_it(path: Path) -> None:
    """The regression this file exists for: all four of these were reported as
    signature failures by the shipped runner."""
    vector = _load(path)
    findings = run_conformance(vector["record"], "trace", level=0, max_age_seconds=MAX_AGE)
    signature = next(f for f in findings["TR-SIG"] if f.code == "TR-SIG-005")
    assert signature.passed(), (
        f"{path.name} is a valid, correctly signed record and the runner rejected "
        f"it: {signature.message}"
    )


def test_the_module_canonicalizes_with_rfc_8785() -> None:
    """Aimed at the function rather than at its effect.

    The vectors above catch a wrong serializer through a failed signature, which is
    one step removed and reads as a key problem. This compares the bytes directly on
    an input chosen so that every ad-hoc form differs, so a reintroduced shortcut is
    reported as what it is.
    """
    probe = {"z\U0001f600": "supplementary-plane key", "z�": "replacement char",
             "value": "modèle-géant"}
    assert tr_sig._canonical_json(probe) == rfc8785.dumps(probe)
    for name, serializer in AD_HOC.items():
        assert tr_sig._canonical_json(probe) != serializer(probe), (
            f"the probe does not separate {name!r} from RFC 8785, so this test "
            "would pass against a verifier using it"
        )

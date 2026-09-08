"""Generate canonicalization boundary vectors (spec section 3.2.2).

The spec: "Implementations MUST use an RFC 8785-conformant library. Using
`json.dumps(sort_keys=True)` (Python) or equivalent ad-hoc sorting is insufficient."
ASCII-only values and schema-fixed keys can conceal escaping and key-order
differences. These portable records make the signature-byte contract observable.

These are the records on which they disagree. The four positive records are
schema-valid and correctly signed over RFC 8785 bytes. Two negative controls use
the same payloads but sign different, non-JCS byte forms: their Ed25519 signatures
are valid over those declared preimages, not valid TRACE signatures. Each carries
``diverges_under`` — the ad-hoc canonicalizations whose output differs from JCS.
For positive vectors these forms reject valid records; the negatives instead
expose acceptance of signatures over an alternate form. The tests recompute
this list rather than trusting it.

The ad-hoc forms make a ladder, each rung needing a sharper vector to expose:

- ``sort_keys_default`` — ``json.dumps(record, sort_keys=True)``. Inserts spaces after
  separators; any record at all diverges.
- ``sort_keys_compact`` — adds ``separators=(",", ":")``. Correct on ASCII; escapes
  non-ASCII as ``\\uXXXX`` where RFC 8785 emits literal UTF-8.
- ``sort_keys_compact_utf8`` — adds ``ensure_ascii=False``. Correct on every record in
  this repository except one: RFC 8785 sorts object keys by UTF-16 code units, Python
  sorts str by code point, and the two orders differ exactly when a key contains a
  supplementary-plane character.

There is no vector for RFC 8785's IEEE 754 number serialization. No v0.2 field is typed
``number``, every integer field is held to the range RFC 8785 Appendix B note 1 names,
and the members a JWK may carry without this schema naming them are held to the same
range, so a record that reaches the number divergence is schema-invalid and no positive
vector can carry it. ``tests/test_canonicalization_boundary.py`` pins all three.

Deterministic key, so the set regenerates byte-for-byte. Public test material.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path("examples/canonicalization-boundary")
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"

SEED = hashlib.sha256(b"trace-spec canonicalization-boundary fixture key").digest()
KEY = Ed25519PrivateKey.from_private_bytes(SEED)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_jwk() -> dict[str, str]:
    raw = KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


BASE_RECORD: dict[str, Any] = {
    "eat_profile": V0_2,
    # Fixed, so the fixture is reproducible. Verifiers running these vectors must
    # disable the freshness check or supply this instant as "now"; canonicalization
    # is the property under test, not staleness.
    "iat": 1785000000,
    "subject": "spiffe://factory.example/agent/payments/prod",
    "model": {
        "provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
    },
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "00" * 32,
    },
    "policy": {
        "bundle_hash": "sha256:" + "aa" * 32,
        "enforcement_mode": "enforce",
    },
    "data_class": "confidential",
    "build_provenance": {
        "slsa_level": 0,
        "digest": "sha256:" + "bb" * 32,
    },
    "appraisal": {
        "status": "affirming",
        "verifier": "https://verifier.example/v1",
    },
    "transparency": "https://rekor.example/api/v1/log/entries/0",
}


def signing_bytes(body: dict[str, Any], form: str) -> bytes:
    """Fixture generation only; no alternate serialization is accepted by TRACE."""
    if form == "rfc8785":
        return rfc8785.dumps(body)
    if form == "sort_keys_compact":
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if form == "sort_keys_compact_utf8":
        return json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    raise ValueError(f"unknown fixture signing form: {form}")


def signed(record: dict[str, Any], *, signing_form: str = "rfc8785") -> dict[str, Any]:
    body = dict(record)
    body["cnf"] = {"jwk": {**public_jwk(), **body.get("cnf", {}).get("jwk", {})}}
    body["signature"] = b64u(KEY.sign(signing_bytes(body, signing_form)))
    return body


def vector(
    name: str,
    description: str,
    record: dict[str, Any],
    diverges_under: list[str],
    *,
    signing_form: str = "rfc8785",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "description": description,
        "spec": "trace-v0.2 section 3.2.2 — implementations MUST use an "
        "RFC 8785-conformant library",
        "profile": "trace.canonicalization.boundary.v0",
        "trusted_key": public_jwk(),
        "record": signed(record, signing_form=signing_form),
        "expected": {"outcome": "verified"},
        "diverges_under": diverges_under,
    }
    if signing_form != "rfc8785":
        body = {key: value for key, value in result["record"].items() if key != "signature"}
        result["expected"] = {"outcome": "rejected", "failure": "signature_invalid"}
        result["signing_form"] = signing_form
        # Exact UTF-8 preimages, encoded as JSON strings for portable inspection.
        # These are fixture metadata, not fields added to the Trust Record.
        result["signed_input_utf8"] = signing_bytes(body, signing_form).decode("utf-8")
        result["canonical_input_utf8"] = rfc8785.dumps(body).decode("utf-8")
    return result


def main() -> None:
    out: list[tuple[str, dict[str, Any]]] = []

    r = copy.deepcopy(BASE_RECORD)
    r["model"]["version"] = "modèle-géant-4.6"
    r["data_class"] = "机密"
    out.append(("01-non-ascii-values.json", vector(
        "non-ascii-values",
        "String values outside ASCII, all in the Basic Multilingual Plane. RFC 8785 "
        "emits them as literal UTF-8; a serializer that escapes to \\uXXXX signs "
        "different bytes and rejects this valid record.",
        r,
        ["sort_keys_default", "sort_keys_compact"],
    )))

    r = copy.deepcopy(BASE_RECORD)
    r["model"]["version"] = "4.6-🤖"
    r["data_class"] = "confidential-🔒"
    out.append(("02-non-bmp-values.json", vector(
        "non-bmp-values",
        "String values above U+FFFF, encoded as four UTF-8 bytes each. Under "
        "ASCII-escaping they become surrogate pairs; either way the bytes differ from "
        "RFC 8785's literal UTF-8.",
        r,
        ["sort_keys_default", "sort_keys_compact"],
    )))

    r = copy.deepcopy(BASE_RECORD)
    # cnf.jwk is the one object in the schema open to additional members (RFC 7517
    # permits them), so it is where a key-ordering divergence can live in a
    # schema-valid record. U+1F600 is D83D DE00 in UTF-16, so it sorts before U+FFFD
    # by code units (RFC 8785) and after it by code points (Python str, and any
    # sorted() on decoded strings).
    r["cnf"] = {"jwk": {
        "zk\U0001f600": "sorts-first-under-rfc-8785",
        "zk�": "sorts-second-under-rfc-8785",
    }}
    out.append(("03-utf16-key-order.json", vector(
        "utf16-key-order",
        "Two object keys whose order under RFC 8785's UTF-16 code-unit sort is the "
        "reverse of their code-point order. This is the record that distinguishes a "
        "true RFC 8785 serializer from json.dumps with every option set carefully: "
        "compact separators and ensure_ascii=False survive vectors 01 and 02, and "
        "fail here.",
        r,
        ["sort_keys_default", "sort_keys_compact", "sort_keys_compact_utf8"],
    )))

    r = copy.deepcopy(BASE_RECORD)
    # The same UTF-16 divergence as vector 03, one level deeper. Every key at the top
    # of `jwk` is ASCII here, so a canonicalizer that sorts by code units at the outer
    # levels and recurses with the default sort agrees with RFC 8785 on vector 03 and
    # separates only here. Measured: sorting by code units to depth 2 passes 03 and
    # fails this one, which is the second, distinct defect #124 asks a boundary to have.
    #
    # The margin this adds is positional rather than mechanistic. Key ordering is the
    # only RFC 8785 divergence this schema can reach at all: no field is typed `number`,
    # and integers are held to the safe-integer range whether the schema names the field
    # or not, so the number serialization rule has nothing schema-valid to act on. The
    # `cnf.jwk` members these two vectors add are subject to that same constraint, which
    # is why they are strings. All of it is pinned in
    # `tests/test_canonicalization_boundary.py`.
    r["cnf"] = {"jwk": {"zmeta": {
        "zk\U0001f600": "sorts-first-under-rfc-8785",
        "zk\ufffd": "sorts-second-under-rfc-8785",
    }}}
    out.append(("04-utf16-key-order-nested.json", vector(
        "utf16-key-order-nested",
        "The divergence of vector 03 moved inside a nested object, so that a "
        "canonicalizer sorting by UTF-16 code units at the outer levels and by code "
        "points below them passes 03 and fails here. Without it the closest "
        "non-conformant form is caught by one vector, and the boundary disappears "
        "with that vector.",
        r,
        ["sort_keys_default", "sort_keys_compact", "sort_keys_compact_utf8"],
    )))

    # Negative controls keep the unsigned payloads of 01 and 03 unchanged. Only
    # the signature preimage changes; schema, trust key and timestamp cannot be
    # the reason a conformant verifier refuses them. Neither expected result is
    # inferred from running the verifier under test.
    r = {key: copy.deepcopy(value) for key, value in out[0][1]["record"].items()
         if key != "signature"}
    out.append(("05-ascii-escaped-signature.json", vector(
        "ascii-escaped-signature",
        "The payload of vector 01 signed over compact ASCII-escaped JSON rather "
        "than RFC 8785 bytes. Its signature verifies over that published alternate "
        "preimage but is not a valid TRACE signature. Canonical re-signing of the "
        "same payload passes.",
        r,
        ["sort_keys_default", "sort_keys_compact"],
        signing_form="sort_keys_compact",
    )))

    r = {key: copy.deepcopy(value) for key, value in out[2][1]["record"].items()
         if key != "signature"}
    out.append(("06-codepoint-order-signature.json", vector(
        "codepoint-order-signature",
        "The payload of vector 03 signed over compact literal-UTF8 JSON with "
        "code-point key ordering. Only key order differs from RFC 8785; ASCII "
        "escaping is not the defect. The published alternate signature is "
        "cryptographically valid, but TRACE verification rejects it.",
        r,
        ["sort_keys_default", "sort_keys_compact", "sort_keys_compact_utf8"],
        signing_form="sort_keys_compact_utf8",
    )))

    for name, doc in out:
        (OUT / name).write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print("wrote", name)


if __name__ == "__main__":
    main()

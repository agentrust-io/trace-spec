"""Generate canonicalization boundary vectors (spec section 3.2.2).

The spec: "Implementations MUST use an RFC 8785-conformant library. Using
`json.dumps(sort_keys=True)` (Python) or equivalent ad-hoc sorting is insufficient."
No published test material exercised that sentence: every existing record is
ASCII-only with schema-fixed keys, and on such records every ad-hoc serializer agrees
with RFC 8785 byte-for-byte, so an implementation using one passes everything.

These are the records on which they disagree. Each is schema-valid and correctly
signed over its RFC 8785 bytes, and each carries ``diverges_under`` — the ad-hoc
canonicalizations whose output differs, so that a verifier built on them computes
different bytes and rejects a valid record. ``tests/test_canonicalization_boundary.py``
recomputes that list rather than trusting it.

The ad-hoc forms make a ladder, each rung needing a sharper vector to expose:

- ``sort_keys_default`` — ``json.dumps(record, sort_keys=True)``. Inserts spaces after
  separators; any record at all diverges.
- ``sort_keys_compact`` — adds ``separators=(",", ":")``. Correct on ASCII; escapes
  non-ASCII as ``\\uXXXX`` where RFC 8785 emits literal UTF-8.
- ``sort_keys_compact_utf8`` — adds ``ensure_ascii=False``. Correct on every record in
  this repository except one: RFC 8785 sorts object keys by UTF-16 code units, Python
  sorts str by code point, and the two orders differ exactly when a key contains a
  supplementary-plane character.

There is no vector for RFC 8785's IEEE 754 number serialization: the v0.2 schema types
no field as ``number``, so the divergence is unreachable in a schema-valid record. The
test suite pins that fact so a future numeric field demands a vector here.

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


def signed(record: dict[str, Any]) -> dict[str, Any]:
    body = dict(record)
    body["cnf"] = {"jwk": {**public_jwk(), **body.get("cnf", {}).get("jwk", {})}}
    body["signature"] = b64u(KEY.sign(rfc8785.dumps(body)))
    return body


def vector(
    name: str,
    description: str,
    record: dict[str, Any],
    diverges_under: list[str],
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "spec": "trace-v0.2 section 3.2.2 — implementations MUST use an "
        "RFC 8785-conformant library",
        "profile": "trace.canonicalization.boundary.v0",
        "trusted_key": public_jwk(),
        "record": signed(record),
        "expected": {"outcome": "verified"},
        "diverges_under": diverges_under,
    }


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

    for name, doc in out:
        (OUT / name).write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print("wrote", name)


if __name__ == "__main__":
    main()

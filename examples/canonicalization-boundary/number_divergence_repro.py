"""Reproduce the section 3.2.2 number divergence with nothing but this repository.

    python examples/canonicalization-boundary/number_divergence_repro.py

The measurements behind the bound were taken against V8, npm's `canonicalize`
and `ajv`. None of that ships here, so none of it is re-runnable by a reviewer,
which makes it the same kind of claim this directory exists to argue against.
This script needs only the standard library and `agentrust_trace`, and it
reproduces every step that decides the question:

  1. RFC 8785 section 3.2.2.3 serializes numbers per ECMA-262 section 7.1.12.1,
     which converts through an IEEE 754 double. `_ecma262_number` below is that
     conversion, and `_jcs` is a canonicalizer built on it. Nothing here is a
     model of the algorithm: `float()` is the same rounding V8 performs.
  2. Two records differing only in `tool_transcript.call_count` reach one
     canonical form, so one Ed25519 signature verifies both. `call_count` rather
     than `iat`, because a verifier enforcing freshness rejects an `iat` at 2**53
     as a record dated in the year 285 million and the collision never decides
     anything.
  3. The bound must be 2**53 - 1 and not 2**53. A validator whose only number
     type is the double sees what the value parsed to, so at 2**53 it reads
     9007199254740993 as 9007199254740992 and admits it.
  4. This repository's schema now rejects both records.

Exit code 0 means every step reproduced.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from agentrust_trace.validate import validate_json  # noqa: E402

SAFE_INTEGER = 2**53 - 1
PAIR = (2**53, 2**53 + 1)


def _ecma262_number(value: int | float) -> str:
    """ECMA-262 section 7.1.12.1 for the values a Trust Record can hold.

    Every JSON number goes through a double first. That is the whole mechanism.
    """
    as_double = float(value)
    if as_double.is_integer() and abs(as_double) < 1e21:
        return str(int(as_double))
    return repr(as_double)


def _jcs(value: Any) -> bytes:
    """RFC 8785, enough of it for these records: UTF-16 key order, no whitespace."""
    if value is None:
        return b"null"
    if isinstance(value, bool):
        return b"true" if value else b"false"
    if isinstance(value, (int, float)):
        return _ecma262_number(value).encode()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_jcs(v) for v in value) + b"]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return b"{" + b",".join(_jcs(k) + b":" + _jcs(v) for k, v in members) + b"}"
    raise TypeError(f"not JSON: {value!r}")


def _record(call_count: int, jwk: dict[str, str]) -> dict[str, Any]:
    fixture = json.loads(
        (Path(__file__).parent / "01-non-ascii-values.json").read_text(encoding="utf-8")
    )
    record = fixture["record"]
    record.pop("signature", None)
    record["cnf"] = {"jwk": jwk}
    record["tool_transcript"] = {"hash": "sha256:" + "c" * 64, "call_count": call_count}
    return record


def main() -> int:
    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    print("0. The canonicalizer below is JCS, checked against the pinned library")
    import rfc8785

    compared = 0
    for path in sorted((REPO_ROOT / "examples").rglob("*.json")):
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        nested = loaded.get("record") if isinstance(loaded, dict) else None
        for obj in [o for o in (loaded, nested) if isinstance(o, dict)]:
            body = {k: v for k, v in obj.items() if k != "signature"}
            try:
                reference = rfc8785.dumps(body)
            except Exception:  # noqa: BLE001 - out of range, which is step 1's subject
                continue
            compared += 1
            check(
                _jcs(body) == reference,
                f"the canonicalizer here disagrees with rfc8785 on {path.name}",
            )
    print(f"     {compared} records, including the non-ASCII and UTF-16 key-order vectors")
    print(f"   byte-for-byte agreement with rfc8785: {not failures}\n")

    print("1. ECMA-262 number serialization, which RFC 8785 3.2.2.3 defers to")
    rendered = {n: _ecma262_number(n) for n in PAIR}
    for n, text in rendered.items():
        print(f"     {n} -> {text}")
    check(len(set(rendered.values())) == 1, "the pair did not collide")
    print(f"   two distinct integers, one serialization: {len(set(rendered.values())) == 1}\n")

    print("2. One canonical form, therefore one signature")
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(key.public_key().public_bytes_raw())
        .rstrip(b"=")
        .decode(),
    }
    a, b = (_record(n, jwk) for n in PAIR)
    canonical_a, canonical_b = _jcs(a), _jcs(b)
    signature_a = base64.urlsafe_b64encode(key.sign(canonical_a)).rstrip(b"=").decode()
    signature_b = base64.urlsafe_b64encode(key.sign(canonical_b)).rstrip(b"=").decode()
    print(f"     call_count {PAIR[0]} -> {len(canonical_a)} bytes")
    print(f"     call_count {PAIR[1]} -> {len(canonical_b)} bytes")
    print(f"     records differ:     {a != b}")
    print(f"     canonical form same: {canonical_a == canonical_b}")
    print(f"     signature same:      {signature_a == signature_b}")
    check(a != b, "the two records are not distinct")
    check(canonical_a == canonical_b, "the canonical forms differ")
    check(signature_a == signature_b, "the signatures differ")
    print("   the signature issued for one record verifies the other\n")

    print("3. Why the bound is 2**53 - 1 and not 2**53")
    for bound in (SAFE_INTEGER, 2**53):
        admitted = [n for n in PAIR if float(n) <= bound]
        print(f"     maximum {bound}: a double-only validator admits {admitted or 'neither'}")
    check(all(float(n) > SAFE_INTEGER for n in PAIR), "the chosen bound admits the pair")
    check(float(PAIR[1]) <= 2**53, "2**53 would have been enforceable after all")
    print("   only the lower bound is enforceable where numbers are doubles\n")

    print("4. This repository's schema, now")
    for n in (SAFE_INTEGER, *PAIR):
        record = _record(n, jwk)
        record["signature"] = signature_a
        try:
            validate_json(record)
            verdict = "accepted"
        except Exception as exc:  # noqa: BLE001 - any rejection is the point
            verdict = f"rejected ({type(exc).__name__})"
        print(f"     call_count {n} -> {verdict}")
        check(
            (verdict == "accepted") == (n <= SAFE_INTEGER),
            f"schema verdict for {n} is wrong",
        )

    print()
    if failures:
        for failure in failures:
            print(f"FAILED: {failure}")
        return 1
    print("every step reproduced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

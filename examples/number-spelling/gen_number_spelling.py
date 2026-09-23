"""Generate the number-spelling vectors (agentrust-io/trace-spec#247).

Each fixture is one signed Trust Record with one integer-typed member written in a
particular spelling, and the outcome a verifier that decides integers by value must
produce. Nothing in a fixture names a language or an API.

A JSON serializer chooses the spelling of every number it writes, so the fixtures
cannot be written by `json.dumps` alone: it would write `1.785e9` back as
`1785000000.0`. The member under test is written as a placeholder string and the
placeholder is replaced, in the serialized text, by the spelling the vector is about.
Every other byte comes from `json.dumps`.

The key is the verifier-compatibility fixture key, derived from the same published
seed, and the base record is that set's record, so this set introduces no new signing
key and vector 01 carries the record and signature of
`examples/verifier-compatibility/01-known-version-verified.json`, unchanged.
Deterministic, so the set regenerates byte for byte. Public test material.
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

OUT = Path(__file__).resolve().parent
PROFILE = "trace.number_spelling.proposal.v0"
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
SAFE_INTEGER = 2**53 - 1

# The verifier-compatibility seed, unchanged: the same key, not a new one.
SEED = hashlib.sha256(b"trace-spec#116 verifier-compatibility fixture key").digest()
KEY = Ed25519PrivateKey.from_private_bytes(SEED)

PLACEHOLDER = "@number-under-test@"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_jwk() -> dict[str, str]:
    raw = KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


# `examples/verifier-compatibility/gen_vectors.py`, BASE_RECORD, member for member.
BASE_RECORD: dict[str, Any] = {
    "eat_profile": V0_2,
    "iat": 1785000000,
    "subject": "spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "example-provider", "model_id": "example-model-1"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    "transparency": "https://rekor.example/api/v1/log/entries/0",
    "cnf": {"jwk": public_jwk()},
}


def _set(record: dict[str, Any], member: str, value: Any) -> None:
    *parents, last = member.split(".")
    target = record
    for name in parents:
        target = target[name]
    target[last] = value


def signed_record(member: str, spelling: str) -> dict[str, Any]:
    """The base record with *member* holding the value *spelling* parses to, signed.

    The signature is over the RFC 8785 form of the parsed record, which is what makes
    the spelling invisible to it. One value has no form in the `rfc8785` package: an
    integer outside the safe-integer range, which that package refuses rather than
    writes. RFC 8785 section 3.2.2.3 converts every number through an IEEE 754 double,
    so the pre-image an implementation of it writes for that integer is the one the
    package writes for the double; the signature is made over those bytes. The record
    keeps the parsed value, so the placeholder is still there to be replaced.
    """
    value = json.loads(spelling)
    record = copy.deepcopy(BASE_RECORD)
    _set(record, member, value)
    preimage = copy.deepcopy(record)
    if isinstance(value, int) and abs(value) > SAFE_INTEGER:
        _set(preimage, member, float(value))
    signature = b64u(KEY.sign(rfc8785.dumps(preimage)))
    _set(record, member, PLACEHOLDER)
    return {**record, "signature": signature}


VECTORS: list[dict[str, Any]] = [
    {
        "file": "01-integer-spelling-verified.json",
        "name": "integer-spelling-verified",
        "description": (
            "The record and signature published as examples/verifier-compatibility/"
            "01-known-version-verified.json, with iat in the plain integer spelling. "
            "The baseline the next two vectors re-spell."
        ),
        "member": "iat",
        "spelling": "1785000000",
        "expected": {"outcome": "verified", "failure": None},
    },
    {
        "file": "02-fraction-spelling-verified.json",
        "name": "fraction-spelling-verified",
        "description": (
            "The same record with iat written 1785000000.0. The value is the integer "
            "1785000000: JSON has one number type, and RFC 8785 writes this value as "
            "1785000000, so the pre-image and the signature are 01's, byte for byte. "
            "Python's json.loads returns a float here and an int for 01; JSON.parse "
            "returns one number for both, so a JavaScript verifier cannot tell this "
            "record from 01 at all."
        ),
        "member": "iat",
        "spelling": "1785000000.0",
        "same_signature_as": "01-integer-spelling-verified.json",
        "expected": {"outcome": "verified", "failure": None},
    },
    {
        "file": "03-exponent-spelling-verified.json",
        "name": "exponent-spelling-verified",
        "description": (
            "The same record with iat written 1.785e9, the exponent spelling of the "
            "same value, with 01's pre-image and 01's signature. Two accepting "
            "re-spellings rather than one: an implementation that refuses an "
            "exponent, or that accepts 02 by stripping a trailing .0 from the text, "
            "verifies 02 and rejects this one."
        ),
        "member": "iat",
        "spelling": "1.785e9",
        "same_signature_as": "01-integer-spelling-verified.json",
        "expected": {"outcome": "verified", "failure": None},
    },
    {
        "file": "04-fractional-value-rejected.json",
        "name": "fractional-value-rejected",
        "description": (
            "iat written 1785000000.5, a number that is not a whole number and so is "
            "not an integer. The signature is valid over this record's own RFC 8785 "
            "form, so the only reason to reject it is the rule under test."
        ),
        "member": "iat",
        "spelling": "1785000000.5",
        "expected": {"outcome": "rejected", "failure": "not_an_integer_value"},
    },
    {
        "file": "05-fractional-value-exponent-spelling-rejected.json",
        "name": "fractional-value-exponent-spelling-rejected",
        "description": (
            "04's value written 17850000005e-1, with no decimal point, and so 04's "
            "pre-image and 04's signature. An implementation that looks for a decimal "
            "point to find a fraction accepts this spelling of a fractional value; "
            "the rule is on the value."
        ),
        "member": "iat",
        "spelling": "17850000005e-1",
        "same_signature_as": "04-fractional-value-rejected.json",
        "expected": {"outcome": "rejected", "failure": "not_an_integer_value"},
    },
    {
        "file": "06-above-range-integer-spelling-rejected.json",
        "name": "above-range-integer-spelling-rejected",
        "description": (
            "appraisal.timestamp written 9007199254740992, one past the safe-integer "
            "range. No freshness rule reads this member, so the range is the only "
            "rule that can reject the record. The signature is valid over the "
            "pre-image RFC 8785 writes for this record, which converts the number "
            "through a double; the rfc8785 Python package refuses to write this "
            "integer at all, so the generator computes the same bytes from the double."
        ),
        "member": "appraisal.timestamp",
        "spelling": "9007199254740992",
        "expected": {"outcome": "rejected", "failure": "outside_safe_integer_range"},
    },
    {
        "file": "07-above-range-exponent-spelling-rejected.json",
        "name": "above-range-exponent-spelling-rejected",
        "description": (
            "appraisal.timestamp written 1.0e+21, the example on #247: a float in "
            "Python, which RFC 8785 writes as 1e+21, and a whole number past the "
            "safe-integer range in JavaScript. Whole and out of range, so rejected by "
            "the range whatever its spelling. Separate from 06 because the rfc8785 "
            "Python package refuses an out-of-range int and writes this float without "
            "complaint: an implementation that leaves the range to its canonicalizer "
            "rejects 06 and verifies this one. The signature is valid over this "
            "record's RFC 8785 form."
        ),
        "member": "appraisal.timestamp",
        "spelling": "1.0e+21",
        "expected": {"outcome": "rejected", "failure": "outside_safe_integer_range"},
    },
]


def fixture(vector: dict[str, Any]) -> str:
    doc: dict[str, Any] = {
        "name": vector["name"],
        "description": vector["description"],
        "spec": "trace-v0.2 section 3.2.2, What counts as an integer",
        "profile": PROFILE,
        "proposal": {
            "issue": "agentrust-io/trace-spec#247",
            "status": "under review, not accepted normative text",
        },
        "member": vector["member"],
        "spelling": vector["spelling"],
    }
    if "same_signature_as" in vector:
        doc["same_signature_as"] = vector["same_signature_as"]
    doc.update({
        "verifier": {
            "verification_time": 1785000100,
            "max_age_seconds": 86400,
            "max_future_skew_seconds": 300,
        },
        "trusted_key": public_jwk(),
        "record": signed_record(vector["member"], vector["spelling"]),
        "expected": vector["expected"],
    })
    text = json.dumps(doc, indent=2) + "\n"
    quoted = json.dumps(PLACEHOLDER)
    if text.count(quoted) != 1:
        raise RuntimeError(f"{vector['file']}: the placeholder is not written exactly once")
    return text.replace(quoted, vector["spelling"])


def main() -> None:
    for vector in VECTORS:
        path = OUT / vector["file"]
        path.write_text(fixture(vector), encoding="utf-8")
        print("wrote", path.name)


if __name__ == "__main__":
    main()

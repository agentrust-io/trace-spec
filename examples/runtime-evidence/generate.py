#!/usr/bin/env python3
"""Corpus generator and reference rule implementation for the runtime-evidence profile.

Informative. Binds nothing until `docs/rfcs/runtime-evidence-profile.md` is adopted.

Every vector here is built around a GENUINE Intel TDX v4 quote captured from a GCP C3
confidential VM on 2026-07-21, committed at
`agentrust-io/agent-manifest:python/tests/fixtures/hardware/gcp-tdx-2026-07-21/`.
No quote in this corpus is minted. A synthetic quote is built to the parser's own idea
of the layout, so a corpus made of them measures a parser against itself.

Two real captures matter more than one. They come from a single TD, so they share an
MRTD, and they carry different REPORT_DATA bindings. That is what makes the
substitution vector meaningful: both quotes verify on their own, and a rule set that
accepts a valid quote without binding it to the record accepts the swap.

Run:  python generate.py [--out DIR]
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import sys
from pathlib import Path

import jsonschema

# The verifier being demonstrated is agent-manifest's, unmodified and reached by
# import. The premise of the profile is that TRACE does not implement attestation and
# should not start; it carries evidence to a verifier that already exists.
_DEFAULT_AM = Path(__file__).resolve().parents[3] / "agent-manifest" / "python" / "src"
sys.path.insert(0, os.environ.get("AGENT_MANIFEST_SRC", str(_DEFAULT_AM)))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from agent_manifest._tdx_verify import (  # noqa: E402
    TdxVerificationError,
    parse_tdx_quote,
    verify_tdx_quote,
)
from agentrust_trace.sign import (  # noqa: E402
    _canonical_bytes,
    _pubkey_from_jwk,
    sign_record,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

_DEFAULT_CAPTURE = (
    Path(__file__).resolve().parents[3]
    / "agent-manifest"
    / "python"
    / "tests"
    / "fixtures"
    / "hardware"
    / "gcp-tdx-2026-07-21"
)
HARDWARE = Path(os.environ.get("TDX_CAPTURE", str(_DEFAULT_CAPTURE)))

PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"

# The draft schema, because the shipped v0.2 one refuses `runtime.evidence` outright:
# `runtime` is additionalProperties:false. That refusal is the gap the profile is
# about, so a corpus cannot be run against the schema it proposes to change.
DRAFT_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "schema" / "trace-claim-v0.3-draft.json").read_text(
        encoding="utf-8"
    )
)


def check_envelope(record: dict) -> None:
    """Schema-validate against the draft, then check the record signature.

    `verify_record()` does both at once against the v0.2 schema, so it cannot be used
    here. This reuses the SDK's own canonicalization and key handling rather than
    restating either: a second JCS implementation in a proposal about evidence
    integrity would be its own argument against the proposal.
    """
    jsonschema.validate(record, DRAFT_SCHEMA)
    signature = record.get("signature")
    if not isinstance(signature, str):
        raise ValueError("record carries no signature")
    jwk = (record.get("cnf") or {}).get("jwk")
    if not jwk:
        raise ValueError("record carries no cnf.jwk")
    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    _pubkey_from_jwk(jwk).verify(unb64u(signature), body)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------- rules


class Reject(Exception):
    """The record is not evidence. Distinct from grading it lower."""


def appraise(record: dict) -> str:
    """Return the assurance grade this record earns, or raise Reject.

    Grades, weakest first:

      unattested         nothing to check; every runtime claim is the issuer's word
      platform-attested  genuine silicon, and this record's signer is not bound to it
      attested           genuine silicon, and REPORT_DATA commits to this record's cnf key

    The middle grade is the one doing the work. A record can carry a real, fully
    verifying quote and still not connect that quote to whoever signed the record.
    Folding it up into `attested` is the rounding-up this profile exists to stop.
    Folding it down into `unattested` discards a fact the verifier did establish.
    """
    runtime = record.get("runtime") or {}
    evidence = runtime.get("evidence")

    # Ordered first, deliberately. The evidence is a member of the record, so the
    # record signature is what stops a valid quote being carried under a record
    # somebody else signed. Verifying the quote before the envelope would check
    # hardware this record never committed to.
    try:
        check_envelope(record)
    except Exception as e:
        raise Reject(f"record envelope failed: {type(e).__name__}") from e

    if evidence is None:
        # Not a rejection. A record with no evidence is a record with no evidence.
        return "unattested"

    fmt = evidence.get("format")
    if fmt != "tdx-quote-v4":
        raise Reject(f"unsupported evidence format {fmt!r}")

    if "quote" not in evidence:
        # By-reference evidence. TRACE claims offline verifiability, and a verifier
        # that has not fetched the bytes has verified nothing, so this grades as if
        # the block were absent rather than crediting the pointer.
        return "unattested"

    quote = unb64u(evidence["quote"])

    try:
        ok = verify_tdx_quote(quote)
    except TdxVerificationError as e:
        raise Reject(f"evidence malformed: {e}") from e
    if ok is not True:
        raise Reject("evidence signature or PCK chain did not verify")

    parsed = parse_tdx_quote(quote)

    if runtime.get("platform") != "intel-tdx":
        raise Reject(f"platform {runtime.get('platform')!r} is not what this evidence roots")

    # The binding rule. A valid quote proves a TD ran. It says nothing about which
    # measurement this record is entitled to claim until the two are compared.
    claimed = runtime.get("measurement", "")
    actual = "sha384:" + parsed.mrtd.hex()
    if claimed != actual:
        raise Reject(f"runtime.measurement {claimed} is not the MRTD in the evidence ({actual})")

    # The key-binding rule, which is the whole distance between the top grade and the
    # middle one. docs/trust-levels.md already requires a Level 1 signing key to be
    # generated inside the TEE; nothing in the record ever made that checkable.
    jwk = (record.get("cnf") or {}).get("jwk") or {}
    if jwk.get("kty") == "OKP" and "x" in jwk:
        if parsed.report_data[:32] == hashlib.sha256(unb64u(jwk["x"])).digest():
            return "attested"
    return "platform-attested"


def grade_model_claim(record: dict, envelope_grade: str) -> str:
    """A TEE-signed record does not make every claim inside it attested.

    `model.weights_digest` is attested only where the verifier can RECOMPUTE the
    binding from the evidence. Otherwise the environment is attested and the model
    claim is the issuer's word carried inside a hardware-signed envelope, which is the
    shape most likely to be read as stronger than it is.

    Note what this deliberately does not do: it never reads `evidence.binds`. That
    member is a producer's statement of intent, and grading a claim by consulting it
    would let a producer raise its own model claim by writing a string, which is the
    assurance laundering this profile exists to refuse. An advisory field that changes
    a grade is not advisory. The first draft of this function did read it, and it took
    a vector that sets `binds` without earning it to make that visible.
    """
    model = record.get("model") or {}
    digest = model.get("weights_digest")
    if digest is None:
        return "model claim: absent"
    if envelope_grade == "unattested":
        return "model claim: self-reported"

    quote = ((record.get("runtime") or {}).get("evidence") or {}).get("quote")
    if quote is None:
        return "model claim: self-reported"

    report_data = parse_tdx_quote(unb64u(quote)).report_data[:32]
    # A producer may commit to the digest string as written, or to the raw digest
    # bytes it names. Both are recomputable; anything else is not this rule's case.
    algo, _, hexdigest = digest.partition(":")
    candidates = [hashlib.sha256(digest.encode()).digest()]
    if algo == "sha256" and len(hexdigest) == 64:
        try:
            candidates.append(bytes.fromhex(hexdigest))
        except ValueError:
            pass
    if report_data in candidates:
        return "model claim: attested"
    return "model claim: self-reported"


# ---------------------------------------------------------------------- generation


def _unsigned(record: dict) -> dict:
    out = {k: v for k, v in record.items() if k != "signature"}
    out["cnf"] = {}
    return out


def base_record(quote: bytes, key: Ed25519PrivateKey) -> dict:
    parsed = parse_tdx_quote(quote)
    record = {
        "eat_profile": PROFILE,
        "iat": 1753056000,
        "subject": "spiffe://trust.example.org/agent/evidence-demo/prod",
        "model": {
            "provider": "meta",
            "model_id": "llama-3.3-70b-instruct",
            "version": "3.3",
            "weights_digest": (
                "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            ),
        },
        "runtime": {
            "platform": "intel-tdx",
            "measurement": "sha384:" + parsed.mrtd.hex(),
            "firmware_version": "gcp-c3",
            "evidence": {
                "format": "tdx-quote-v4",
                "quote": b64u(quote),
                "collateral": "embedded",
            },
        },
        "policy": {
            "bundle_hash": (
                "sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"
            ),
            "enforcement_mode": "enforce",
            "version": "1.0.0",
        },
        "data_class": "internal",
        "build_provenance": {
            "slsa_level": 2,
            "builder": (
                "https://github.com/slsa-framework/slsa-github-generator"
                "/.github/workflows/generator_container_slsa3.yml"
            ),
            "digest": ("sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"),
        },
        "appraisal": {
            "status": "affirming",
            "verifier": "https://github.com/agentrust-io/agent-manifest",
        },
        "cnf": {},
    }
    return sign_record(record, key)


# Published test key, fixed so the corpus is reproducible and the committed vectors
# are byte-stable. It signs nothing outside this directory and protects nothing; the
# alternative is a fresh key per run, which makes every vector churn and makes
# "regenerate and diff" useless as a review.
PUBLISHED_TEST_KEY = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)


def build_corpus() -> list[tuple[str, str, str | None, dict]]:
    """Return (name, expected grade, expected model claim or None, record)."""
    key = Ed25519PrivateKey.from_private_bytes(PUBLISHED_TEST_KEY)
    quote_a = (HARDWARE / "tdx_quote.bin").read_bytes()
    quote_b = (HARDWARE / "tdx_quote_manifest.bin").read_bytes()

    accept = base_record(quote_a, key)
    vectors: list[tuple[str, str, str | None, dict]] = [
        (
            "accept-real-quote-platform-attested",
            "platform-attested",
            "model claim: self-reported",
            accept,
        )
    ]

    # No citation at all. Nothing to check, so nothing is claimed.
    absent = copy.deepcopy(accept)
    del absent["runtime"]["evidence"]
    vectors.append(
        (
            "downgrade-evidence-absent",
            "unattested",
            "model claim: self-reported",
            sign_record(_unsigned(absent), key),
        )
    )

    # A pointer to evidence is not evidence held.
    byref = copy.deepcopy(accept)
    byref["runtime"]["evidence"] = {
        "format": "tdx-quote-v4",
        "quote_digest": "sha256:" + hashlib.sha256(quote_a).hexdigest(),
        "quote_uri": "https://example.org/quotes/a",
    }
    vectors.append(
        (
            "downgrade-evidence-by-reference",
            "unattested",
            "model claim: self-reported",
            sign_record(_unsigned(byref), key),
        )
    )

    # Forged: one byte flipped inside the region the attestation key signs.
    forged_quote = bytearray(quote_a)
    forged_quote[48 + 136] ^= 0xFF
    forged = copy.deepcopy(accept)
    forged["runtime"]["evidence"]["quote"] = b64u(bytes(forged_quote))
    vectors.append(("reject-forged-quote", "reject", None, sign_record(_unsigned(forged), key)))

    # Genuine quote, measurement taken from somewhere else.
    mismatch = copy.deepcopy(accept)
    mismatch["runtime"]["measurement"] = "sha384:" + "00" * 48
    vectors.append(
        ("reject-measurement-mismatch", "reject", None, sign_record(_unsigned(mismatch), key))
    )

    # The vector this corpus exists for, and it does not do what it was written to do.
    #
    # Quote B is real and verifies by itself. Substituting it for quote A was expected
    # to be refused by the measurement rule. It is not: both captures come from one TD,
    # so they carry the same MRTD, and measurement-binding cannot separate two quotes
    # that agree on the measurement. The swap passes.
    #
    # This is recorded as a LIMIT rather than corrected, because it is a property of
    # the rule and not of this script. Its consequence is stated in the profile: the
    # middle grade means "genuine silicon reporting this measurement", never "this
    # execution". Only a binding in the guest-controlled field separates two quotes
    # from one TD, which is what the top grade requires and what makes it worth having.
    swapped = copy.deepcopy(accept)
    swapped["runtime"]["evidence"]["quote"] = b64u(quote_b)
    vectors.append(
        (
            "limit-substituted-quote-from-the-same-td",
            "platform-attested",
            "model claim: self-reported",
            sign_record(_unsigned(swapped), key),
        )
    )

    # The same swap, made after signing. The record signature is what refuses it.
    tampered = copy.deepcopy(accept)
    tampered["runtime"]["evidence"]["quote"] = b64u(quote_b)
    vectors.append(("reject-evidence-swapped-after-signing", "reject", None, tampered))

    # A hardware platform value the evidence does not root.
    wrongplat = copy.deepcopy(accept)
    wrongplat["runtime"]["platform"] = "amd-sev-snp"
    vectors.append(
        ("reject-platform-not-the-evidence", "reject", None, sign_record(_unsigned(wrongplat), key))
    )

    # `binds` is advisory, and a vector proves it cannot raise anything. This record
    # declares that the guest committed to the weights digest. It did not: REPORT_DATA
    # holds a manifest digest, as it does in every capture we own. The envelope grade
    # is unaffected and the model claim stays self-reported, because the rule
    # recomputes the binding instead of believing the declaration.
    claimed_binding = copy.deepcopy(accept)
    claimed_binding["runtime"]["evidence"]["binds"] = "weights-digest"
    vectors.append(
        (
            "advisory-binds-cannot-raise-a-claim",
            "platform-attested",
            "model claim: self-reported",
            sign_record(_unsigned(claimed_binding), key),
        )
    )

    return vectors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="write the vectors as JSON here")
    args = ap.parse_args()

    rows: list[tuple[str, str, str, bool, str]] = []
    for name, expected, expected_claim, record in build_corpus():
        try:
            grade = appraise(record)
        except Reject as e:
            actual, note = "reject", str(e)
        else:
            actual, note = grade, grade_model_claim(record, grade)
        ok = actual == expected and (expected_claim is None or note == expected_claim)
        rows.append((name, expected, actual, ok, note))
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            # Wrapped, not bare: the expectation travels with the vector so a reader
            # and tests/test_runtime_evidence_vectors.py see what it is graded against
            # without re-deriving it. `record` stays a clean TRACE record, because a
            # vector carrying an extra top-level member would fail the very schema the
            # corpus exists to exercise.
            (out / f"{name}.json").write_text(
                json.dumps(
                    {
                        "expected": {"grade": expected, "model_claim": expected_claim},
                        "record": record,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

    width = max(len(r[0]) for r in rows)
    print(f"{'vector'.ljust(width)}  {'expected'.ljust(17)}  {'actual'.ljust(17)}  note")
    print("-" * (width + 62))
    for name, expected, actual, ok, note in rows:
        flag = "" if ok else "   <-- MISMATCH"
        print(f"{name.ljust(width)}  {expected.ljust(17)}  {actual.ljust(17)}  {note}{flag}")

    failures = sum(1 for r in rows if not r[3])
    limits = sum(1 for r in rows if r[0].startswith("limit-"))
    print()
    print(
        f"{len(rows) - failures}/{len(rows)} vectors behaved as the profile says they must "
        f"({limits} of them documenting a limit of the rules rather than a success)."
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

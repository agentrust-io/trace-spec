"""Generate portable verifier-compatibility vectors (agentrust-io/trace-spec#116).

Implementation-agnostic JSON: each fixture carries a signed record, the profile set
the verifier declares, and the outcome any conformant verifier must produce. Nothing
in the fixture names a language or an API.

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

OUT = Path("examples/verifier-compatibility")
PROFILE = "trace.verifier_compatibility.proposal.v0"
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
V0_1 = "tag:agentrust.io,2026:trace-v0.1"
FUTURE = "tag:agentrust-io.com,2031:trace-v9.9"
# The downgrade vectors need an older profile a verifier may legitimately declare.
# That cannot be the real v0.1 identifier: the spec's cutover forbids a v0.2 verifier
# from accepting it under any configuration, so a downgrade vector built on v0.1
# encodes a non-conformant verifier, which an earlier revision of vector 04 did.
OLDER = "tag:example.com,2025:trace-v0.0"

SEED = hashlib.sha256(b"trace-spec#116 verifier-compatibility fixture key").digest()
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
    # disable the freshness check or supply this instant as "now"; version skew is
    # the property under test, not staleness.
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


def signed_record(profile: str) -> dict[str, Any]:
    """A genuinely signed record carrying *profile*.

    Every fixture's signature is valid. That is the point: the question these
    vectors ask is never "does the signature check out", it is "does this verifier
    implement the semantics the record was written under".
    """
    record = copy.deepcopy(BASE_RECORD)
    record["eat_profile"] = profile
    body = rfc8785.dumps(record)
    return {**record, "signature": b64u(KEY.sign(body))}


def fixture(
    name: str,
    description: str,
    *,
    record_profile: str,
    accepted_profiles: list[str],
    expected: dict[str, Any],
    preconditions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One vector. *preconditions*, where present, states what has to be true of the
    verifier under test for the expectation below to be the conformant answer.

    Most vectors need none: the outcome follows from the record and the declared set
    alone, both of which are in the file. Two do. `unschemaed_profile_in_accepted_set`
    is a refusal because the *verifier* carries no schema for the named profile, which
    is a fact about the implementation reading the vector and not about the JSON. The
    identifier those two carry is uncheckable for the reference implementation and
    might not be for another one, so it is written down as a premise the adapter
    checks rather than left as an assumption the adapter would report as a
    non-conformance.
    """
    out = {
        "name": name,
        "description": description,
        "profile": PROFILE,
        "proposal": {
            "issue": "agentrust-io/trace-spec#116",
            "status": "under review, not accepted normative text",
        },
        "verifier": {
            "accepted_profiles": accepted_profiles,
            "verification_time": 1785000100,
            "check_freshness": False,
        },
        "trusted_key": public_jwk(),
        "record": signed_record(record_profile),
        "expected": expected,
    }
    if preconditions is not None:
        out["preconditions"] = preconditions
    return out


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fixtures = [
        (
            "01-known-version-verified.json",
            fixture(
                "known-version-verified",
                "The record's profile is in the verifier's accepted set. Verification "
                "succeeds and the statement names the profile it ran under.",
                record_profile=V0_2,
                accepted_profiles=[V0_2],
                expected={
                    "outcome": "verified",
                    "failure": None,
                    "statement": {
                        "profile": V0_2,
                        "accepted_profiles": [V0_2],
                    },
                },
            ),
        ),
        (
            "02-unknown-version-refused.json",
            fixture(
                "unknown-version-refused",
                "A future profile the verifier does not implement. The signature is "
                "valid and the record must still be refused: fail-open here means "
                "verifying semantics the build does not implement.",
                record_profile=FUTURE,
                accepted_profiles=[V0_2],
                expected={
                    "outcome": "refused",
                    "failure": "profile_not_accepted",
                    "statement": None,
                },
            ),
        ),
        (
            "04-unschemaed-profile-refused.json",
            fixture(
                "unschemaed-profile-refused",
                "The verifier declares support for an older profile it carries no "
                "schema for. The record does not use it and does not need to: the "
                "first sentence of this description said it did until 2026-09-12, "
                "contradicting the sentence three lines below that says the record is "
                "an ordinary v0.2 record, which it is and always was. Refused at "
                "configuration, not at "
                "the record: a verifier can only honestly accept a profile whose shape "
                "it can check, and declaring more than that is a claim it cannot make. "
                "The record is an ordinary v0.2 record and nothing about it is wrong, "
                "which is the point: the only defect is in what the verifier declared, "
                "so a verifier that checks the record and not its own configuration "
                "accepts this and is still non-conformant. This vector said 'verified, "
                "downgraded' over an older record until the set was measured against a "
                "null verifier: that record was reaching the schema and being refused "
                "there, so the vector separated the schema rule rather than the profile "
                "rule it named. The older profile is deliberately not the v0.1 "
                "identifier, which no accepted set may contain for a different reason: "
                "the cutover in spec/trace-v0.2.md, whose coverage lives in "
                "tests/test_sign.py rather than in this set.",
                record_profile=V0_2,
                accepted_profiles=[V0_2, OLDER],
                expected={
                    "outcome": "refused",
                    "failure": "unschemaed_profile_in_accepted_set",
                    "statement": None,
                },
                preconditions={
                    "unschemaed_for_the_verifier_under_test": [OLDER],
                    "why": "The expectation is a refusal because the verifier carries "
                    "no schema for this profile. That is a fact about the "
                    "implementation running the vector, not about this file, so it is "
                    "stated here rather than assumed. An implementation that does "
                    "carry a schema for this identifier has not failed the vector: the "
                    "premise no longer holds for it, and it substitutes an identifier "
                    "of its own that it cannot check. The rule under test is that a "
                    "verifier refuses a declared set naming a profile whose shape it "
                    "cannot check, with an innocent record.",
                },
            ),
        ),
        (
            "05-downgrade-silent-is-impossible.json",
            fixture(
                "downgrade-silent-is-impossible",
                "The same older record against a verifier that did not declare the "
                "older profile. There must be no outcome in which verification "
                "succeeds under a profile absent from the accepted set: silent "
                "fallback is the failure this vector exists to forbid.",
                record_profile=OLDER,
                accepted_profiles=[V0_2],
                expected={
                    "outcome": "refused",
                    "failure": "profile_not_accepted",
                    "statement": None,
                },
            ),
        ),
        (
            "09-unschemaed-profile-first-in-set-refused.json",
            fixture(
                "unschemaed-profile-first-in-set-refused",
                "The same defect as vector 04 with the unusable profile first in the "
                "declared set instead of last. Every declared profile has to be "
                "checked, not one of them: an implementation that reads the head of "
                "the set, or the tail, agrees with one of these two vectors and not "
                "the other. The record is again an ordinary v0.2 record, so the only "
                "difference between the pair is where the unusable entry sits.",
                record_profile=V0_2,
                accepted_profiles=[OLDER, V0_2],
                expected={
                    "outcome": "refused",
                    "failure": "unschemaed_profile_in_accepted_set",
                    "statement": None,
                },
                preconditions={
                    "unschemaed_for_the_verifier_under_test": [OLDER],
                    "why": "The expectation is a refusal because the verifier carries "
                    "no schema for this profile. That is a fact about the "
                    "implementation running the vector, not about this file, so it is "
                    "stated here rather than assumed. An implementation that does "
                    "carry a schema for this identifier has not failed the vector: the "
                    "premise no longer holds for it, and it substitutes an identifier "
                    "of its own that it cannot check. The rule under test is that a "
                    "verifier refuses a declared set naming a profile whose shape it "
                    "cannot check, with an innocent record.",
                },
            ),
        ),
        (
            "06-empty-accepted-set-refused.json",
            fixture(
                "empty-accepted-set-refused",
                "A verifier that declares no supported profile verifies nothing. An "
                "empty set must not be read as 'accept anything'.",
                record_profile=V0_2,
                accepted_profiles=[],
                expected={
                    "outcome": "refused",
                    "failure": "no_accepted_profiles",
                    "statement": None,
                },
            ),
        ),
        (
            "11-empty-profile-string-refused.json",
            fixture(
                "empty-profile-string-refused",
                "The profile claim is present and empty. 07 removes the member "
                "entirely, so an implementation testing `\"eat_profile\" not in "
                "record` passes it and reads this one as a profile it simply does not "
                "recognise, or worse, as absent-and-therefore-current. A claim that "
                "is present and says nothing is not a claim. This cannot separate, "
                "and the reason is structural rather than a flaw: the schema pins "
                "`eat_profile` with a `const`, so any record reaching this rule is "
                "already schema-invalid and a verifier implementing nothing refuses "
                "it too.",
                record_profile="",
                accepted_profiles=[V0_2],
                expected={
                    "outcome": "refused",
                    "failure": "profile_absent",
                    "statement": None,
                },
            ),
        ),
    ]

    for filename, doc in fixtures:
        (OUT / filename).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print("wrote", OUT / filename)

    # 07 has no profile at all, so it cannot be produced by signed_record's profile arg.
    missing = fixture(
        "profile-absent-refused",
        "A record with no profile claim. A verifier cannot supply the semantics by "
        "assumption, so this refuses rather than defaulting to the current version.",
        record_profile=V0_2,
        accepted_profiles=[V0_2],
        expected={
            "outcome": "refused",
            "failure": "profile_absent",
            "statement": None,
        },
    )
    record = copy.deepcopy(BASE_RECORD)
    del record["eat_profile"]
    body = rfc8785.dumps(record)
    missing["record"] = {**record, "signature": b64u(KEY.sign(body))}
    (OUT / "07-profile-absent-refused.json").write_text(
        json.dumps(missing, indent=2) + "\n", encoding="utf-8"
    )
    print("wrote", OUT / "07-profile-absent-refused.json")


if __name__ == "__main__":
    main()

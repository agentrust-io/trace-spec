"""Generate examples/applicability-assessment: six signed Trust Records, each citing an
`applicability-assessment` reference, against an assessment store and an altered copy.

Every key derives from one published seed, so the set regenerates byte for byte and
tests/test_applicability_assessment_fixtures.py holds the committed files to this script.
The assessment objects are illustrative: the issuer is `compliance.deployer-b.example`,
the legal provision is Article 26(6) of Regulation (EU) 2024/1689 as read on 2026-09-30,
and every digest and signature in the set recomputes from what is committed. Nothing
here is a production record or legal advice.

Usage: python examples/applicability-assessment/gen_applicability_assessment_vectors.py [--out DIR]
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import key_to_jwk, sign_record

SEED = b"trace-spec examples/applicability-assessment 2026-10-16"
HERE = Path(__file__).resolve().parent

ISSUER = "https://compliance.deployer-b.example"
OTHER_ISSUER = "https://other-assessor.example.org"
RESOLVER = "https://compliance.deployer-b.example/assessments/2026-10"
ISSUED_AT = "2026-10-01T09:00:00Z"
IAT = int(datetime(2026, 10, 1, 9, 5, tzinfo=UTC).timestamp())
VOCABULARY = ["applies", "does-not-apply", "undetermined"]

PARTY = {"id": "https://deployer-b.example", "role": "deployer"}
JURISDICTION = "EU"
PROVISION = {
    "instrument": "http://data.europa.eu/eli/reg/2024/1689/oj",
    "article": "26(6)",
    "text_as_of": "2026-09-30",
}
BASIS_APPLIES = [
    "Regulation (EU) 2024/1689, Article 2(1)(b)",
    "Regulation (EU) 2024/1689, Article 6(2) and Annex III, point 4(a)",
    "Regulation (EU) 2026/1744, point (40)(b), amending Article 113",
]
BASIS_DOES_NOT_APPLY = [
    "Regulation (EU) 2024/1689, Article 2(1)(b)",
    "Regulation (EU) 2024/1689, Article 6(2) and Annex III",
]
BASIS_UNDETERMINED = [
    "Regulation (EU) 2024/1689, Article 2(1)(b)",
    "Regulation (EU) 2024/1689, Article 6(2), Article 6(3), and Annex III, point 4(a)",
]


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jcs_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(SEED + b"|" + label.encode()).digest()
    )


def thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638: SHA-256 over the required members, lexically ordered, no whitespace."""
    required = {k: jwk[k] for k in ("crv", "kty", "x")}
    encoded = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(encoded).digest())


def placeholder_digest(label: str) -> str:
    """A digest with no artifact behind it, derived from the seed by label."""
    return "sha256:" + hashlib.sha256(SEED + b"|digest|" + label.encode()).hexdigest()


def assessment(
    issuer: str,
    issuer_key: Ed25519PrivateKey,
    status: str,
    basis: list[str],
    detail: str,
    applies_from: str | None = None,
) -> dict[str, Any]:
    """The referenced object: party and role, jurisdiction, provision and text date,
    basis, the outcome in a closed vocabulary the object names, the issuer and its key,
    and a signature over the RFC 8785 canonical form of everything else."""
    outcome: dict[str, Any] = {
        "status": status,
        "vocabulary": VOCABULARY,
        "detail": detail,
    }
    if applies_from is not None:
        outcome["applies_from"] = applies_from
    body = {
        "type": "applicability-assessment",
        "issuer": issuer,
        "issuer_key_id": thumbprint(key_to_jwk(issuer_key)),
        "party": PARTY,
        "jurisdiction": JURISDICTION,
        "provision": PROVISION,
        "basis": basis,
        "outcome": outcome,
        "issued_at": ISSUED_AT,
    }
    return {**body, "signature": b64u(issuer_key.sign(rfc8785.dumps(body)))}


def record(producer: Ed25519PrivateKey, reference: dict[str, Any]) -> dict[str, Any]:
    unsigned = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": IAT,
        "subject": "spiffe://trust.example.org/agent/recruitment-screener",
        "model": {"provider": "example", "model_id": "example-model"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "confidential",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "cnf": {"jwk": key_to_jwk(producer)},
        "references": [reference],
    }
    return sign_record(unsigned, producer)


def reference(id_: str, digest: str) -> dict[str, Any]:
    return {
        "rel": "applicability-assessment",
        "id": id_,
        "resolver": RESOLVER,
        "digest": digest,
        "retention": "P1Y",
    }


def build() -> dict[str, Any]:
    producer, issuer_key, other_key = key("producer"), key("issuer"), key("other-issuer")

    store = {
        "resolver": RESOLVER,
        "assessments": {
            "assessment/1": assessment(
                ISSUER,
                issuer_key,
                "applies",
                BASIS_APPLIES,
                "high-risk recruitment-screening system under Annex III point 4(a)",
                applies_from="2027-12-02",
            ),
            "assessment/2": assessment(
                ISSUER,
                issuer_key,
                "does-not-apply",
                BASIS_DOES_NOT_APPLY,
                "internal formatting assistant outside Annex III high-risk categories",
            ),
            "assessment/3": assessment(
                ISSUER,
                issuer_key,
                "undetermined",
                BASIS_UNDETERMINED,
                "pending Article 6(3) narrow procedural task and profiling review",
            ),
            "assessment/4": assessment(
                OTHER_ISSUER,
                other_key,
                "applies",
                BASIS_APPLIES,
                "high-risk recruitment-screening system under Annex III point 4(a)",
                applies_from="2027-12-02",
            ),
        },
    }
    # The store as a relying party later finds it: assessment/2's does-not-apply
    # rewritten as applies. The digest the record carries was taken over the object as
    # issued, so it no longer matches, and the issuer's signature no longer verifies
    # over the rewritten bytes.
    altered = copy.deepcopy(store)
    altered["assessments"]["assessment/2"]["outcome"]["status"] = "applies"

    cite = lambda id_: reference(id_, jcs_sha256(store["assessments"][id_]))  # noqa: E731
    records = {
        "01-assessment-applies-verified.json": record(producer, cite("assessment/1")),
        "02-assessment-altered-after-issue.json": record(producer, cite("assessment/2")),
        "03-outcome-is-does-not-apply.json": record(producer, cite("assessment/2")),
        "04-outcome-is-undetermined.json": record(producer, cite("assessment/3")),
        "05-reference-unresolvable.json": record(
            producer, reference("assessment/9", placeholder_digest("assessment/9"))
        ),
        "06-issuer-key-not-configured.json": record(producer, cite("assessment/4")),
    }

    issuer_jwk = key_to_jwk(issuer_key)
    expected = {
        "trace_signer_jwk": key_to_jwk(producer),
        "resolver": RESOLVER,
        # The keys this relying party holds. The other issuer's key is deliberately
        # absent: spec section 3.3.2 says a receipt whose issuer key is unknown to the
        # verifier is unverified, not invalid.
        "issuer_keys": {thumbprint(issuer_jwk): issuer_jwk},
        "cases": {
            "01-assessment-applies-verified.json": {
                "store": "assessment-store.json",
                "trace_record_verifies": True,
                "reference_resolves": True,
                "digest_matches": True,
                "issuer_key_configured": True,
                "assessment_verifies": True,
                "outcome": "applies",
                "verdict": "assessment-verified",
            },
            "02-assessment-altered-after-issue.json": {
                "store": "assessment-store-altered.json",
                "trace_record_verifies": True,
                "reference_resolves": True,
                "digest_matches": False,
                "issuer_key_configured": True,
                "assessment_verifies": False,
                "outcome": "applies",
                "verdict": "assessment-digest-mismatch",
            },
            "03-outcome-is-does-not-apply.json": {
                "store": "assessment-store.json",
                "trace_record_verifies": True,
                "reference_resolves": True,
                "digest_matches": True,
                "issuer_key_configured": True,
                "assessment_verifies": True,
                "outcome": "does-not-apply",
                "verdict": "assessment-verified",
            },
            "04-outcome-is-undetermined.json": {
                "store": "assessment-store.json",
                "trace_record_verifies": True,
                "reference_resolves": True,
                "digest_matches": True,
                "issuer_key_configured": True,
                "assessment_verifies": True,
                "outcome": "undetermined",
                "verdict": "assessment-verified",
            },
            "05-reference-unresolvable.json": {
                "store": "assessment-store.json",
                "trace_record_verifies": True,
                "reference_resolves": False,
                "digest_matches": None,
                "issuer_key_configured": None,
                "assessment_verifies": None,
                "outcome": None,
                "verdict": "assessment-unresolved",
            },
            "06-issuer-key-not-configured.json": {
                "store": "assessment-store.json",
                "trace_record_verifies": True,
                "reference_resolves": True,
                "digest_matches": True,
                "issuer_key_configured": False,
                "assessment_verifies": None,
                "outcome": "applies",
                "verdict": "assessment-unverified",
            },
        },
    }

    return {
        **records,
        "assessment-store.json": store,
        "assessment-store-altered.json": altered,
        "expected.json": expected,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=True)
    files = build()
    for name, value in files.items():
        text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
        (out / name).write_bytes(text.encode("utf-8"))
    print(f"{len(files)} files written to {out}")


if __name__ == "__main__":
    main()

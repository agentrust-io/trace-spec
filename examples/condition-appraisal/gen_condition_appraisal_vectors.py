"""Generate examples/condition-appraisal: five signed Trust Records, each citing a
`condition-appraisal` reference, against an appraisal store and an altered copy of it.

Every key derives from one published seed, so the set regenerates byte for byte and
tests/test_condition_appraisal_fixtures.py holds the committed files to this script.
The appraisal objects are illustrative: the issuer is `gates.example.org`, the
condition and the deliverable are the small JSON values in `context.json`, and every
digest and signature in the set recomputes from what is committed. Nothing here is a
production record.

Usage: python examples/condition-appraisal/gen_condition_appraisal_vectors.py [--out DIR]
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

SEED = b"trace-spec examples/condition-appraisal 2026-09-21"
HERE = Path(__file__).resolve().parent

ISSUER = "https://gates.example.org"
OTHER_ISSUER = "https://other-gates.example.org"
RESOLVER = "https://gates.example.org/run/20260920-165918"
ISSUED_AT = "2026-09-20T17:01:00Z"
IAT = int(datetime(2026, 9, 20, 17, 1, tzinfo=UTC).timestamp())
VOCABULARY = ["pass", "fail", "inconclusive"]


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


CONDITION = {
    "id": "gate:tests-and-worktree/1",
    "criteria": [
        "the test suite exits 0",
        "no path outside the task worktree is written",
        "the diff touches only files the task names",
    ],
}

DELIVERABLE = {
    "id": "task:7f8f9bdabf7a/deliverable",
    "files": [
        {"path": "src/backend/payments.py", "sha256": placeholder_digest("payments.py")[7:]},
        {"path": "tests/test_payments.py", "sha256": placeholder_digest("test_payments.py")[7:]},
    ],
}


def appraisal(
    issuer: str, issuer_key: Ed25519PrivateKey, status: str, detail: str
) -> dict[str, Any]:
    """The referenced object: condition and subject by digest, the issuer and its key,
    the outcome in the issuer's own closed vocabulary, and a signature over the RFC 8785
    canonical form of everything else."""
    body = {
        "type": "condition-appraisal",
        "issuer": issuer,
        "issuer_key_id": thumbprint(key_to_jwk(issuer_key)),
        "condition": {"id": CONDITION["id"], "digest": jcs_sha256(CONDITION)},
        "subject": {"id": DELIVERABLE["id"], "digest": jcs_sha256(DELIVERABLE)},
        "outcome": {"status": status, "vocabulary": VOCABULARY, "detail": detail},
        "issued_at": ISSUED_AT,
    }
    return {**body, "signature": b64u(issuer_key.sign(rfc8785.dumps(body)))}


def record(producer: Ed25519PrivateKey, reference: dict[str, Any]) -> dict[str, Any]:
    unsigned = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": IAT,
        "subject": "spiffe://trust.example.org/agent/build-bot",
        "model": {"provider": "example", "model_id": "example-model"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "cnf": {"jwk": key_to_jwk(producer)},
        "references": [reference],
    }
    return sign_record(unsigned, producer)


def reference(id_: str, digest: str) -> dict[str, Any]:
    return {
        "rel": "condition-appraisal", "id": id_, "resolver": RESOLVER,
        "digest": digest, "retention": "P1Y",
    }


def build() -> dict[str, Any]:
    producer, issuer_key, other_key = key("producer"), key("issuer"), key("other-issuer")

    store = {
        "resolver": RESOLVER,
        "appraisals": {
            "appraisal/1": appraisal(ISSUER, issuer_key, "pass", "3 criteria checked, 3 held"),
            "appraisal/2": appraisal(
                ISSUER, issuer_key, "fail",
                "criterion 2 not held: tests/fixtures/out.txt written outside the worktree",
            ),
            "appraisal/3": appraisal(OTHER_ISSUER, other_key, "pass", "3 criteria checked, 3 held"),
        },
    }
    # The store as a relying party later finds it: appraisal/2's fail rewritten as a pass.
    # The digest the record carries was taken over the object as issued, so it no longer
    # matches, and the issuer's signature no longer verifies over the rewritten bytes.
    altered = copy.deepcopy(store)
    altered["appraisals"]["appraisal/2"]["outcome"]["status"] = "pass"

    cite = lambda id_: reference(id_, jcs_sha256(store["appraisals"][id_]))  # noqa: E731
    records = {
        "01-appraisal-confirmed.json": record(producer, cite("appraisal/1")),
        "02-appraisal-altered-after-issue.json": record(producer, cite("appraisal/2")),
        "03-outcome-is-a-fail.json": record(producer, cite("appraisal/2")),
        "04-reference-unresolvable.json": record(
            producer, reference("appraisal/9", placeholder_digest("appraisal/9"))
        ),
        "05-issuer-key-not-configured.json": record(producer, cite("appraisal/3")),
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
            "01-appraisal-confirmed.json": {
                "store": "appraisal-store.json", "trace_record_verifies": True,
                "reference_resolves": True, "digest_matches": True, "issuer_key_configured": True,
                "appraisal_verifies": True, "outcome": "pass", "verdict": "appraisal-confirmed",
            },
            "02-appraisal-altered-after-issue.json": {
                "store": "appraisal-store-altered.json", "trace_record_verifies": True,
                "reference_resolves": True, "digest_matches": False, "issuer_key_configured": True,
                "appraisal_verifies": False, "outcome": "pass", "verdict": "appraisal-contradicted",
            },
            "03-outcome-is-a-fail.json": {
                "store": "appraisal-store.json", "trace_record_verifies": True,
                "reference_resolves": True, "digest_matches": True, "issuer_key_configured": True,
                "appraisal_verifies": True, "outcome": "fail", "verdict": "appraisal-confirmed",
            },
            "04-reference-unresolvable.json": {
                "store": "appraisal-store.json", "trace_record_verifies": True,
                "reference_resolves": False, "digest_matches": None, "issuer_key_configured": None,
                "appraisal_verifies": None, "outcome": None, "verdict": "appraisal-unconfirmed",
            },
            "05-issuer-key-not-configured.json": {
                "store": "appraisal-store.json", "trace_record_verifies": True,
                "reference_resolves": True, "digest_matches": True, "issuer_key_configured": False,
                "appraisal_verifies": None, "outcome": "pass", "verdict": "appraisal-unverified",
            },
        },
    }

    return {
        **records,
        "appraisal-store.json": store,
        "appraisal-store-altered.json": altered,
        "context.json": {"condition": CONDITION, "deliverable": DELIVERABLE},
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

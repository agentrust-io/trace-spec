"""Generate the revocation-bundle conformance vectors (spec section 3.2.3).

The bundle format merged with #187 and nothing consumed it: `valid_until` appeared
zero times under `src/`. Issue #190 greenlit a consumer that distinguishes three
states, verified against a bundle, unverified for revocation, and no check
performed, and settled two calls inside that scope. These vectors pin both.

**Precedence.** Two bounds govern bundle age. `valid_until` is the issuer's,
signed into the bundle. The maximum bundle age is the deployment's, supplied by
the caller and measured from `issued_at`, which is the only field an age can be
measured from; the inference is safe because the schema offers no alternative,
not because the spec says so. The tighter bound governs. A deployment must be able
to be stricter than an issuer and must never be forced looser.

Five implementations of "is this bundle too old" are plausible, one of them a
one-character mistake: `min` (tighter governs), `issuer` (`valid_until` alone),
`deploy` (maximum age alone), `max` (either party may extend, `or` where `and` was
meant), and `none`. Vectors A, B, C and D are the complete truth table of the two
booleans every candidate is a function of, so two rules that differ anywhere
differ on one of those four rows. A alone separates `min` from `issuer`; B alone
separates `min` from `deploy`; without D, `max` and `none` are indistinguishable.
Each boundary is carried by two vectors, per the margin rule in #124, so a
shortcut that happens to reject one of them does not pass the boundary.

**The context block.** `max_bundle_age_seconds` has no home in the record and none
in the bundle: a bundle asserting its own acceptable staleness is the same shape
of problem as a record asserting its own approval threshold. It lives in the
vector's `context`, beside `now`, exactly as `max_depth` and `trusted_builders`
do in the two merged sets. The outcome then reproduces from retained facts.

**Every vector is offline.** No vector needs a resolver. A bundle is bytes in hand;
what a verifier does when it cannot obtain one is a harness question, not a
record question, and this set does not pretend otherwise.

Keys derive from one published seed, per role, so the whole set regenerates
byte-for-byte and a third party can reissue any of it. Files are written as bytes
with LF line endings, so the set regenerates identically on every platform.
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

OUT = Path("examples/revocation-bundle")
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
SPEC = "spec/trace-v0.2.md#323-revocation-of-record-signing-keys"

SEED = hashlib.sha256(b"trace-spec revocation-bundle fixture key").digest()
ROLES = ("issuer", "bundler", "stranger", "other-issuer")

#: Fixed verification moment. Vectors that turn on time move the bundle, never the clock.
NOW = 1785000000
#: Section 3.2.2's default maximum age, applied to bundles by 3.2.3's "same
#: maximum-age model" sentence. 3.2.3 names no bundle default of its own.
MAX_AGE = 86400
SKEW = 300
LOG = "https://log.example/trace"
DAY = 86400
HOUR = 3600


def key_for(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(SEED + b"|" + role.encode()).digest()
    )


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk_for(role: str, *, kid: str | None = None) -> dict[str, str]:
    raw = key_for(role).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}
    if kid is not None:
        jwk["kid"] = kid
    return jwk


def thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 for an OKP key: crv, kty, x, in that order, JCS bytes, sha256."""
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64u(hashlib.sha256(rfc8785.dumps(members)).digest())


def base_record(*, iat: int) -> dict[str, Any]:
    """A schema-valid v0.2 record with nothing optional except what the set needs."""
    return {
        "eat_profile": V0_2,
        "iat": iat,
        "subject": "spiffe://acme.example/agent/issuer",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "00" * 32},
        "policy": {"bundle_hash": "sha256:" + "aa" * 32, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "bb" * 32},
        "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    }


def signed_record(body: dict[str, Any], *, sign_key: str) -> dict[str, Any]:
    record = dict(body)
    record["cnf"] = {"jwk": jwk_for(sign_key)}
    record["signature"] = b64u(key_for(sign_key).sign(rfc8785.dumps(record)))
    return record


def statement(*, compromised: str, issuer: str = "bundler") -> dict[str, Any]:
    body = {
        "type": "TraceRevocation/1.0",
        "compromised_key_id": compromised,
        "last_valid_entry_id": "41",
        "revoked_after_entry": "42",
        "log_id": LOG,
        "reason": "key compromise",
        "revocation_key_id": thumbprint(jwk_for(issuer)),
    }
    value = b64u(key_for(issuer).sign(rfc8785.dumps(body)))
    return {**body, "sig": {"alg": "ed25519", "value": value}}


def bundle(
    *,
    issued_at: int,
    valid_until: int,
    statements: list[dict[str, Any]] | None = None,
    sign_key: str = "bundler",
    key_id: str | None = None,
) -> dict[str, Any]:
    body = {
        "type": "TraceRevocationBundle/1.0",
        "log_id": LOG,
        "issued_at": issued_at,
        "valid_until": valid_until,
        "statements": statements or [],
        "bundle_key_id": key_id or thumbprint(jwk_for(sign_key)),
    }
    value = b64u(key_for(sign_key).sign(rfc8785.dumps(body)))
    return {**body, "sig": {"alg": "ed25519", "value": value}}


def bundle_digest(b: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(b)).hexdigest()


def expired_by(issued_at: int, valid_until: int) -> str | None:
    """The consumer's own arithmetic, restated here so `expected` cannot drift from it."""
    issuer = NOW > valid_until
    deploy = (NOW - issued_at) > MAX_AGE
    if issuer and deploy:
        return "both"
    if issuer:
        return "issuer"
    if deploy:
        return "deployment"
    return None


RECORD = signed_record(base_record(iat=NOW - HOUR), sign_key="issuer")
TRUSTED = jwk_for("issuer", kid="issuer-key-2026")
TRUSTED_ID = thumbprint(TRUSTED)
BUNDLE_KEYS = [jwk_for("bundler")]


def vector(
    n: int,
    name: str,
    description: str,
    *,
    b: dict[str, Any] | None,
    outcome: str | None,
    cause: str | None = None,
    codes: list[str],
    rejected: bool = False,
    evidence: dict[str, Any] | None = None,
    trusted_bundle_keys: list[dict[str, str]] | None = None,
    trusted_key: dict[str, str] = TRUSTED,
) -> tuple[str, dict[str, Any]]:
    expected: dict[str, Any] = {"rejected": rejected, "codes": codes}
    if not rejected:
        expected["outcome"] = outcome
        expected["cause"] = cause
        expected["evidence"] = evidence or {}
    return f"{n:02d}-{name}.json", {
        "id": f"TRACE-RBUN-{n:03d}",
        "name": name,
        "description": description,
        "spec": SPEC,
        "context": {
            "now": NOW,
            "max_bundle_age_seconds": MAX_AGE,
            "max_future_skew_seconds": SKEW,
            "trusted_key": trusted_key,
            "trusted_bundle_keys": (
                BUNDLE_KEYS if trusted_bundle_keys is None else trusted_bundle_keys
            ),
            "bundle": b,
        },
        "records": [RECORD],
        "expected": expected,
    }


def fresh_evidence(b: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "bundle_digest": bundle_digest(b),
        "log_id": LOG,
        "issued_at": b["issued_at"],
        "valid_until": b["valid_until"],
        "now": NOW,
        "max_bundle_age_seconds": MAX_AGE,
        **extra,
    }


def age_vector(
    n: int, name: str, description: str, *, issued_at: int, valid_until: int
) -> tuple[str, dict[str, Any]]:
    b = bundle(issued_at=issued_at, valid_until=valid_until)
    tripped = expired_by(issued_at, valid_until)
    if tripped is None:
        return vector(n, name, description, b=b, outcome="verified", codes=[],
                      evidence=fresh_evidence(b, statements_count=0))
    codes = ["bundle_expired"] + (
        ["issuer_bound_tripped", "deployment_bound_tripped"] if tripped == "both"
        else [f"{tripped}_bound_tripped"]
    )
    return vector(n, name, description, b=b, outcome="unverified_for_revocation",
                  cause="bundle_expired", codes=codes,
                  evidence=fresh_evidence(b, bound_tripped=tripped))


def main() -> None:
    out: list[tuple[str, dict[str, Any]]] = []

    # The truth table, with margin. C: neither bound tripped.
    out.append(age_vector(1, "fresh-well-inside-both-bounds",
        "Issued an hour ago, valid for thirty days. Neither bound tripped; verified against the "
        "bundle valid at T.",
        issued_at=NOW - HOUR, valid_until=NOW + 30 * DAY))
    out.append(age_vector(2, "fresh-at-issuer-horizon",
        "now equals valid_until exactly. The issuer bound is inclusive on the valid side, so this "
        "is still evidence.",
        issued_at=NOW - HOUR, valid_until=NOW))
    out.append(age_vector(3, "fresh-at-deployment-maximum",
        "Age equals max_bundle_age_seconds exactly. The deployment bound is inclusive on the valid "
        "side.",
        issued_at=NOW - MAX_AGE, valid_until=NOW + 30 * DAY))
    # A: only the deployment bound tripped. The sole discriminator between min and issuer.
    out.append(age_vector(4, "deployment-bound-tripped-wide",
        "Issued 48 hours ago under a 24 hour maximum, valid_until thirty days out. An "
        "implementation honouring valid_until alone passes this and is wrong.",
        issued_at=NOW - 2 * DAY, valid_until=NOW + 30 * DAY))
    out.append(age_vector(5, "deployment-bound-tripped-by-one-second",
        "Age is max_bundle_age_seconds plus one. The margin vector for the deployment boundary.",
        issued_at=NOW - MAX_AGE - 1, valid_until=NOW + 30 * DAY))
    # B: only the issuer bound tripped. The sole discriminator between min and deploy.
    out.append(age_vector(6, "issuer-bound-tripped-wide",
        "Issued an hour ago, valid_until thirty minutes ago. An implementation honouring the "
        "maximum age alone passes this and is wrong.",
        issued_at=NOW - HOUR, valid_until=NOW - 30 * 60))
    out.append(age_vector(7, "issuer-bound-tripped-by-one-second",
        "valid_until is one second ago. The margin vector for the issuer boundary.",
        issued_at=NOW - HOUR, valid_until=NOW - 1))
    # D: both tripped. Separates max from none.
    out.append(age_vector(8, "both-bounds-tripped-wide",
        "Issued 48 hours ago and valid_until thirty minutes ago. Without this vector, a verifier "
        "that ORs the two bounds is indistinguishable from one that checks nothing.",
        issued_at=NOW - 2 * DAY, valid_until=NOW - 30 * 60))
    out.append(age_vector(9, "both-bounds-tripped-by-one-second",
        "Both bounds exceeded by exactly one second. The margin vector for the both-tripped row.",
        issued_at=NOW - MAX_AGE - 1, valid_until=NOW - 1))

    # What the set says, once it is evidence.
    b10 = bundle(issued_at=NOW - HOUR, valid_until=NOW + DAY)
    out.append(vector(10, "empty-statements-is-evidence",
        "A fresh bundle with no statements. The schema says an empty array is meaningful: as of "
        "issued_at the issuer knew of no revoked keys on this log. Verified.",
        b=b10, outcome="verified", codes=[], evidence=fresh_evidence(b10, statements_count=0)))
    b11 = bundle(issued_at=NOW - HOUR, valid_until=NOW + DAY,
                 statements=[statement(compromised=TRUSTED_ID)])
    out.append(vector(11, "statement-names-trusted-key-by-thumbprint",
        "A fresh bundle carrying a statement whose compromised_key_id is the trusted key's RFC "
        "7638 thumbprint. No entry ID reaches the verifier, so the 3.2.3 fallback rejects the "
        "record.",
        b=b11, outcome=None, codes=["key_revoked"], rejected=True))
    b12 = bundle(issued_at=NOW - HOUR, valid_until=NOW + DAY,
                 statements=[statement(compromised="issuer-key-2026")])
    out.append(vector(12, "statement-names-trusted-key-by-kid",
        "As 11, but the statement names the key by its kid. A match on either identifier revokes "
        "the key.",
        b=b12, outcome=None, codes=["key_revoked"], rejected=True))
    b13 = bundle(issued_at=NOW - HOUR, valid_until=NOW + DAY,
                 statements=[statement(compromised=thumbprint(jwk_for("other-issuer")))])
    out.append(vector(13, "statement-names-a-different-key",
        "A fresh bundle whose only statement names some other key. This record's key is not named; "
        "verified, with the statement counted.",
        b=b13, outcome="verified", codes=[], evidence=fresh_evidence(b13, statements_count=1)))

    # No bundle at all.
    out.append(vector(14, "no-bundle-no-check-performed",
        "Neither a bundle nor a store was supplied. The verifier reports that it performed no "
        "revocation check, which is what 3.2.3 requires and what the old None return withheld.",
        b=None, outcome="no_check_performed", codes=["no_check_performed"], evidence={},
        trusted_bundle_keys=[]))
    out.append(vector(25, "no-bundle-with-bundle-keys-configured",
        "Bundle keys are configured and no bundle was supplied. Configuration is not a check; "
        "still no check performed. The margin vector for the no-check row, against an "
        "implementation that reads configuration as evidence.",
        b=None, outcome="no_check_performed", codes=["no_check_performed"], evidence={}))

    # The bundle cannot ground anything.
    b15 = copy.deepcopy(b10)
    value = b15["sig"]["value"]
    b15["sig"]["value"] = ("A" if value[0] != "A" else "B") + value[1:]
    out.append(vector(15, "signature-value-corrupted",
        "One character of sig.value changed. The signature does not verify; unverified, and the "
        "bundle is not read further.",
        b=b15, outcome="unverified_for_revocation", cause="bundle_signature_invalid",
        codes=["bundle_signature_invalid"],
        evidence=fresh_evidence(b15, bundle_key_id=b15["bundle_key_id"])))
    b16 = copy.deepcopy(b10)
    b16["valid_until"] = b16["valid_until"] + DAY
    out.append(vector(16, "signed-bytes-do-not-match",
        "valid_until extended after signing. The signature was made over other bytes, so an issuer "
        "horizon nobody signed is not evidence.",
        b=b16, outcome="unverified_for_revocation", cause="bundle_signature_invalid",
        codes=["bundle_signature_invalid"],
        evidence=fresh_evidence(b16, bundle_key_id=b16["bundle_key_id"])))
    b17 = bundle(issued_at=NOW - HOUR, valid_until=NOW + DAY, sign_key="stranger")
    out.append(vector(17, "bundle-key-unknown-to-caller",
        "A correctly signed bundle from a key the caller does not trust for bundles. Untrusted, "
        "not invalid: the signature is fine, the signer is not accepted.",
        b=b17, outcome="unverified_for_revocation", cause="bundle_key_untrusted",
        codes=["bundle_key_untrusted"],
        evidence=fresh_evidence(b17, bundle_key_id=b17["bundle_key_id"])))
    b18 = bundle(issued_at=NOW - HOUR, valid_until=NOW + DAY, sign_key="issuer")
    out.append(vector(18, "bundle-signed-by-record-key",
        "The record-signing key signed the bundle about itself. It is not in trusted_bundle_keys, "
        "so the bundle is untrusted; 3.2.3's signing-key independence is the reason it must not "
        "be.",
        b=b18, outcome="unverified_for_revocation", cause="bundle_key_untrusted",
        codes=["bundle_key_untrusted"],
        evidence=fresh_evidence(b18, bundle_key_id=b18["bundle_key_id"])))
    b19 = copy.deepcopy(b10)
    del b19["valid_until"]
    out.append(vector(19, "malformed-valid-until-absent",
        "A required field is missing. Malformed, with the path named; nothing after shape is "
        "checked.",
        b=b19, outcome="unverified_for_revocation", cause="bundle_malformed",
        codes=["bundle_malformed"], evidence={"path": "/"}))
    b20 = bundle(issued_at=NOW - HOUR, valid_until=NOW + DAY,
                 statements=[{
                     **statement(compromised=thumbprint(jwk_for("other-issuer"))),
                     "log_id": "https://log.example/other",
                 }])
    out.append(vector(20, "malformed-statement-on-another-log",
        "Schema-valid, but one statement names a different log from the bundle. One log per "
        "bundle; entry IDs across logs are not comparable.",
        b=b20, outcome="unverified_for_revocation", cause="bundle_malformed",
        codes=["bundle_malformed"], evidence={"path": "statements/0/log_id"}))
    b21 = {**b10, "sig": {"alg": "ES256", "value": b10["sig"]["value"]}}
    out.append(vector(21, "signature-alg-es256-unsupported",
        "The schema admits ES256; this build verifies Ed25519 only. Reported as unsupported rather "
        "than skipped.",
        b=b21, outcome="unverified_for_revocation", cause="bundle_signature_unsupported",
        codes=["bundle_signature_unsupported"], evidence=fresh_evidence(b21, alg="ES256")))
    b22 = {**b10, "sig": {"alg": "ES384", "value": b10["sig"]["value"]}}
    out.append(vector(22, "signature-alg-es384-unsupported",
        "As 21, with ES384. The margin vector for the unsupported-algorithm boundary.",
        b=b22, outcome="unverified_for_revocation", cause="bundle_signature_unsupported",
        codes=["bundle_signature_unsupported"], evidence=fresh_evidence(b22, alg="ES384")))
    b23 = bundle(issued_at=NOW + SKEW + 1, valid_until=NOW + 30 * DAY)
    out.append(vector(23, "issued-in-future-past-skew",
        "issued_at is one second past the tolerated clock skew. Nothing can have observed this "
        "bundle yet.",
        b=b23, outcome="unverified_for_revocation", cause="bundle_issued_in_future",
        codes=["bundle_issued_in_future"],
        evidence=fresh_evidence(b23, max_future_skew_seconds=SKEW)))
    b24 = bundle(issued_at=NOW + DAY, valid_until=NOW + 30 * DAY)
    out.append(vector(24, "issued-in-future-by-a-day",
        "issued_at is a day ahead. The margin vector for the future-issue boundary.",
        b=b24, outcome="unverified_for_revocation", cause="bundle_issued_in_future",
        codes=["bundle_issued_in_future"],
        evidence=fresh_evidence(b24, max_future_skew_seconds=SKEW)))

    # A statement outlives its carrier. The bounds govern the bundle's silence;
    # an authenticated statement naming the key is read before either time check.
    named = [statement(compromised=TRUSTED_ID)]
    b26 = bundle(issued_at=NOW - HOUR, valid_until=NOW - 1, statements=named)
    out.append(vector(26, "stale-by-issuer-statement-still-rejects",
        "valid_until is one second past and the bundle names the trusted key. The "
        "statement was authenticated with the bundle's signature and has no expiry "
        "of its own, so the record is rejected; a verifier that aged the bundle out "
        "before reading it would report unverified instead.",
        b=b26, outcome=None, codes=["key_revoked", "statement_outlives_bundle"], rejected=True))
    b27 = bundle(issued_at=NOW - MAX_AGE - 1, valid_until=NOW + 30 * DAY, statements=named)
    out.append(vector(27, "stale-by-deployment-statement-still-rejects",
        "Age is one second past max_bundle_age_seconds and the bundle names the "
        "trusted key. Same rule on the deployment bound: rejected.",
        b=b27, outcome=None, codes=["key_revoked", "statement_outlives_bundle"], rejected=True))
    b28 = bundle(issued_at=NOW + DAY, valid_until=NOW + 30 * DAY, statements=named)
    out.append(vector(28, "future-issued-statement-still-rejects",
        "issued_at is a day ahead and the bundle names the trusted key. A "
        "future-dated bundle vouches for nothing it is silent about, but what it "
        "says was signed by a trusted bundle key: rejected.",
        b=b28, outcome=None, codes=["key_revoked", "statement_outlives_bundle"], rejected=True))

    OUT.mkdir(parents=True, exist_ok=True)
    for name, doc in sorted(out):
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        (OUT / name).write_bytes(text.encode("utf-8"))
        print("wrote", name)


if __name__ == "__main__":
    main()

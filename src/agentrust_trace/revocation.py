"""Revocation-bundle consumer for ``verify_record`` (spec section 3.2.3).

Section 3.2.3 publishes a bundle format, ``schema/trace-revocation-bundle.json``,
and states what a verifier reports under it: "verified against revocation bundle
valid at T"; "unverified for revocation" when the newest bundle is older than the
profile's maximum age; "performed no revocation check" when there is no bundle at
all. It closes with the sentence this module is built around: "Neither may be
reported as an affirming appraisal."

Those three phrases are the three values of ``RevocationCheck.outcome``. They are
lifted from the normative text rather than coined here, and nothing in this module
names or sets an ``appraisal.status`` value. Where an unresolvable check is finally
recorded in the record itself is the question issue #190 holds open; this module
stops one step short of it, as that thread asked.

The outcome is a value in the result, not an exception and not an out-parameter.
A caller who does not know to ask for it gets a ``VerificationResult`` whose
``revocation`` field says ``no_check_performed``, which is the same information the
old ``None`` return silently withheld. A caller who discards the result has the
fail-open problem the old return had; that is stated in ``verify_record``'s
docstring rather than hidden, and it is the shape chosen over the alternatives on
issue #190, with the reason on the record there.

Two bounds govern bundle age, and the tighter one wins. ``valid_until`` is the
issuer's horizon, inside the bundle's signed bytes. The deployment's maximum bundle
age is the caller's, supplied per call; 3.2.3 caches bundles "under the same
maximum-age model as section 3.2.2", and 3.2.2's default under that model is 24
hours, so 86400 is the default here. 3.2.3 itself names no bundle-specific default
and defers the value to the deployment profile. A bundle is evidence only while
both bounds hold, and an expired outcome names which bound tripped, so a verifier
re-running from the retained facts alone, with no clock and no network, reaches
the same outcome. Whether a second implementation agrees is what the conformance
vectors are for. The bounds govern the bundle's silence, not its speech: a
statement naming the trusted key was authenticated with the bundle's signature,
has no expiry of its own, and rejects the record whether the bundle that carried
it is fresh or not.

What this module does not do, stated so it is not mistaken for something it does:

- It does not verify each statement's own signature against the section 3.2.1 key
  hierarchy. The bundle signature authenticates the set and its horizon; statement
  signer independence is a separate check that needs the hierarchy, which this
  module does not hold.
- It does not apply the entry-ID rule. No SCITT inclusion entry ID reaches
  ``verify_record`` today, so a key named by a statement on the bundle's log is the
  section 3.2.3 fallback: every record it signed is rejected. That is the existing
  behaviour of the ``revocation`` store, unchanged.
- It does not fetch anything. Schema references are resolved from the two files
  packaged beside this module, never over the network.
"""

from __future__ import annotations

import hashlib
import importlib.resources
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

import jsonschema
import referencing
import referencing.jsonschema

from agentrust_trace.sign import (
    _b64url_decode,
    _canonical_bytes,
    _key_identifiers,
    _pubkey_from_jwk,
)

Outcome = Literal["verified", "unverified_for_revocation", "no_check_performed"]
"""Section 3.2.3's three reportable states, in its own words."""

Cause = Literal[
    "bundle_expired",
    "bundle_malformed",
    "bundle_key_untrusted",
    "bundle_signature_invalid",
    "bundle_signature_unsupported",
    "bundle_issued_in_future",
]
"""Why a supplied bundle could not ground a verified outcome."""

BoundTripped = Literal["issuer", "deployment", "both"]


@dataclass(frozen=True)
class RevocationCheck:
    """What the revocation check reported, and the facts a second verifier needs.

    ``evidence`` is JSON-serialisable by construction so it can be retained beside
    the record and compared byte-for-byte against a conformance vector's
    ``expected`` block.
    """

    outcome: Outcome
    cause: Cause | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationResult:
    """The result of ``verify_record``. Success is no longer ``None``.

    Every other rejection still raises, as before. This type exists so that the
    outcomes section 3.2.3 says may not be reported as an affirming appraisal have
    somewhere to be reported, alongside the checks that passed.
    """

    revocation: RevocationCheck
    trusted_key_thumbprint: str


NO_CHECK = RevocationCheck(outcome="no_check_performed")
"""The result when neither a bundle nor a store was supplied."""


def _unverified(cause: Cause, evidence: dict[str, Any]) -> RevocationCheck:
    return RevocationCheck(outcome="unverified_for_revocation", cause=cause, evidence=evidence)


@lru_cache(maxsize=1)
def _bundle_validator() -> jsonschema.Draft202012Validator:
    """A validator for the bundle schema that resolves its statement ``$ref`` locally.

    ``statements.items.$ref`` is an absolute URL. A validator built from the bundle
    file alone resolves it by fetching the published schema, which checks a nested
    statement against whatever is deployed rather than the file next to it, and
    fails outright with no network. Both schemas are packaged beside this module
    and registered under their ``$id`` so resolution never leaves the process.
    ``tests/test_revocation_bundle.py`` validates with sockets blocked to hold it
    to that.
    """
    pkg = importlib.resources.files("agentrust_trace") / "schema"
    bundle_schema = json.loads(
        (pkg / "trace-revocation-bundle.json").read_text(encoding="utf-8")
    )
    statement_schema = json.loads((pkg / "trace-revocation.json").read_text(encoding="utf-8"))
    resource = referencing.Resource.from_contents(
        statement_schema, default_specification=referencing.jsonschema.DRAFT202012
    )
    return jsonschema.Draft202012Validator(
        bundle_schema, registry=resource @ referencing.Registry()
    )


def bundle_digest(bundle: dict[str, Any]) -> str:
    """The bundle's identity: sha256 over its RFC 8785 form, signature included.

    Signature included, because two bundles with identical content and different
    signatures are two different pieces of evidence, and the digest names which one
    the outcome was reached against.
    """
    if not isinstance(bundle, dict):
        raise ValueError(f"bundle must be a JSON object, got {type(bundle).__name__}")
    try:
        canonical = _canonical_bytes(bundle)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"bundle has no RFC 8785 form: {exc}") from exc
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _trusted_bundle_key(
    bundle_key_id: str, trusted_bundle_keys: Iterable[dict[str, Any]]
) -> dict[str, Any] | None:
    for jwk in trusted_bundle_keys:
        if bundle_key_id in _key_identifiers(jwk):
            return jwk
    return None


def check_bundle(
    bundle: dict[str, Any],
    *,
    trusted_key_identifiers: Iterable[str],
    trusted_bundle_keys: Iterable[dict[str, Any]],
    now: int,
    max_bundle_age_seconds: int,
    max_future_skew_seconds: int,
) -> RevocationCheck:
    """Decide what a bundle lets a verifier report about the trusted record key.

    The order of checks is fixed and is the order a second verifier must follow to
    reproduce the outcome: shape, then who signed the set, then what the set says
    about this key, then whether the set is still evidence for what it does not
    say. A bundle that fails an earlier step is not read further, so the cause
    names the first thing wrong, not everything. Statements are read before the
    time checks on purpose: the freshness bounds exist so that an absent statement
    means something, and a present, authenticated one needs no clock to mean what
    it says. That ordering was raised in review of the pull request that added
    this module and chosen rather than inherited.

    Raises ``ValueError`` when a statement on the bundle's log names the trusted
    key. That is evidence failing rather than evidence absent, and it fails closed
    like the ``revocation`` store does.
    """
    trusted_ids = list(trusted_key_identifiers)
    trusted_bundle_keys = list(trusted_bundle_keys)

    # 3a. Shape, against the packaged schema pair. The first error by path, so the
    # evidence points at one place rather than listing the file.
    errors = sorted(
        _bundle_validator().iter_errors(bundle),
        key=lambda e: list(map(str, e.absolute_path)),
    )
    if errors:
        first = errors[0]
        return _unverified("bundle_malformed", {
            "path": "/".join(str(p) for p in first.absolute_path) or "/",
            "error": first.message,
        })

    log_id = bundle["log_id"]
    statements = bundle["statements"]

    # 3b. One log per bundle. The schema pins that on the bundle and on each
    # statement separately; equality between them is this module's check.
    for index, statement in enumerate(statements):
        if statement["log_id"] != log_id:
            return _unverified("bundle_malformed", {
                "path": f"statements/{index}/log_id",
                "error": f"statement names log {statement['log_id']!r}; bundle is for {log_id!r}",
            })

    issued_at = bundle["issued_at"]
    valid_until = bundle["valid_until"]
    base = {
        "bundle_digest": bundle_digest(bundle),
        "log_id": log_id,
        "issued_at": issued_at,
        "valid_until": valid_until,
        "now": now,
        "max_bundle_age_seconds": max_bundle_age_seconds,
    }

    # 3c. Who signed the set. Only Ed25519 can be verified here; the schema also
    # admits ES256 and ES384, and those are reported as unsupported rather than
    # skipped, because a signature nobody checked grounds nothing.
    alg = bundle["sig"]["alg"]
    if alg != "ed25519":
        return _unverified("bundle_signature_unsupported", {**base, "alg": alg})
    key = _trusted_bundle_key(bundle["bundle_key_id"], trusted_bundle_keys)
    if key is None:
        return _unverified(
            "bundle_key_untrusted", {**base, "bundle_key_id": bundle["bundle_key_id"]}
        )
    try:
        public = _pubkey_from_jwk(key)
    except ValueError as exc:
        return _unverified(
            "bundle_signature_unsupported", {**base, "alg": alg, "key": str(exc)}
        )
    unsigned = {k: v for k, v in bundle.items() if k != "sig"}
    try:
        signature = _b64url_decode(bundle["sig"]["value"], field="bundle sig.value")
        public.verify(signature, _canonical_bytes(unsigned))
    except Exception:
        return _unverified(
            "bundle_signature_invalid", {**base, "bundle_key_id": bundle["bundle_key_id"]}
        )

    # 3d. What the set says about this key, read before either time check. A
    # statement's signature was verified with the bundle's at 3c, so it is an
    # authenticated assertion that the issuer declared this key compromised;
    # section 3.2.3 gives a statement no expiry and no withdrawal, and the
    # schema puts valid_until on the bundle, not on the statement. The time
    # bounds below govern what the bundle's silence is worth; they do not make
    # its speech untrue. Fallback rule: no entry ID is available here, so a
    # named key rejects every record it signed.
    for statement in statements:
        if statement["compromised_key_id"] in trusted_ids:
            raise ValueError(
                f"signing key is revoked: statement on log {log_id!r} names it as "
                f"{statement['compromised_key_id']!r} (bundle {base['bundle_digest']}). "
                "No inclusion entry ID is available to place this record before the "
                "revocation, so section 3.2.3's fallback applies and the record is rejected."
            )

    # 3e. A bundle from the future has an issued_at nothing can have observed, so
    # its silence about other keys is not evidence of anything.
    if issued_at > now + max_future_skew_seconds:
        return _unverified("bundle_issued_in_future", {
            **base, "max_future_skew_seconds": max_future_skew_seconds,
        })

    # 3f. Age. Tighter governs: the bundle vouches for the absence of a statement
    # only while both bounds hold, since an absent statement means "none known as
    # of issued_at" and that is only informative while issued_at is recent.
    # Inclusive on the valid side, so now == valid_until and age == max are fresh.
    issuer_tripped = now > valid_until
    deployment_tripped = (now - issued_at) > max_bundle_age_seconds
    if issuer_tripped or deployment_tripped:
        tripped: BoundTripped = (
            "both" if issuer_tripped and deployment_tripped
            else "issuer" if issuer_tripped
            else "deployment"
        )
        return _unverified("bundle_expired", {**base, "bound_tripped": tripped})

    # 3g. Verified against this bundle, valid at T, with T retained.
    return RevocationCheck(
        outcome="verified", evidence={**base, "statements_count": len(statements)}
    )

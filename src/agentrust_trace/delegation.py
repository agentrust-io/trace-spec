"""Delegation-link digest, single-hop verification, and A2A chain appraisal.

Section 3.1.3 of ``spec/trace-v0.2.md`` defines the single-hop delegation commitment:
a child Trust Record's ``delegation.parent_record_hash`` is the ``sha256`` or ``sha384``
digest over the complete RFC 8785 (JCS) canonical form of the parent Trust Record,
with its ``signature`` member present:

    delegation.parent_record_hash = "<alg>:" + hex(H(JCS(parent_record)))

``parent_record_hash`` and ``verify_delegation_link`` implement that single-hop
commitment and mirror ``trust-record-verify/src/delegation.ts``.

``verify_delegation_chain`` implements the eleven-rule A2A delegation-link verification
walk specified in ``docs/rfcs/a2a-delegation-profile.md`` and scored by the 26 test
vectors under ``examples/delegation-link/``.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import ValidationError

from agentrust_trace.sign import _b64url_decode, _canonical_bytes, _integer_value
from agentrust_trace.validate import validate_json

DELEGATION_DIGEST_ALGORITHMS: tuple[str, ...] = ("sha256", "sha384")
"""Digest algorithms permitted for ``delegation.parent_record_hash`` (section 3.1.3)."""

CLASSIFICATIONS: frozenset[str] = frozenset(
    {"verified", "provenance-invalid", "authorization-invalid", "unverifiable"}
)
"""Three-way A2A chain appraisal classifications plus ``verified``."""


class DelegationError(ValueError):
    """Raised when a delegation link or chain verification input is malformed or invalid."""


@dataclass(frozen=True)
class DelegationLink:
    """Verified single-hop commitment from a child Trust Record to its parent."""

    parent_record_hash: str
    algorithm: str
    credential_id: str


@dataclass(frozen=True)
class ChainResult:
    """Appraisal outcome for an A2A delegation chain."""

    classification: str
    failures: list[str]
    warnings: list[str]
    depth: int

    def __post_init__(self) -> None:
        if self.classification not in CLASSIFICATIONS:
            raise DelegationError(f"undeclared outcome {self.classification!r}")

    @property
    def codes(self) -> list[str]:
        return sorted(set(self.failures) | set(self.warnings))


def parent_record_hash(record: dict[str, Any], algorithm: str = "sha256") -> str:
    """Return the section 3.1.3 chain digest of *record* as ``"<alg>:<hex>"``.

    The pre-image is the complete *record* as published, ``signature`` included,
    canonicalised with RFC 8785 (JCS). Raises :class:`DelegationError` if *record*
    is not a JSON object, cannot be canonicalised under RFC 8785, or if *algorithm*
    is not in :data:`DELEGATION_DIGEST_ALGORITHMS`.
    """
    if not isinstance(algorithm, str) or algorithm not in DELEGATION_DIGEST_ALGORITHMS:
        raise DelegationError(f"unsupported chain digest algorithm {algorithm!r}")
    if not isinstance(record, dict):
        raise DelegationError(
            f"record must be a JSON object, got {type(record).__name__}"
        )
    try:
        canonical = _canonical_bytes(record)
    except (rfc8785.CanonicalizationError, ValueError, TypeError) as exc:
        raise DelegationError(
            f"record has no RFC 8785 canonical form: {exc}"
        ) from exc
    return f"{algorithm}:{hashlib.new(algorithm, canonical).hexdigest()}"


def _normalize_supported_algorithms(value: Any) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, bytearray, dict)) or not isinstance(
        value, Iterable
    ):
        raise DelegationError(
            "supported_digest_algorithms must be an iterable of algorithm names"
        )
    items = tuple(value)
    if not items or not all(isinstance(alg, str) and alg for alg in items):
        raise DelegationError(
            "supported_digest_algorithms must contain non-empty algorithm strings"
        )
    return items


def verify_delegation_link(
    child: dict[str, Any],
    parent: dict[str, Any],
    *,
    supported_digest_algorithms: Iterable[str] = DELEGATION_DIGEST_ALGORITHMS,
) -> DelegationLink:
    """Verify that *parent* is the record *child* commits to in ``child["delegation"]``.

    Raises :class:`DelegationError` when *child* or *parent* is not a JSON object,
    when *child* carries no ``delegation`` block, when the block is malformed,
    when the digest algorithm prefix is not in *supported_digest_algorithms* or
    :data:`DELEGATION_DIGEST_ALGORITHMS`, or when the recomputed digest of *parent*
    does not match ``child["delegation"]["parent_record_hash"]``.
    """
    supported = _normalize_supported_algorithms(supported_digest_algorithms)
    if not isinstance(child, dict):
        raise DelegationError(
            f"child record must be a JSON object, got {type(child).__name__}"
        )
    if not isinstance(parent, dict):
        raise DelegationError(
            f"parent record must be a JSON object, got {type(parent).__name__}"
        )
    delegation = child.get("delegation")
    if delegation is None:
        raise DelegationError(
            "the record has no delegation block, so it claims no parent hop"
        )
    if not isinstance(delegation, dict):
        raise DelegationError("the record's delegation member is not an object")
    if set(delegation) != {"parent_record_hash", "credential_id"}:
        raise DelegationError(
            "the delegation block must contain only parent_record_hash and credential_id"
        )
    stated = delegation.get("parent_record_hash")
    credential_id = delegation.get("credential_id")
    if (
        not isinstance(stated, str)
        or not stated
        or not isinstance(credential_id, str)
        or not credential_id
    ):
        raise DelegationError(
            "the delegation block needs a parent_record_hash and a credential_id"
        )
    separator = stated.find(":")
    algorithm = "" if separator == -1 else stated[:separator]
    if algorithm not in supported:
        raise DelegationError(
            f"the link names digest algorithm {algorithm!r}, which this verifier does not "
            "implement; section 3.1.3 forbids falling back to another one"
        )
    if algorithm not in DELEGATION_DIGEST_ALGORITHMS:
        raise DelegationError(
            f"digest algorithm {algorithm!r} is not one this build can compute"
        )
    computed = parent_record_hash(parent, algorithm)
    if not hmac.compare_digest(computed, stated):
        raise DelegationError(
            "the candidate parent record does not digest to the value the child commits to"
        )
    return DelegationLink(
        parent_record_hash=stated,
        algorithm=algorithm,
        credential_id=credential_id,
    )


def _signature_invalid(record: dict[str, Any]) -> bool:
    """Does *record* fail verification under the key it advertises in ``cnf.jwk``?

    The claimed key, not a trusted one: whether the key is trusted is a separate
    question with its own rule, and merging them produces a verifier that cannot
    tell "forged" from "signed by someone you have not heard of".
    """
    cnf = record.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict):
        return True
    if (
        jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
        or not isinstance(jwk.get("x"), str)
    ):
        return True
    signature = record.get("signature")
    if not isinstance(signature, str):
        return True
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        canonical_body = _canonical_bytes(body)
        raw_x = _b64url_decode(jwk["x"], field="cnf.jwk.x")
        raw_sig = _b64url_decode(signature, field="signature")
        Ed25519PublicKey.from_public_bytes(raw_x).verify(
            raw_sig, canonical_body
        )
    except (
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError,
        rfc8785.CanonicalizationError,
    ):
        return True
    return False


def _jwk_key(jwk: dict[str, Any]) -> tuple[Any, ...]:
    """Hashable identity for a JWK over key material only."""
    return (jwk.get("kty"), jwk.get("crv"), jwk.get("x"), jwk.get("y"))


@dataclass(frozen=True)
class Hop:
    """One position in the delegation walk, carrying the state a rule inspects."""

    record: dict[str, Any]
    context: dict[str, Any]
    index: dict[str, dict[str, Any]]
    depth: int
    parent: dict[str, Any] | None = None

    @property
    def delegation(self) -> dict[str, Any]:
        return self.record["delegation"]  # type: ignore[no-any-return]

    @property
    def link_algorithm(self) -> str:
        return str(self.delegation["parent_record_hash"]).split(":", 1)[0]

    @property
    def credential(self) -> dict[str, Any] | None:
        creds: dict[str, dict[str, Any]] = self.context["credentials"]
        return creds.get(self.delegation["credential_id"])


@dataclass(frozen=True)
class Rule:
    """One named obligation in the A2A delegation profile."""

    code: str
    severity: str
    klass: str
    path: str
    check: Callable[[Hop], bool] = field(compare=False)


def _record_signature_invalid(hop: Hop) -> bool:
    return _signature_invalid(hop.record)


def _root_key_untrusted(hop: Hop) -> bool:
    trusted = {_jwk_key(j) for j in hop.context["trusted_root_keys"]}
    return _jwk_key(hop.record.get("cnf", {}).get("jwk", {})) not in trusted


def _depth_exceeded(hop: Hop) -> bool:
    return bool(hop.depth > hop.context["max_depth"])


def _digest_algorithm_unsupported(hop: Hop) -> bool:
    return hop.link_algorithm not in hop.context["supported_digest_algorithms"]


def _parent_not_found(hop: Hop) -> bool:
    if _digest_algorithm_unsupported(hop):
        return False
    return hop.delegation["parent_record_hash"] not in hop.index


def _credential_unknown(hop: Hop) -> bool:
    return hop.credential is None


def _credential_issuer_mismatch(hop: Hop) -> bool:
    cred = hop.credential
    if cred is None or hop.parent is None:
        return False
    return bool(cred["issuer"] != hop.parent["subject"])


def _credential_holder_mismatch(hop: Hop) -> bool:
    cred = hop.credential
    if cred is None:
        return False
    return bool(cred["holder"] != hop.record["subject"])


def _credential_window(hop: Hop) -> bool:
    cred = hop.credential
    if cred is None:
        return False
    # Judged at the hop's own `iat`. A chain does not expire because it is being
    # read late, and a verifier using its own clock reports a different answer
    # every day for the same evidence.
    iat = _integer_value(hop.record["iat"], "iat")
    return not bool(cred["not_before"] <= iat <= cred["not_after"])


def _data_class_unknown(hop: Hop) -> bool:
    if hop.parent is None:
        return False
    lattice: list[str] = hop.context["data_class_lattice"]
    return (
        hop.record["data_class"] not in lattice
        or hop.parent["data_class"] not in lattice
    )


def _data_class_widened(hop: Hop) -> bool:
    if hop.parent is None or _data_class_unknown(hop):
        return False
    lattice: list[str] = hop.context["data_class_lattice"]
    return lattice.index(hop.record["data_class"]) > lattice.index(
        hop.parent["data_class"]
    )


RULES: tuple[Rule, ...] = (
    Rule(
        "record_signature_invalid",
        "failure",
        "provenance",
        "record",
        _record_signature_invalid,
    ),
    Rule("root_key_untrusted", "failure", "provenance", "root", _root_key_untrusted),
    Rule("depth_exceeded", "failure", "authorization", "resolve", _depth_exceeded),
    Rule(
        "digest_algorithm_unsupported",
        "warning",
        "unverifiable",
        "resolve",
        _digest_algorithm_unsupported,
    ),
    Rule("parent_not_found", "failure", "provenance", "resolve", _parent_not_found),
    Rule(
        "credential_unknown", "failure", "authorization", "link", _credential_unknown
    ),
    Rule(
        "credential_issuer_mismatch",
        "failure",
        "authorization",
        "link",
        _credential_issuer_mismatch,
    ),
    Rule(
        "credential_holder_mismatch",
        "failure",
        "authorization",
        "link",
        _credential_holder_mismatch,
    ),
    Rule("credential_window", "failure", "authorization", "link", _credential_window),
    Rule(
        "data_class_unknown", "warning", "unverifiable", "link", _data_class_unknown
    ),
    Rule(
        "data_class_widened", "failure", "authorization", "link", _data_class_widened
    ),
)


def _evaluate(
    hop: Hop, rules: Sequence[Rule], path: str
) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    for rule in rules:
        if rule.path == path and rule.check(hop):
            (failures if rule.severity == "failure" else warnings).append(rule.code)
    return failures, warnings


def _validate_record_shape(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise DelegationError(
            f"each record must be a JSON object, got {type(record).__name__}"
        )
    try:
        validate_json(record)
    except ValidationError as exc:
        raise DelegationError(
            f"record does not conform to the TRACE v0.2 schema: {exc.message}"
        ) from exc
    try:
        _integer_value(record.get("iat"), "iat")
    except ValueError as exc:
        raise DelegationError(str(exc)) from exc
    return record


def _validate_context(context: Any) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise DelegationError(
            f"context must be a JSON object, got {type(context).__name__}"
        )
    required = (
        "trusted_root_keys",
        "credentials",
        "data_class_lattice",
        "max_depth",
        "supported_digest_algorithms",
    )
    missing = [key for key in required if key not in context]
    if missing:
        raise DelegationError(f"context is missing required field(s): {missing}")

    supported = _normalize_supported_algorithms(
        context["supported_digest_algorithms"]
    )
    for alg in supported:
        if alg not in DELEGATION_DIGEST_ALGORITHMS:
            raise DelegationError(
                f"context lists unsupported digest algorithm {alg!r}"
            )

    max_depth = context["max_depth"]
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
        raise DelegationError("context.max_depth must be a non-negative integer")

    lattice = context["data_class_lattice"]
    if (
        isinstance(lattice, (str, bytes, bytearray, dict))
        or not isinstance(lattice, Sequence)
        or not all(isinstance(item, str) and item for item in lattice)
    ):
        raise DelegationError(
            "context.data_class_lattice must be a sequence of non-empty strings"
        )

    trusted_keys = context["trusted_root_keys"]
    if (
        isinstance(trusted_keys, (str, bytes, bytearray, dict))
        or not isinstance(trusted_keys, Iterable)
    ):
        raise DelegationError(
            "context.trusted_root_keys must be an iterable of JWK objects"
        )
    trusted_list = list(trusted_keys)
    if not all(isinstance(k, dict) for k in trusted_list):
        raise DelegationError(
            "context.trusted_root_keys must contain only JWK objects"
        )

    credentials = context["credentials"]
    if not isinstance(credentials, dict):
        raise DelegationError("context.credentials must be a JSON object")
    for cid, cred in credentials.items():
        if not isinstance(cid, str) or not cid or not isinstance(cred, dict):
            raise DelegationError(
                "context.credentials must map credential IDs to credential objects"
            )
        if not isinstance(cred.get("issuer"), str) or not isinstance(
            cred.get("holder"), str
        ):
            raise DelegationError(
                f"credential {cid!r} must carry string issuer and holder"
            )
        for bound in ("not_before", "not_after"):
            val = cred.get(bound)
            if isinstance(val, bool) or not isinstance(val, int):
                raise DelegationError(
                    f"credential {cid!r} must carry integer {bound}"
                )

    return {
        **context,
        "supported_digest_algorithms": list(supported),
        "data_class_lattice": list(lattice),
        "trusted_root_keys": trusted_list,
    }


def verify_delegation_chain(
    records: Iterable[dict[str, Any]],
    leaf: dict[str, Any] | str,
    context: dict[str, Any],
    *,
    rules: Sequence[Rule] = RULES,
) -> ChainResult:
    """Walk a delegation chain from *leaf* towards its root under *context*.

    The record set is a set: it arrives in no useful order, the leaf is named by
    digest (or passed as the leaf record dict itself) rather than by position,
    and a parent is found by looking its digest up rather than by taking the next
    element. An implementation that reads ``records[0]`` as the root agrees with
    this one on nothing.

    No cycle check, deliberately. A cycle needs each record's delegation block to
    carry a digest covering the block that names it back, which is a hash
    collision; the reachable analogue is an unbounded chain, and that is what
    ``depth_exceeded`` is for. The RFC states this rather than leaving a reader to
    wonder which of the two was forgotten.

    Raises :class:`DelegationError` when the caller's inputs (*records*, *leaf*,
    *context*, or *rules*) are malformed, when any record fails schema validation,
    or when *leaf* is not present in *records* under a supported digest algorithm.
    """
    if isinstance(records, (str, bytes, bytearray, dict)) or not isinstance(
        records, Iterable
    ):
        raise DelegationError("records must be an iterable of Trust Record objects")
    record_list = [_validate_record_shape(r) for r in records]
    if not record_list:
        raise DelegationError("records must not be empty")

    validated_context = _validate_context(context)

    if isinstance(rules, (str, bytes, bytearray, dict)) or not isinstance(
        rules, Sequence
    ):
        raise DelegationError("rules must be a sequence of Rule objects")
    rule_tuple = tuple(rules)
    if not all(isinstance(r, Rule) for r in rule_tuple):
        raise DelegationError("rules must contain only Rule instances")

    supported = validated_context["supported_digest_algorithms"]
    index: dict[str, dict[str, Any]] = {}
    for algorithm in supported:
        for record in record_list:
            index[parent_record_hash(record, algorithm)] = record

    if isinstance(leaf, str):
        if ":" not in leaf:
            raise DelegationError("leaf digest must have an '<alg>:<hex>' prefix")
        current = index.get(leaf)
    elif isinstance(leaf, dict):
        _validate_record_shape(leaf)
        current = index.get(parent_record_hash(leaf, supported[0]))
    else:
        raise DelegationError(
            f"leaf must be a Trust Record object or digest string, got {type(leaf).__name__}"
        )

    if current is None:
        raise DelegationError(
            "the leaf record is not in records under a supported digest algorithm"
        )

    failures: list[str] = []
    warnings: list[str] = []
    depth = 0
    visited: set[int] = set()

    while True:
        hop = Hop(
            record=current,
            context=validated_context,
            index=index,
            depth=depth,
        )

        found, warned = _evaluate(hop, rule_tuple, "record")
        failures += found
        warnings += warned

        if "delegation" not in current:
            found, warned = _evaluate(hop, rule_tuple, "root")
            failures += found
            warnings += warned
            break

        depth += 1
        hop = replace(hop, depth=depth)
        found, warned = _evaluate(hop, rule_tuple, "resolve")
        failures += found
        warnings += warned

        # Whether the walk can continue is a structural fact about the records,
        # asked here directly. The registry says *why* a link could not be
        # followed; it does not decide whether one was. Deriving the control flow
        # from "did any rule fire" instead couples the walk to the registry's
        # contents, and the completeness suite's whole method is to run this
        # function with rules removed: under which that walk stepped off the end
        # of the index and raised, rather than reporting a changed outcome.
        # One reason only: the parent could not be resolved. The depth bound is
        # deliberately *not* repeated here. Repeating it stops the walk at the same
        # record whether or not `depth_exceeded` is registered, so a weakened bound
        # never gets to walk further than a correct one, and the two depth vectors
        # move together under every mutation: margin without independence, which
        # is exactly what #124 says a second vector must not be.
        parent = None
        if hop.link_algorithm in supported:
            parent = index.get(current["delegation"]["parent_record_hash"])
        if parent is None:
            break

        hop = replace(hop, parent=parent)
        found, warned = _evaluate(hop, rule_tuple, "link")
        failures += found
        warnings += warned

        # Not a conformance rule, and it cannot fire on a chain anyone can build:
        # a cycle would need a record's delegation block to hold a digest of the
        # block that names it back. It is here so that this function terminates on
        # any input at all, including one hand-edited into a shape the hashes
        # forbid, rather than terminating because the corpus happens to be honest.
        if id(parent) in visited:
            break
        visited.add(id(parent))

        current = parent

    if any(
        rule.klass == "provenance" for rule in rule_tuple if rule.code in failures
    ):
        classification = "provenance-invalid"
    elif failures:
        classification = "authorization-invalid"
    elif warnings:
        classification = "unverifiable"
    else:
        classification = "verified"

    return ChainResult(
        classification=classification,
        failures=failures,
        warnings=warnings,
        depth=depth,
    )

"""MCP Server Provenance Records: build, sign, verify.

Implements ``spec/server-provenance-v1.md``. A provenance record is a signed
statement *about* an MCP server, not about an execution, so it is deliberately
not a Trust Record and does not pretend to be one.

The function that matters here is :func:`check_tool_catalog`. Everything else
verifies that a document is internally consistent and signed by a key you already
trust, which is table stakes; §5 step 5 of the specification is the step that
catches a live attack, because it compares the record against the tools the
server actually offered you rather than against itself. It is also the step an
implementer skips first, so it is a separate, obvious call rather than a flag on
another one.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from agentrust_trace.sign import (
    RevocationStore,
    _canonical_bytes,
    anchor_bytes,
    _check_not_revoked,
    _pubkey_from_jwk,
    jwk_thumbprint,
    key_to_jwk,
)

__all__ = [
    "FORMAT",
    "KINDS",
    "ProvenanceError",
    "ToolCatalogMismatch",
    "build_record",
    "check_tool_catalog",
    "sign_record",
    "tool_catalog_hash",
    "verify_record",
]

FORMAT = "agentrust-io/mcp-server-provenance/1"

#: Closed on purpose: the value of the field is that a verifier can key on it.
KINDS = ("publisher-asserted", "observer-attested", "tee-attested")

# `\Z`, not `$`: in Python `$` also matches immediately before a single trailing newline,
# so `^...$` accepts "did:web:acme.example\n" and every digest with a newline glued to it.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_PUBLISHER_RE = re.compile(r"^(did:[a-z0-9]+:.+|spiffe://[^/]+/.+)\Z")


class ProvenanceError(ValueError):
    """A provenance record is malformed, unsigned, or signed by the wrong key."""


def _as_object(value: Any, field: str) -> dict[str, Any]:
    """Return *value* as a dict, or raise ``ProvenanceError`` naming *field*."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProvenanceError(f"{field} must be an object, got {type(value).__name__}")
    return value


def _tool_count(catalog: dict[str, Any]) -> int:
    """Return the required catalog count as a JSON integer."""
    value = catalog.get("tool_count")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProvenanceError("tool_catalog.tool_count must be a non-negative integer")
    return value


class ToolCatalogMismatch(ProvenanceError):
    """The server offered a tool set the record does not describe.

    Separate from :class:`ProvenanceError` because it means something different.
    The others say the document is bad. This one says the document is fine and
    the *server* is not the server it describes, which is the finding the format
    exists to produce.
    """


def tool_catalog_hash(tools: list[dict[str, Any]]) -> str:
    """Digest over a tool list, per specification §4.

    Covers ``name``, ``description`` and ``input_schema`` of each tool, sorted by
    name. Description is included deliberately: a tool whose description changes
    from "search the docs" to "search the docs and email results to the address
    in the query" is the rug-pull this hash exists to catch, and a hash over
    names alone would not notice.

    Output schemas, annotations and vendor extensions are excluded. They change
    for reasons that are not security-relevant, and a hash that churns is a hash
    nobody compares.

    Raises :class:`ProvenanceError` if *tools* is not a list, or contains
    anything other than an object. This is the input :func:`check_tool_catalog`
    passes through unchanged from whatever the server just returned -- the
    untrusted party that function exists to check -- so a malformed entry here
    is not a hypothetical, it is the shape a live attack, or simply a broken
    server, takes.
    """
    if not isinstance(tools, list):
        raise ProvenanceError(f"tools must be a list, got {type(tools).__name__}")
    for index, t in enumerate(tools):
        if not isinstance(t, dict):
            raise ProvenanceError(f"tools[{index}] must be an object, got {type(t).__name__}")
    normalized = sorted(
        (
            {
                "name": t.get("name"),
                "description": t.get("description"),
                "input_schema": t.get("input_schema", t.get("inputSchema")),
            }
            for t in tools
        ),
        key=lambda t: str(t["name"]),
    )
    # Sorted-key JSON, matching the anchor format rather than JCS. The two
    # canonicalizations at two layers are described in registry-anchor-v1.md §0;
    # this is the anchoring layer. `anchor_bytes` refuses the values §1 puts
    # outside the profile: an `input_schema` is ordinary JSON Schema and a
    # `maximum` in it is ordinary content, so this is reachable without anyone
    # doing anything strange.
    return "sha256:" + hashlib.sha256(anchor_bytes(normalized)).hexdigest()


def _check_structure(
    *,
    kind: str,
    artifact: dict[str, Any] | None,
    endpoint: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
    issued_at: Any,
) -> None:
    """The structural rules both the producer and the consumer must apply.

    Shared rather than duplicated because these rules were enforced only in
    :func:`build_record` for a time, and a record does not have to come from
    ``build_record``: anyone can write the JSON and sign it. A rule that lives
    only on the producer side is a rule an attacker simply does not run, so a
    ``tee-attested`` record with ``attestation: null`` verified cleanly.

    Keeping one implementation is the point. Two copies drift, and the copy that
    matters is the one on the consumer side.
    """
    if artifact is not None:
        if not isinstance(artifact, dict):
            raise ProvenanceError(
                f"identity.artifact must be an object, got {type(artifact).__name__}"
            )
        if not artifact.get("package"):
            raise ProvenanceError("artifact.package is required (a Package URL)")
        if not _DIGEST_RE.match(str(artifact.get("digest", ""))):
            raise ProvenanceError(
                "artifact.digest must be a sha256: digest of the entrypoint. For an "
                "interpreted server that is the script, not the interpreter: every such "
                "server on a host shares one interpreter digest."
            )
    if endpoint is not None:
        if not isinstance(endpoint, dict):
            raise ProvenanceError(
                f"identity.endpoint must be an object, got {type(endpoint).__name__}"
            )
        if not endpoint.get("url"):
            raise ProvenanceError("endpoint.url is required when endpoint is present")
        if not _DIGEST_RE.match(str(endpoint.get("spki_sha256", ""))):
            raise ProvenanceError(
                "endpoint.spki_sha256 must be a sha256: digest of the Subject Public Key "
                "Info. A URL on its own is not an identity."
            )
    if kind == "tee-attested" and not attestation:
        raise ProvenanceError(
            "kind='tee-attested' without attestation evidence is the claim without the "
            "thing that backs it"
        )
    if kind != "tee-attested" and attestation:
        raise ProvenanceError(
            f"kind={kind!r} carries attestation evidence. Evidence that is present but "
            "not claimed invites a consumer to read it as an attestation that was made."
        )
    # bool is an int subclass, and True would otherwise pass as a timestamp.
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 0:
        raise ProvenanceError(
            "issued_at must be a non-negative integer Unix timestamp. A record with no "
            "issue time cannot be aged, so a consumer has no way to reject a stale one."
        )


def build_record(
    *,
    kind: str,
    publisher: str,
    tools: list[dict[str, Any]],
    artifact: dict[str, str] | None = None,
    endpoint: dict[str, str] | None = None,
    attestation: dict[str, Any] | None = None,
    issued_at: int | None = None,
) -> dict[str, Any]:
    """Assemble an unsigned provenance record.

    Raises rather than emitting a record that cannot mean anything: an identity
    with neither an artifact nor an endpoint identifies nothing, and a
    ``tee-attested`` record without attestation evidence is the claim without the
    thing that backs it.
    """
    if kind not in KINDS:
        raise ProvenanceError(f"kind {kind!r} is not one of {', '.join(KINDS)}")
    if not _PUBLISHER_RE.match(publisher or ""):
        raise ProvenanceError(
            f"publisher {publisher!r} must be a DID or SPIFFE URI. A display name is not "
            "resolvable and a verifier cannot check one."
        )
    if artifact is None and endpoint is None:
        raise ProvenanceError(
            "a record needs artifact identity, endpoint identity, or both. One with "
            "neither identifies nothing."
        )
    stamped_at = int(issued_at if issued_at is not None else time.time())
    _check_structure(
        kind=kind,
        artifact=artifact,
        endpoint=endpoint,
        attestation=attestation,
        issued_at=stamped_at,
    )

    identity: dict[str, Any] = {}
    if artifact is not None:
        identity["artifact"] = dict(artifact)
    if endpoint is not None:
        identity["endpoint"] = dict(endpoint)

    return {
        "format": FORMAT,
        "kind": kind,
        "issued_at": stamped_at,
        "identity": identity,
        "publisher": publisher,
        "tool_catalog": {"hash": tool_catalog_hash(tools), "tool_count": len(tools)},
        "attestation": attestation,
    }


def sign_record(record: dict[str, Any], key: Any) -> dict[str, Any]:
    """Sign per TRACE v0.2 §3.2: Ed25519 over the JCS form with the signature absent.

    Raises ``ProvenanceError`` for a *record* that is not a JSON object. ``{**record}``
    reads it before its shape is established, so a non-mapping raised a bare
    ``TypeError`` about dict unpacking, which is not this module's documented refusal.
    """
    if not isinstance(record, dict):
        raise ProvenanceError(
            f"record must be a JSON object, got {type(record).__name__}"
        )
    payload = {**record, "cnf": {"jwk": key_to_jwk(key)}}
    body = _canonical_bytes({k: v for k, v in payload.items() if k != "signature"})
    import base64

    sig = base64.urlsafe_b64encode(key.sign(body)).rstrip(b"=").decode()
    return {**payload, "signature": sig}


def _check_seconds(name: str, value: Any, *, optional: bool = False) -> None:
    """Reject a malformed policy input instead of silently acting on it.

    A verifier's age policy is configuration, and a wrong one fails in the
    direction that matters: ``max_age_seconds=-1`` is not a stricter bound, it
    classifies every record ever issued as stale, and a caller who meant to
    disable the bound would see a uniform refusal rather than an error naming
    the cause. ``bool`` is excluded explicitly because it is a subclass of
    ``int`` in Python, so ``True`` would otherwise pass as one second.
    """
    if optional and value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProvenanceError(f"{name} must be an integer, got {type(value).__name__}")
    if value < 0:
        raise ProvenanceError(f"{name} must be non-negative, got {value}")


def verify_record(
    record: dict[str, Any],
    trusted_jwk: dict[str, Any],
    *,
    revocation: RevocationStore | None = None,
    max_age_seconds: int | None = None,
    max_future_skew_seconds: int = 300,
) -> None:
    """Verify structure and signature. Raises :class:`ProvenanceError` on failure.

    *trusted_jwk* is required and is never taken from the record. Verifying a
    document against a key it supplies proves only that it is internally
    consistent, which is what a forged record is.

    ``revocation`` is consulted before the signature is checked, with exactly the
    semantics :func:`sign.verify_record` documents: a container of revoked
    identifiers or a callable, matched against the trusted key's RFC 7638
    thumbprint *and* its ``kid``. Both a revoked key and an unreachable store fail
    closed. ``None`` skips the check and keeps verification offline; offline
    verification cannot prove non-revocation.

    ``max_age_seconds`` bounds how old ``issued_at`` may be. It defaults to
    ``None``, unlike the 86400 of a Trust Record, because a provenance record
    describes an artifact by immutable digest and those are conventionally valid
    indefinitely. A record carrying ``endpoint`` identity is the case where that
    reasoning does not hold, a URL and an SPKI digest decay, so a consumer
    relying on ``endpoint`` should pass a bound.

    ``max_future_skew_seconds`` (default 300) is enforced whether or not an age
    bound is set. Without it a far-future ``issued_at`` stays inside any later
    ``max_age_seconds`` window until that time arrives, which is the defect
    #155 fixed for Trust Records.

    **This does not check the server.** It checks the paper. Call
    :func:`check_tool_catalog` with the tools the server actually offered.
    """
    import base64

    if not isinstance(record, dict):
        raise ProvenanceError(
            f"record must be a JSON object, got {type(record).__name__}. `_as_object` "
            "holds `identity` and `tool_catalog` to that shape, and neither can be "
            "reached until the record itself is one: `record.get(...)` on a list or a "
            "string raises AttributeError, which is not the ProvenanceError this "
            "function documents and is not caught by a caller written against it."
        )

    if record.get("format") != FORMAT:
        raise ProvenanceError(
            f"unknown format {record.get('format')!r}; expected {FORMAT}. An unknown "
            "version is rejected rather than parsed best-effort."
        )
    if record.get("kind") not in KINDS:
        raise ProvenanceError(f"unknown kind {record.get('kind')!r}")
    if not _PUBLISHER_RE.match(str(record.get("publisher", ""))):
        raise ProvenanceError("publisher must be a DID or SPIFFE URI")
    identity = _as_object(record.get("identity"), "identity")
    if not identity.get("artifact") and not identity.get("endpoint"):
        raise ProvenanceError("identity carries neither an artifact nor an endpoint")
    _check_structure(
        kind=str(record.get("kind")),
        artifact=identity.get("artifact"),
        endpoint=identity.get("endpoint"),
        attestation=record.get("attestation"),
        issued_at=record.get("issued_at"),
    )
    catalog = _as_object(record.get("tool_catalog"), "tool_catalog")
    if not _DIGEST_RE.match(str(catalog.get("hash", ""))):
        raise ProvenanceError("tool_catalog.hash is not a sha256: digest")
    _tool_count(catalog)

    # Freshness. `issued_at` has been required and type-checked since the format
    # existed, with an error message explaining that a record with no issue time
    # cannot be aged; this is the step that reads it. `_check_structure` above has
    # already established it is a non-negative int.
    _check_seconds("max_future_skew_seconds", max_future_skew_seconds)
    _check_seconds("max_age_seconds", max_age_seconds, optional=True)
    age = time.time() - int(record["issued_at"])
    if age < -max_future_skew_seconds:
        raise ProvenanceError(
            f"record is dated {int(-age)}s in the future, exceeds "
            f"max_future_skew_seconds={max_future_skew_seconds}"
        )
    if max_age_seconds is not None and age > max_age_seconds:
        raise ProvenanceError(
            f"record is stale: issued_at is {int(age)}s old, exceeds "
            f"max_age_seconds={max_age_seconds}"
        )

    # Revocation, before the signature rather than after. A signature made by a
    # revoked key stays cryptographically valid for ever, so the verifier is the
    # only place the fact can be applied.
    if revocation is not None:
        try:
            _check_not_revoked(trusted_jwk, revocation)
        except ValueError as exc:
            raise ProvenanceError(str(exc)) from exc

    signature = record.get("signature")
    if not signature:
        raise ProvenanceError("record carries no signature")

    cnf = _as_object(record.get("cnf"), "cnf")
    embedded = cnf.get("jwk")
    if not embedded:
        raise ProvenanceError("record carries no cnf.jwk")

    # Compared by RFC 7638 thumbprint, not by dict equality. A JWK is identified by
    # its key material; `kid`, `use` and `alg` are optional members that carry none
    # of it, and a key resolved from a JWKS endpoint normally has `kid` while
    # `key_to_jwk` emits the bare minimum. Dict equality made that difference fatal
    # and rejected records signed by exactly the right key.
    from hmac import compare_digest

    try:
        matched = compare_digest(jwk_thumbprint(embedded), jwk_thumbprint(trusted_jwk))
    except ValueError as exc:
        raise ProvenanceError(f"the record's embedded key is unusable: {exc}") from exc
    if not matched:
        raise ProvenanceError(
            "the record's embedded key is not the trusted key. A record signed by "
            "some other key is a record about a server somebody else is describing."
        )

    pub = _pubkey_from_jwk(trusted_jwk)
    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    padded = signature + "=" * (-len(signature) % 4)
    try:
        pub.verify(base64.urlsafe_b64decode(padded), body)
    except Exception as exc:  # cryptography raises InvalidSignature
        raise ProvenanceError(f"signature does not verify: {exc}") from exc


def check_tool_catalog(record: dict[str, Any], tools: list[dict[str, Any]]) -> None:
    """Compare the record against the tools the server actually offered.

    Specification §5 step 5, and the only step that catches a live attack. A
    mismatch means the server you are talking to is not the server the record
    describes, whoever signed it and however well the signature verifies.

    Kept as its own call rather than folded into :func:`verify_record` because it
    needs something ``verify_record`` does not have: what the server said to
    *you*. A verifier that never obtains that has checked a document against
    itself.

    Raises :class:`ToolCatalogMismatch` on a mismatch, and :class:`ProvenanceError`
    if ``record["tool_catalog"]`` is present but is not an object -- the same
    contract :func:`verify_record` makes, since this can run against a record
    ``verify_record`` has not (yet) seen.
    """
    if not isinstance(record, dict):
        raise ProvenanceError(
            f"record must be a JSON object, got {type(record).__name__}. This runs "
            "against records `verify_record` has not seen, as its docstring says, so it "
            "cannot assume that function established the shape."
        )

    actual = tool_catalog_hash(tools)
    catalog = _as_object(record.get("tool_catalog"), "tool_catalog")
    expected = catalog.get("hash")
    if actual != expected:
        declared_count = catalog.get("tool_count")
        raise ToolCatalogMismatch(
            f"the server offered a tool set this record does not describe: computed "
            f"{actual}, record says {expected} "
            f"({len(tools)} tools offered, record declares {declared_count}). "
            "The signature may be perfectly valid; this is about the server, not the "
            "document."
        )
    declared_count = _tool_count(catalog)
    if declared_count != len(tools):
        raise ProvenanceError(
            f"tool_catalog.tool_count declares {declared_count} tools, but the matching "
            f"catalog contains {len(tools)}"
        )

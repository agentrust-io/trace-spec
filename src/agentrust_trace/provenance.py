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
import json
import re
import time
from typing import Any

from agentrust_trace.sign import _canonical_bytes, _pubkey_from_jwk, key_to_jwk

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

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PUBLISHER_RE = re.compile(r"^(did:[a-z0-9]+:.+|spiffe://[^/]+/.+)$")


class ProvenanceError(ValueError):
    """A provenance record is malformed, unsigned, or signed by the wrong key."""


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
    """
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
    # this is the anchoring layer.
    canonical = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


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
    if artifact is not None:
        if not artifact.get("package"):
            raise ProvenanceError("artifact.package is required (a Package URL)")
        if not _DIGEST_RE.match(artifact.get("digest", "")):
            raise ProvenanceError(
                "artifact.digest must be a sha256: digest of the entrypoint. For an "
                "interpreted server that is the script, not the interpreter: every such "
                "server on a host shares one interpreter digest."
            )
    if endpoint is not None:
        if not endpoint.get("url"):
            raise ProvenanceError("endpoint.url is required when endpoint is present")
        if not _DIGEST_RE.match(endpoint.get("spki_sha256", "")):
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

    identity: dict[str, Any] = {}
    if artifact is not None:
        identity["artifact"] = dict(artifact)
    if endpoint is not None:
        identity["endpoint"] = dict(endpoint)

    return {
        "format": FORMAT,
        "kind": kind,
        "issued_at": int(issued_at if issued_at is not None else time.time()),
        "identity": identity,
        "publisher": publisher,
        "tool_catalog": {"hash": tool_catalog_hash(tools), "tool_count": len(tools)},
        "attestation": attestation,
    }


def sign_record(record: dict[str, Any], key: Any) -> dict[str, Any]:
    """Sign per TRACE v0.2 §3.2: Ed25519 over the JCS form with the signature absent."""
    payload = {**record, "cnf": {"jwk": key_to_jwk(key)}}
    body = _canonical_bytes({k: v for k, v in payload.items() if k != "signature"})
    import base64

    sig = base64.urlsafe_b64encode(key.sign(body)).rstrip(b"=").decode()
    return {**payload, "signature": sig}


def verify_record(record: dict[str, Any], trusted_jwk: dict[str, Any]) -> None:
    """Verify structure and signature. Raises :class:`ProvenanceError` on failure.

    *trusted_jwk* is required and is never taken from the record. Verifying a
    document against a key it supplies proves only that it is internally
    consistent, which is what a forged record is.

    **This does not check the server.** It checks the paper. Call
    :func:`check_tool_catalog` with the tools the server actually offered.
    """
    import base64

    if record.get("format") != FORMAT:
        raise ProvenanceError(
            f"unknown format {record.get('format')!r}; expected {FORMAT}. An unknown "
            "version is rejected rather than parsed best-effort."
        )
    if record.get("kind") not in KINDS:
        raise ProvenanceError(f"unknown kind {record.get('kind')!r}")
    if not _PUBLISHER_RE.match(str(record.get("publisher", ""))):
        raise ProvenanceError("publisher must be a DID or SPIFFE URI")
    identity = record.get("identity") or {}
    if not identity.get("artifact") and not identity.get("endpoint"):
        raise ProvenanceError("identity carries neither an artifact nor an endpoint")
    catalog = record.get("tool_catalog") or {}
    if not _DIGEST_RE.match(str(catalog.get("hash", ""))):
        raise ProvenanceError("tool_catalog.hash is not a sha256: digest")

    signature = record.get("signature")
    if not signature:
        raise ProvenanceError("record carries no signature")

    embedded = (record.get("cnf") or {}).get("jwk")
    if embedded and embedded != trusted_jwk:
        raise ProvenanceError(
            "the record's embedded key is not the trusted key. A record signed by some "
            "other key is a record about a server somebody else is describing."
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
    """
    actual = tool_catalog_hash(tools)
    expected = (record.get("tool_catalog") or {}).get("hash")
    if actual != expected:
        declared_count = (record.get("tool_catalog") or {}).get("tool_count")
        raise ToolCatalogMismatch(
            f"the server offered a tool set this record does not describe: computed "
            f"{actual}, record says {expected} "
            f"({len(tools)} tools offered, record declares {declared_count}). "
            "The signature may be perfectly valid; this is about the server, not the "
            "document."
        )

"""Bind a C2PA-marked asset to the execution that produced it.

Implements ``spec/content-marking-v1.md``: one assertion, ``com.agentrust-io.trace``,
carrying a hashed reference to a Trust Record.

**This module does not touch media files.** It builds and checks the assertion
payload; embedding it in an asset and signing the C2PA manifest is c2pa tooling's
job, and pretending otherwise would put a media-format dependency inside a
signing library for no benefit.

The function that earns its place is :func:`verify_assertion`. Anyone can write
a JSON object with a URL in it; the hash over the referenced record bytes is what
makes the assertion mean something, and checking it requires the bytes. That is
also the step an implementer skips, so it is a parameter that cannot be omitted
rather than an optional extra.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

__all__ = [
    "ASSERTION_LABEL",
    "ASSERTION_VERSION",
    "ContentMarkingError",
    "RecordMismatch",
    "build_assertion",
    "verify_assertion",
]

#: C2PA reverse-DNS label for an entity-specific assertion.
ASSERTION_LABEL = "com.agentrust-io.trace"
ASSERTION_VERSION = 1

_ALGS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384}
_SUBJECT_RE = re.compile(r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$")
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")


class ContentMarkingError(ValueError):
    """The assertion is malformed, or points at something it does not describe."""


class RecordMismatch(ContentMarkingError):
    """The referenced record is not the record the assertion was built over.

    Its own type because it means something different from a malformed
    assertion: the document is well-formed and the thing it points at changed
    after the asset was signed.
    """


def _digest(data: bytes, alg: str) -> str:
    if alg not in _ALGS:
        raise ContentMarkingError(f"unsupported digest algorithm {alg!r}; use sha256 or sha384")
    return f"{alg}:{_ALGS[alg](data).hexdigest()}"


def build_assertion(
    record_bytes: bytes,
    *,
    url: str,
    alg: str = "sha256",
    anchor: str | None = None,
) -> dict[str, Any]:
    """Build the assertion from the **exact bytes** that will be served at *url*.

    Takes bytes rather than a record object on purpose. A hash computed over a
    re-serialized dict is a hash of something nobody will ever fetch: key order,
    separators and escaping all change the bytes without changing the record, and
    the verifier hashes what the server sends.
    """
    if not isinstance(record_bytes, bytes | bytearray) or not record_bytes:
        raise ContentMarkingError(
            "record_bytes must be the serialized record as it will be served. A hash "
            "over a re-serialized object is a hash of bytes nobody will fetch."
        )
    if not url:
        raise ContentMarkingError("url is required: an assertion with no reference binds nothing")

    import json

    try:
        record = json.loads(record_bytes)
    except ValueError as exc:
        raise ContentMarkingError(f"record_bytes is not JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise ContentMarkingError(
            f"record_bytes must decode to a JSON object, got {type(record).__name__}. A "
            "Trust Record is always an object; anything else is not a record to bind to."
        )

    subject = record.get("subject")
    profile = record.get("eat_profile")
    if not _SUBJECT_RE.match(str(subject or "")):
        raise ContentMarkingError("the record has no SPIFFE or DID subject to bind to")
    if not profile:
        raise ContentMarkingError("the record declares no eat_profile")

    data: dict[str, Any] = {
        "version": ASSERTION_VERSION,
        "record": {"url": url, "hash": _digest(bytes(record_bytes), alg), "alg": alg},
        "subject": subject,
        "eat_profile": profile,
    }
    if anchor:
        data["anchor"] = anchor
    return {"label": ASSERTION_LABEL, "data": data}


def verify_assertion(assertion: dict[str, Any], record_bytes: bytes) -> dict[str, Any]:
    """Check an assertion against the record bytes actually retrieved from its URL.

    *record_bytes* is not optional and has no default. The hash is the binding,
    and an assertion whose hash was never checked is a URL in a file.

    Returns the parsed record on success. Raises :class:`ContentMarkingError` or
    :class:`RecordMismatch` otherwise.

    **This checks the binding, not the whole chain.** The C2PA manifest signature
    and the Trust Record signature are separate checks by separate keys, and this
    function performs neither. A caller that runs only this has confirmed the
    assertion points at the record it claims, and nothing about whether either
    was signed by anyone it trusts.
    """
    import json

    if not isinstance(assertion, dict):
        raise ContentMarkingError("assertion must be an object")
    if assertion.get("label") != ASSERTION_LABEL:
        raise ContentMarkingError(
            f"assertion label {assertion.get('label')!r} is not {ASSERTION_LABEL}"
        )
    data = assertion.get("data")
    if not isinstance(data, dict):
        raise ContentMarkingError("assertion has no data object")
    if data.get("version") != ASSERTION_VERSION:
        raise ContentMarkingError(
            f"unknown assertion version {data.get('version')!r}; expected {ASSERTION_VERSION}. "
            "An unknown version is rejected rather than parsed best-effort."
        )

    ref = data.get("record")
    if not isinstance(ref, dict) or not ref.get("url"):
        raise ContentMarkingError("assertion carries no record reference")
    alg = ref.get("alg", "sha256")
    expected = ref.get("hash")
    if not _DIGEST_RE.match(str(expected or "")):
        raise ContentMarkingError(f"record.hash {expected!r} is not a sha256:/sha384: digest")

    actual = _digest(bytes(record_bytes), alg)
    if actual != expected:
        raise RecordMismatch(
            f"the record at {ref['url']} does not match the assertion: computed {actual}, "
            f"assertion says {expected}. The record changed after the asset was signed, or "
            "the URL is serving a different one."
        )

    record: dict[str, Any]
    try:
        record = json.loads(record_bytes)
    except ValueError as exc:
        raise ContentMarkingError(f"record at {ref['url']} is not JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise ContentMarkingError(
            f"the record at {ref['url']} must decode to a JSON object, got "
            f"{type(record).__name__}. It matched the declared hash, so this is what the "
            "record actually is at that URL, not a mismatch to report as RecordMismatch."
        )
    if record.get("subject") != data.get("subject"):
        raise RecordMismatch(
            f"assertion names subject {data.get('subject')!r} and the record says "
            f"{record.get('subject')!r}: the assertion describes a different record than it "
            "points at"
        )
    if record.get("eat_profile") != data.get("eat_profile"):
        raise RecordMismatch(
            "assertion and record disagree about eat_profile, so the assertion describes a "
            "different record than it points at"
        )
    return record

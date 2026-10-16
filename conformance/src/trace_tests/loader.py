"""Load and normalize trust records from disk."""

from __future__ import annotations

import json
import pathlib
from typing import Any


class LoadError(Exception):
    pass


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise LoadError(f"Invalid JSON: duplicate member name {key!r}")
        obj[key] = value
    return obj


def loads_strict(raw: bytes) -> Any:
    """Parse untrusted JSON bytes, raising only :class:`LoadError`.

    Three things ``json.loads`` does not do on its own:

    * Duplicate member names are refused. ``json.loads`` keeps the last, the
      signature is checked over that, and a consumer whose parser keeps the
      first reads a value no signature covered. RFC 8785 is defined over
      I-JSON (RFC 7493), which forbids duplicates, so such a record has no
      canonical form to verify in the first place.
    * Bytes that are not UTF-8 are a ``LoadError``, not ``UnicodeDecodeError``.
    * Nesting deep enough to exhaust the interpreter stack is a ``LoadError``,
      not ``RecursionError``.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LoadError(f"Invalid JSON: not UTF-8 ({exc})") from exc
    try:
        return json.loads(text, object_pairs_hook=_refuse_duplicates)
    except json.JSONDecodeError as exc:
        raise LoadError(f"Invalid JSON: {exc}") from exc
    except RecursionError as exc:
        raise LoadError("Invalid JSON: nested too deeply to parse") from exc


def load_record(path: str) -> tuple[dict[str, Any], str]:
    """Load a trust record from *path*.

    Returns ``(record_dict, format_string)`` where format is one of:
    - ``"cmcp-runtime"``: cmcp RuntimeClaim envelope (positive marker: ``cmcp_version``)
    - ``"trace"``: canonical TRACE Trust Record (fields at top level)

    Format detection is based on positive structural markers so an attacker cannot
    downgrade a cmcp envelope to the weaker plain-trace path by stripping fields.
    Records that look like partial cmcp envelopes are rejected outright.
    """
    p = pathlib.Path(path)
    if not p.exists():
        raise LoadError(f"File not found: {path}")

    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise LoadError(f"Cannot read {path}: {exc}") from exc

    return parse_record(raw)


def parse_record(raw: bytes) -> tuple[dict[str, Any], str]:
    """:func:`load_record` on bytes already in hand; raises only :class:`LoadError`."""
    data = loads_strict(raw)

    if not isinstance(data, dict):
        raise LoadError("Record must be a JSON object")

    if "cmcp_version" in data:
        if not isinstance(data.get("trace"), dict):
            raise LoadError(
                "Record declares cmcp_version but has no 'trace' object; refusing malformed cmcp-runtime envelope"
            )
        return data, "cmcp-runtime"

    # Envelope-only keys present without cmcp_version: this is a partial/stripped
    # cmcp envelope, not a canonical TRACE record. Reject rather than silently
    # downgrading to the weaker plain-trace verification path.
    # Note: "signature" alone is allowed -- plain TRACE records may carry an
    # embedded Ed25519 signature field (agentrust-trace sign_record() output).
    partial_markers = sorted(k for k in ("trace", "gateway") if k in data)
    if partial_markers:
        raise LoadError(
            f"Record contains cmcp envelope field(s) {partial_markers} but no 'cmcp_version'; "
            "refusing to treat a partial cmcp-runtime envelope as a plain trace record"
        )

    return data, "trace"


def extract_trace(record: dict[str, Any], fmt: str) -> dict[str, Any]:
    """Return the TRACE fields dict from *record*."""
    if fmt == "cmcp-runtime":
        return record["trace"]
    return record

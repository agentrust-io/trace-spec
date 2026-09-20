"""Citation-resolution consumer for ``verify_record`` (spec section 3.1.2).

A Trust Record cites objects outside itself. ``appraisal.policy_ref``,
``runtime.rim_uri`` and ``model.aibom_uri`` are URIs the schema constrains to
``format: uri``, two of which the adapters write, and, until this module,
nothing under ``src/`` read. This module records, per surface, whether a
caller-supplied resolver produced bytes for the cited URI and what those
bytes hashed to. It records resolvability and nothing else.

What this module asserts, and what it does not:

- It asserts no binding. Whether a resolved object binds the record is the
  question agentrust-io/trace-spec#280 holds open. Which ``appraisal.status``
  an unresolvable citation carries is the question agentrust-io/trace-spec#190
  holds open; this module stops short of both. A ``resolved`` outcome says
  bytes were produced and hashed, not that the record is true or that the
  object was in force.
- It never reads ``references[]``. Section 3.1.2 rule 3 binds a verifier not
  to reject a record because an entry in ``references`` cannot be resolved and
  not to treat a resolved reference as attested evidence. The block is a
  pointer, and this module follows none of its pointers; the surfaces it reads
  are record members, not ``references[]`` entries.
- The resolver is caller-supplied only. Section 3.1.2 explains why TR-POL-003
  takes its resolver from the caller and never from the record: a record that
  names its own checker can name one that agrees with it. Nothing in the
  record selects or configures the resolver here; a record carrying a
  resolver hint is read exactly as one that does not.
- ``transparency`` is deferred, not consumed. Its resolution is coordinated
  in agentrust-io/trace-tests#92 and held by spec section 7 open question 3.
  The surface is reported as ``not_attempted`` with that reason, so a reader
  sees a deferral and not an absence.
- The outcome names are not accepted normative text
  (agentrust-io/trace-spec#279). ``resolved``, ``unresolvable`` and
  ``not_attempted`` describe what the resolver did; the specification has
  not adopted them, and a consumer that adopts different names is not
  thereby wrong.
- It runs last in ``verify_record``, after the signature has verified and
  after every check that can raise. A record that fails verification drives
  no resolution, so a caller's resolver never sees a URI from a record that
  was not authenticated.
- It imports no network library. A resolver that reaches the network is the
  caller's, and the import sweep in ``tests/test_revocation_bundle.py``
  holds this module, with every other module at the package's top level, to
  that.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

Outcome = Literal["resolved", "unresolvable", "not_attempted"]
"""What the resolver did for one cited surface."""

Cause = Literal[
    "no_resolver",
    "field_absent",
    "surface_deferred",
    "resolver_raised",
    "resolver_returned_non_bytes",
]
"""Why a surface reports anything other than ``resolved``."""

#: The citation surfaces, in report order. The second member is the deferral
#: reason for a surface this module does not consume, or ``None`` for one it does.
SURFACES: tuple[tuple[str, str | None], ...] = (
    ("appraisal.policy_ref", None),
    ("runtime.rim_uri", None),
    ("model.aibom_uri", None),
    (
        "transparency",
        "coordinated in agentrust-io/trace-tests#92; spec section 7 open question 3",
    ),
)


@dataclass(frozen=True)
class CitationCheck:
    """What the resolver did for one surface, and the facts a second run needs.

    ``evidence`` is JSON-serialisable by construction: its values are the URI as
    the record carries it, a hex digest, a byte count, or a class name, so it can
    be retained beside the record and compared against a conformance vector's
    ``expected`` block.
    """

    outcome: Outcome
    cause: Cause | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


def _lookup(record: dict[str, Any], path: str) -> Any:
    """The value at a dotted path, or ``None`` when a step is missing or not an object."""
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def check_citations(
    record: dict[str, Any], resolver: Callable[[str], bytes] | None
) -> dict[str, CitationCheck]:
    """Report, per surface in ``SURFACES`` order, whether the cited URI resolved.

    ``resolver`` takes the URI and returns the object's bytes. It is the
    caller's: nothing in ``record`` chooses it. ``None`` means no resolver was
    supplied, and every consumed surface then reports ``not_attempted`` with
    cause ``no_resolver``. A surface whose field is absent or ``null`` reports
    ``not_attempted`` with cause ``field_absent``. A deferred surface reports
    ``not_attempted`` with cause ``surface_deferred`` and the reason.

    A resolver that raises, or returns something other than ``bytes``, yields
    ``unresolvable`` with the cause named and, in the evidence, the exception's
    class name when it raised or the returned value's type name when it did
    not, never any message text; the exception does not propagate.
    Inability to resolve is not evidence of a defect in the record. Bytes yield
    ``resolved`` with the URI, the SHA-256 hex digest over exactly the returned
    bytes, and their count. On the ``verify_record`` path the schema has already
    required each surface to be a string; a direct call with a non-string value
    at a surface places that value in ``evidence["uri"]`` as given.

    Raises ``ValueError`` when ``record`` is not a JSON object or ``resolver`` is
    neither callable nor ``None``. Those are the caller's mistakes, refused at
    entry rather than reported as an outcome of the record.
    """
    if not isinstance(record, dict):
        raise ValueError(f"record must be a JSON object, got {type(record).__name__}")
    if resolver is not None and not callable(resolver):
        raise ValueError("resolver must be callable or None")

    out: dict[str, CitationCheck] = {}
    for path, deferred in SURFACES:
        if deferred is not None:
            out[path] = CitationCheck(
                outcome="not_attempted",
                cause="surface_deferred",
                evidence={"reason": deferred},
            )
            continue
        if resolver is None:
            out[path] = CitationCheck(outcome="not_attempted", cause="no_resolver")
            continue
        uri = _lookup(record, path)
        if uri is None:
            out[path] = CitationCheck(outcome="not_attempted", cause="field_absent")
            continue
        try:
            value = resolver(uri)
        except Exception as exc:
            out[path] = CitationCheck(
                outcome="unresolvable",
                cause="resolver_raised",
                evidence={"uri": uri, "exception": type(exc).__name__},
            )
            continue
        if not isinstance(value, bytes):
            out[path] = CitationCheck(
                outcome="unresolvable",
                cause="resolver_returned_non_bytes",
                evidence={"uri": uri, "returned": type(value).__name__},
            )
            continue
        out[path] = CitationCheck(
            outcome="resolved",
            evidence={
                "uri": uri,
                "sha256": hashlib.sha256(value).hexdigest(),
                "bytes": len(value),
            },
        )
    return out

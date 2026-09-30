#!/usr/bin/python3
"""Fuzz the two canonicalizations: JCS for signatures, anchor form for digests.

Input: JSON text. ``sign._canonical_bytes`` is the signature pre-image of spec
section 3.2.2 and ``sign.anchor_bytes`` is registry-anchor-v1 section 1.

Properties, stronger than "does not crash":

- Round trip. Parsing either output must reproduce the input, up to JSON's
  single number type: a float whose shortest form has no fraction re-parses as
  an int, which is correct RFC 8785 output. A canonicalization that silently
  drops or merges a member still produces bytes somebody signs.
- Determinism. The same value canonicalizes to the same bytes twice.
- Declared refusals only. JCS refuses with ``rfc8785.CanonicalizationError``
  (a ``ValueError``) and the anchor form with ``UnanchorableValue``.
"""

import json
import math
import sys

import atheris

with atheris.instrument_imports():
    import rfc8785

    from agentrust_trace.sign import UnanchorableValue, _canonical_bytes, anchor_bytes


def _json_equal(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b, strict=True))
    return type(a) is type(b) and a == b


def _has_nonfinite(value) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, dict):
        return any(_has_nonfinite(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_nonfinite(v) for v in value)
    return False


def TestOneInput(data: bytes) -> None:
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):
        return
    try:
        if not isinstance(value, dict) or _has_nonfinite(value):
            # The signature pre-image is always an object, and Python's json
            # accepts NaN and Infinity, which have no JSON form to return to.
            return
    except RecursionError:
        return
    try:
        jcs = _canonical_bytes(value)
    except (rfc8785.CanonicalizationError, RecursionError):
        # RecursionError: nesting deeper than the interpreter stack. The
        # verifiers refuse such documents before they reach this function.
        jcs = None
    if jcs is not None:
        assert _json_equal(json.loads(jcs), value), f"JCS output did not round-trip: {jcs!r}"
        assert _canonical_bytes(value) == jcs, "JCS is not deterministic"
    try:
        anchored = anchor_bytes(value)
    except (UnanchorableValue, RecursionError):
        return
    assert _json_equal(json.loads(anchored), value), f"anchor form did not round-trip: {anchored!r}"
    assert anchor_bytes(value) == anchored, "anchor form is not deterministic"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

"""Vector 24 exists to catch one specific mistake; this file proves it does.

`test_delegation_vectors.py::test_vector_reaches_its_declared_outcome` already
runs `24-parent-key-supplementary-plane.json` through the reference walk and
checks it comes back `verified`, the same as every other vector in the loop.
That is necessary but not sufficient: a vector can reach the right
classification for a reason that has nothing to do with what it was built to
test. This file checks the thing itself, the same way
`test_canonicalization_boundary.py::test_declared_divergence_is_the_measured_divergence`
does for the section 3.2.2 signature preimage: it recomputes the divergence
rather than trusting the vector's docstring to still describe it.

Section 3.1.3's near-miss is specific to *this* preimage, the delegation chain
digest, and not to the one `test_canonicalization_boundary.py` already covers.
Both are RFC 8785 over a record, but over a different one: the record's own
signature covers itself with `signature` absent; the chain digest covers a
*parent* record with `signature` present, and is computed by whoever is
walking a delegation chain rather than by whoever is verifying a lone record's
signature. A canonicalizer that is correct for one call site and reused
carelessly for the other has no vector to catch it before this one.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from tests.test_delegation_vectors import _digest, verify_chain

VECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "delegation-link"
    / "24-parent-key-supplementary-plane.json"
)


def _load() -> dict[str, Any]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def _code_point_digest(record: dict[str, Any], alg: str = "sha256") -> str:
    """The rejected canonicalizer: `json.dumps(sort_keys=True)`.

    Python's `sorted()`, and therefore `sort_keys=True`, orders strings by code
    point. RFC 8785 section 3.2.3 orders by UTF-16 code unit. The two agree
    everywhere except where a key holds a character outside the Basic
    Multilingual Plane, which is exactly what this record's `cnf.jwk` was
    built to carry.
    """
    body = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return f"{alg}:" + hashlib.new(alg, body).hexdigest()


def test_the_root_record_has_the_key_pair_this_vector_needs() -> None:
    """Sanity check on the fixture itself, before trusting anything it proves.

    Both members must be present, and one of them must sit outside the Basic
    Multilingual Plane, or this vector is testing nothing.
    """
    vector = _load()
    root = next(r for r in vector["records"] if "delegation" not in r)
    keys = root["cnf"]["jwk"].keys()
    non_bmp = [k for k in keys if any(ord(c) > 0xFFFF for c in k)]
    bmp_only = [
        k
        for k in keys
        if k not in ("kty", "crv", "x", "y", "kid") and k not in non_bmp
    ]
    assert non_bmp, "no cnf.jwk member key is outside the Basic Multilingual Plane"
    assert bmp_only, "no cnf.jwk member key is BMP-only, so there is nothing to compare against"


def test_utf16_and_code_point_order_disagree_on_this_record() -> None:
    """The premise. If this ever stopped holding, the vector would stop proving
    anything and every other assertion here would be vacuous."""
    vector = _load()
    root = next(r for r in vector["records"] if "delegation" not in r)
    assert _digest(root, "sha256") != _code_point_digest(root), (
        "RFC 8785 and json.dumps(sort_keys=True) computed the same digest for "
        "the root record: the supplementary-plane key no longer discriminates "
        "the two canonicalizers, and this vector needs a replacement."
    )


def test_the_declared_link_is_the_rfc8785_digest_not_the_code_point_one() -> None:
    """The leaf's `delegation.parent_record_hash` must be reachable only by the
    conformant canonicalizer. If it matched the code-point digest instead (or
    both), a non-conformant implementation would resolve the link by accident
    and this vector would certify exactly the mistake it exists to catch."""
    vector = _load()
    root = next(r for r in vector["records"] if "delegation" not in r)
    leaf = next(r for r in vector["records"] if "delegation" in r)
    declared = leaf["delegation"]["parent_record_hash"]
    assert declared == _digest(root, "sha256")
    assert declared != _code_point_digest(root)


def test_a_code_point_canonicalizer_cannot_resolve_the_link() -> None:
    """The failure mode section 3.1.3 predicts, reproduced directly: a verifier
    that indexes parent records by `json.dumps(sort_keys=True)` digests instead
    of RFC 8785 ones builds an index that does not contain the key the leaf is
    looking for. Vector 04 (`parent-record-absent`) is what that looks like
    from the walk's side; this is why it would happen here even though every
    record is present."""
    vector = _load()
    root = next(r for r in vector["records"] if "delegation" not in r)
    leaf = next(r for r in vector["records"] if "delegation" in r)
    code_point_index = {_code_point_digest(root): root}
    assert leaf["delegation"]["parent_record_hash"] not in code_point_index


def test_the_reference_walk_verifies_this_vector() -> None:
    """The reference walk in `test_delegation_vectors.py` uses `rfc8785.dumps`,
    is therefore conformant, and must reach the outcome the vector declares.
    Restated here rather than left to the parametrised loop alone, so a reader
    of this file sees the positive and negative cases side by side."""
    vector = _load()
    result = verify_chain(vector)
    assert result.classification == "verified"
    assert not result.failures
    assert not result.warnings

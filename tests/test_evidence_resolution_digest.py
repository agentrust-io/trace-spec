"""ER01: object identity uses the existing JCS digest, not downloaded JSON bytes."""

import copy
import hashlib
import json

import pytest

from prototype.verifier_token import canonical_digest


@pytest.mark.parametrize("encoded", [
    '{"packet":{"name":"synthetic","count":1},"version":1}',
    '{\n  "version": 1,\n  "packet": { "count": 1, "name": "synthetic" }\n}',
    '{"version":1.0,"packet":{"name":"synthetic","count":1.0}}',
], ids=["compact", "whitespace-and-order", "equivalent-numbers"])
def test_er01_canonical_identity_survives_encoding_but_not_member_change(encoded):
    packet = json.loads(encoded)
    # Pin the expected preimages without importing the production serializer.
    canonical = b'{"packet":{"count":1,"name":"synthetic"},"version":1}'
    changed_canonical = b'{"packet":{"count":2,"name":"synthetic"},"version":1}'
    expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
    assert canonical_digest(packet) == expected
    assert "sha256:" + hashlib.sha256(encoded.encode()).hexdigest() != expected

    changed = copy.deepcopy(packet)
    changed["packet"]["count"] = 2
    assert canonical_digest(changed) == "sha256:" + hashlib.sha256(changed_canonical).hexdigest()
    assert canonical_digest(changed) != expected
    assert canonical_digest(packet) == expected

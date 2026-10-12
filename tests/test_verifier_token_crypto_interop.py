"""Cross-language crypto agreement; not independent semantic conformance."""

import copy
import json
import os
import shutil
import subprocess

import cbor2
import pytest

from tests.test_verifier_token_profile import ROOT, VECTORS, g, unb64

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node/OpenSSL crypto oracle unavailable")


def oracle(path):
    result = subprocess.run(
        [
            NODE,
            str(ROOT / "tools/verifier_token_crypto_oracle.mjs"),
            str(path),
            str(VECTORS / "01-valid.json"),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("path", sorted(VECTORS.glob("*.json")), ids=lambda p: p.stem)
def test_node_verifies_exact_portable_signature_bytes(path):
    result = oracle(path)
    assert result["signature_valid_under_fixed_anchor"] == (not path.name.startswith("13-"))
    anchor = json.loads((VECTORS / "01-valid.json").read_text(encoding="utf-8"))
    assert result["exact_manifest_digest"] == anchor["token"]["manifest"]["digest"]


@pytest.mark.parametrize("changed_part", [2, 3], ids=["payload", "signature"])
def test_node_rejects_signature_and_payload_tampering(tmp_path, changed_part):
    vector = json.loads((VECTORS / "01-valid.json").read_text(encoding="utf-8"))
    envelope = list(cbor2.loads(unb64(vector["envelope_b64"])).value)
    damaged = bytearray(envelope[changed_part])
    damaged[-1] ^= 1
    envelope[changed_part] = bytes(damaged)
    modified = copy.deepcopy(vector)
    modified["envelope_b64"] = g.b64(cbor2.dumps(cbor2.CBORTag(18, envelope), canonical=True))
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(modified), encoding="utf-8")
    assert oracle(path)["signature_valid_under_fixed_anchor"] is False

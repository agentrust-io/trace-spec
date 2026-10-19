"""Cross-language verifier alignment for CMCP runtime signatures, anchor entries, and citations."""

from __future__ import annotations

import base64
import importlib
import json
import pathlib
import sys
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONFORMANCE_SRC = str(ROOT / "conformance" / "src")
if CONFORMANCE_SRC not in sys.path:
    sys.path.insert(0, CONFORMANCE_SRC)

rfc8785: Any = importlib.import_module("rfc8785")
tr_sig: Any = importlib.import_module("trace_tests.modules.tr_sig")
result_mod: Any = importlib.import_module("trace_tests.result")
Status: Any = result_mod.Status


def _b64url_decode_canonical(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    reencoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    assert reencoded == value, "value is not canonical unpadded base64url"
    return raw


def test_valid_cmcp_runtime_vector_has_valid_ed25519_signature() -> None:
    vector_path = ROOT / "conformance" / "tests" / "vectors" / "valid_cmcp_runtime.json"
    vec: dict[str, Any] = json.loads(vector_path.read_text(encoding="utf-8"))

    sig = vec["signature"]
    assert isinstance(sig, str)
    assert sig != "unsigned-test-vector"

    sig_bytes = _b64url_decode_canonical(sig)
    assert len(sig_bytes) == 64

    pub_x = vec["trace"]["cnf"]["jwk"]["x"]
    pub_bytes = _b64url_decode_canonical(pub_x)
    assert len(pub_bytes) == 32

    canonical_payload: bytes = rfc8785.dumps(
        {k: v for k, v in vec.items() if k != "signature"}
    )
    Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, canonical_payload)

    findings = tr_sig.check(vec["trace"], vec, "cmcp-runtime", level=1)
    assert findings, "expected TR-SIG findings for valid_cmcp_runtime.json"
    by_code = {f.code: f.status for f in findings}
    assert by_code.get("TR-SIG-001") is Status.PASS
    for code in ("TR-SIG-001", "TR-SIG-002", "TR-SIG-003", "TR-SIG-004"):
        if code in by_code:
            assert by_code[code] is Status.PASS


def test_registry_anchor_v1_section_4_allows_optional_entry_fields() -> None:
    spec_path = ROOT / "spec" / "registry-anchor-v1.md"
    text = spec_path.read_text(encoding="utf-8")
    section_4 = text.split("## 4. Registry entry", 1)[1].split("## 5. Inclusion proof", 1)[0]

    assert "with exactly these fields" not in section_4
    assert "carrying these required fields" in section_4
    assert "canonicalization_id" in section_4
    assert "mmr_checkpoint" in section_4


def test_citation_resolution_readme_documents_harness_keyerror_exception() -> None:
    readme_path = ROOT / "examples" / "citation-resolution" / "README.md"
    text = readme_path.read_text(encoding="utf-8")

    assert "expected.citations[*].evidence.exception" in text
    assert "type(exc).__name__" in text
    assert "table[uri]" in text
    assert "Go, Rust, or TypeScript" in text

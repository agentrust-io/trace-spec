"""Independent one-leaf oracle pins the declared experimental projection."""
import pytest

pytest.importorskip("httpx", reason="cross-repository gateway test")
pytest.importorskip("cmcp_runtime.manifest_catalog", reason="needs cMCP TRACE gate")

import hashlib

import rfc8785

from cmcp_runtime.manifest_catalog import manifest_catalog_binding
from tests.test_cmcp_trace_gate import deployment
from tests.test_verifier_token_profile import fixture

__all__ = ["deployment", "fixture"]


def test_merkle_root_is_not_sealed_catalog_digest(deployment):
    # The projection ruled on agent-manifest#340: schema_hash over
    # JCS({"input_schema", "output_schema"}), description_hash over JCS(description).
    catalog = deployment["proxy"]._catalog
    projected = manifest_catalog_binding(catalog)
    schema = rfc8785.dumps({"input_schema": {}, "output_schema": None})
    leaf = (
        b"read\x00"
        + hashlib.sha256(schema).digest()
        + hashlib.sha256(rfc8785.dumps("read")).digest()
    )
    expected = "sha256:" + hashlib.sha256(b"\x00" + leaf).hexdigest()
    assert projected["catalog_hash"] == expected
    assert projected["catalog_hash"] != catalog.catalog_hash

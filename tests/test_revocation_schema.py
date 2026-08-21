"""The revocation schema pair must hold together (spec §3.2.3, issue #67).

Two files that reference each other by `$id` are one artifact with a seam down
the middle, and nothing else in the repository reads them yet, so a broken
`$ref` or a drifted field name would ship unnoticed until the first
implementation tried to validate against them.

The assertions worth making mechanically are the ones that encode the design
decisions rather than the shape: that the boundary field is an entry ID, that no
timestamp is load-bearing, and that a statement carries its own signer
separately from the bundle's.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schema"
STATEMENT = SCHEMA_DIR / "trace-revocation.json"
BUNDLE = SCHEMA_DIR / "trace-revocation-bundle.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def statement() -> dict:
    return _load(STATEMENT)


@pytest.fixture(scope="module")
def bundle() -> dict:
    return _load(BUNDLE)


def test_both_schemas_are_draft_2020_12(statement, bundle):
    for schema in (statement, bundle):
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_bundle_items_reference_the_statement_id(statement, bundle):
    """The seam. A renamed `$id` on one side silently unhooks the other."""
    assert bundle["properties"]["statements"]["items"]["$ref"] == statement["$id"]


def test_claim_type_is_pinned(statement, bundle):
    assert statement["properties"]["type"]["const"] == "TraceRevocation/1.0"
    assert bundle["properties"]["type"]["const"] == "TraceRevocationBundle/1.0"


def test_the_boundary_is_an_entry_id_and_is_required(statement):
    """§3.2.3: the boundary is a log entry ID because a compromised key signs
    the timestamp it would otherwise be judged against."""
    assert "last_valid_entry_id" in statement["required"]
    assert statement["properties"]["last_valid_entry_id"]["type"] == "string"


def test_no_timestamp_is_required_on_a_statement(statement):
    """`revoked_at` exists and is informational. Requiring it would invite an
    implementation to treat it as the boundary, which is the defect §3.2.3 is
    about."""
    assert "revoked_at" not in statement["required"]
    assert "informational" in statement["properties"]["revoked_at"]["description"].lower()


def test_log_id_is_required_on_both(statement, bundle):
    """Entry IDs from different logs are not comparable, so neither side may be
    silent about which log it means."""
    assert "log_id" in statement["required"]
    assert "log_id" in bundle["required"]


def test_statement_and_bundle_carry_separate_signers(statement, bundle):
    """A bundle assembler authenticates the set and its horizon. It must not be
    able to add a revocation it was not authorised to issue, which is why each
    statement keeps its own signature and signer."""
    assert "revocation_key_id" in statement["required"]
    assert "sig" in statement["required"]
    assert "bundle_key_id" in bundle["required"]
    assert "sig" in bundle["required"]


def test_bundle_horizon_is_required(bundle):
    """An expired bundle is not a pass, so there has to be something to expire."""
    assert "valid_until" in bundle["required"]
    assert "issued_at" in bundle["required"]


def test_signature_algorithms_match_the_spec_set(statement, bundle):
    """§3.2.1 allows ES256, ES384 and EdDSA. A schema admitting more would let a
    conforming document carry an algorithm the spec does not."""
    expected = {"ed25519", "ES256", "ES384"}
    for schema in (statement, bundle):
        assert set(schema["properties"]["sig"]["properties"]["alg"]["enum"]) == expected


def test_neither_schema_admits_unknown_fields(statement, bundle):
    """Revocation is the one place where a field an implementation invents could
    read as narrowing the revocation, so both are closed."""
    for schema in (statement, bundle):
        assert schema["additionalProperties"] is False


def test_an_empty_statement_list_is_representable(bundle):
    """A bundle asserting no known revocations is different from having no
    bundle, and the schema has to be able to say the first one."""
    items = bundle["properties"]["statements"]
    assert items.get("minItems") is None

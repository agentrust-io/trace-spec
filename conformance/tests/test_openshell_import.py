"""Conformance coverage for records imported from an OpenShell control plane."""

from __future__ import annotations

import copy
import time

import jsonschema
import pytest

from trace_tests.result import Status
from trace_tests.runner import run


def _failures(results):
    return [
        finding
        for findings in results.values()
        for finding in findings
        if finding.status is Status.FAIL
    ]


def test_openshell_import_fails_level0_only_on_its_verifier_string(schema, load_vector) -> None:
    """The one accepted delta, named — and everything else still guarded.

    This record is schema-valid and was Level 0 conformant until TR-APR
    landed. Its `appraisal.verifier` is `"nvidia-openshell/0.3.0"`, a product
    and version string rather than a URI, so it has no scheme and is a
    relative reference; `format: "uri"` in the packaged schema is an
    annotation and does not reject it. TR-APR-002 does, at every level.

    That is the accepted scope of trace-tests#63 doing its work rather than a
    regression, so the assertion is an exact set rather than a relaxation: any
    failure here other than TR-APR-002 still fails this test.
    """
    record = load_vector("valid_openshell_import.json")
    record["iat"] = int(time.time())

    jsonschema.validate(record, schema)
    assert {f.code for f in _failures(run(record, "trace", 0))} == {"TR-APR-002"}


def test_imported_openshell_evidence_cannot_claim_hardware(schema, load_vector) -> None:
    record = copy.deepcopy(load_vector("valid_openshell_import.json"))
    record["runtime"]["platform"] = "intel-tdx"

    with pytest.raises(jsonschema.exceptions.ValidationError):
        jsonschema.validate(record, schema)


def test_openshell_import_does_not_require_transparency_at_level0(schema, load_vector) -> None:
    record = load_vector("valid_openshell_import.json")
    assert "transparency" not in record
    jsonschema.validate(record, schema)

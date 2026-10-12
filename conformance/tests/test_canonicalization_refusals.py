"""A record JCS has no canonical form for must be refused, not raise.

``tr_sig`` verifies over RFC 8785 canonical bytes, which is what specification §3.2.2
requires. A value RFC 8785 cannot serialize therefore has no signing input, and
``rfc8785.dumps`` says so by raising. ``runner.run`` calls every module with no ``try``,
so until this was fixed that exception left the module and ended the run: the caller got
a traceback where a verdict belongs, exiting 1, which is also what an honest FAIL exits.

Three classes of value do it, and all three are ordinary JSON that ``json.loads`` accepts
and ``load_record`` has no reason to refuse: an integer outside the JCS safe range, a
non-finite float, and a string carrying a lone surrogate. The vectors here are files on
disk read through ``load_record``, because reachability from a file rather than only from
a library caller is the whole reason this matters.

``tests/test_modules_never_raise.py`` states the contract these violate and could not see
them: all nine values its ``JUNK`` tuple carried serialize through ``rfc8785`` without
complaint, so no number of runs of it could reach a module raising while canonicalizing.
Its tuple now carries the three, which is the general guard. This file is the specific
one, and it asserts the verdict rather than only the absence of an exception, because a
module that returned nothing at all would satisfy the general guard.
"""
from __future__ import annotations

import json
import pathlib

import pytest
import rfc8785

from trace_tests.loader import load_record
from trace_tests.result import Status
from trace_tests.runner import run

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors"

#: vector, the code its outcome is published under, the rfc8785 error it must provoke.
#: The code differs by call site: a cmcp claim reports its signature outcome under
#: TR-SIG-001 and a plain TRACE record under TR-SIG-005, per docs/error-codes.md.
CASES = [
    ("invalid_canonical_integer_out_of_range.json", "TR-SIG-001", rfc8785.IntegerDomainError),
    ("invalid_canonical_non_finite_float.json", "TR-SIG-001", rfc8785.FloatDomainError),
    ("invalid_canonical_lone_surrogate.json", "TR-SIG-001", rfc8785.CanonicalizationError),
    ("invalid_canonical_plain_trace.json", "TR-SIG-005", rfc8785.IntegerDomainError),
]


@pytest.mark.parametrize(("filename", "code", "error"), CASES)
def test_the_vector_still_provokes_the_error_it_was_written_for(
    filename: str, code: str, error: type[Exception]
) -> None:
    """Checked before the verdict, because a vector edited into serializability would
    leave every assertion below passing over a record that exercises nothing."""
    record = json.loads((VECTORS / filename).read_text(encoding="utf-8"))
    body = {k: v for k, v in record.items() if k != "signature"}
    with pytest.raises(error):
        rfc8785.dumps(body)


@pytest.mark.parametrize(("filename", "code", "error"), CASES)
def test_a_record_with_no_canonical_form_fails_rather_than_raising(
    filename: str, code: str, error: type[Exception]
) -> None:
    record, fmt = load_record(str(VECTORS / filename))

    results = run(record, fmt, 0)

    findings = [f for f in results.get("TR-SIG", []) if f.code == code]
    assert findings, f"nothing published under {code}: {results.get('TR-SIG')}"
    assert any(f.status is Status.FAIL for f in findings), (
        f"{filename} has no canonical form, so no signature over it can verify; "
        f"{code} is {[f.status for f in findings]}"
    )


@pytest.mark.parametrize(("filename", "code", "error"), CASES)
def test_the_finding_names_the_cause_and_not_a_signature_mismatch(
    filename: str, code: str, error: type[Exception]
) -> None:
    """Two different facts, and a consumer acting on the wrong one goes looking for a key
    problem that is not there. The bytes a signature would be taken over do not exist."""
    record, fmt = load_record(str(VECTORS / filename))

    findings = [f for f in run(record, fmt, 0).get("TR-SIG", []) if f.code == code]
    message = " ".join(f.message for f in findings)

    assert "canonical form" in message, message
    assert "verification failed" not in message, message


def test_the_control_still_verifies_normally() -> None:
    """Without this, a change that made TR-SIG fail on everything would pass the three
    tests above while destroying the module."""
    record, fmt = load_record(str(VECTORS / "valid_cmcp_runtime.json"))

    findings = [f for f in run(record, fmt, 0).get("TR-SIG", []) if f.code == "TR-SIG-001"]

    assert findings, "the control publishes no TR-SIG-001 at all"
    assert all("canonical form" not in f.message for f in findings), (
        f"the control record canonicalizes; nothing should report otherwise: {findings}"
    )

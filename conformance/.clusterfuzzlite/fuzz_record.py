#!/usr/bin/python3
"""Fuzz the record loader and every conformance module behind it.

Input is the bytes of a trust-record file, exactly what ``trace-tests verify
--record`` reads. The property is the suite's documented contract:
``parse_record`` raises ``LoadError`` or returns a record, and every level of
``runner.run``, the accounting path ``_run_levels`` and all three report
renderers then return a verdict for that record. Anything else escaping is a
traceback where a conformance result belongs, which is what
``tests/test_modules_never_raise.py`` pins for known shapes and this target
looks for in unknown ones.
"""
import sys

import atheris

with atheris.instrument_imports():
    from trace_tests import report
    from trace_tests.loader import LoadError, parse_record
    from trace_tests.runner import _run_levels, run

_RECEIPT = {
    "leaf_index": 0,
    "leaf_count": 1,
    "audit_path": [],
    "merkle_root": "sha256:" + "0" * 64,
}


def _resolver(uri: str) -> bytes:
    # Deterministic, so TR-POL-003 reaches its digest comparison rather than
    # stopping at "no resolver".
    return uri.encode("utf-8", "surrogatepass")


def TestOneInput(data: bytes) -> None:
    try:
        record, fmt = parse_record(data)
    except LoadError:
        return

    for level in (0, 1, 2):
        run(
            record,
            fmt,
            level,
            expected_nonce="fuzz-nonce",
            receipt=_RECEIPT,
            policy_resolver=_resolver,
        )

    execution = _run_levels(
        record,
        fmt,
        (0, 1, 2),
        expected_nonce="fuzz-nonce",
        receipt=_RECEIPT,
        policy_resolver=_resolver,
    )
    built = report._build_from_execution(
        record=record,
        record_path="fuzz.json",
        execution=execution,
        suite_version="fuzz",
        library_version=None,
        generated_at="1970-01-01 00:00 UTC",
    )
    report.to_json(built)
    report.to_html(built)
    report.badge_svg(built)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

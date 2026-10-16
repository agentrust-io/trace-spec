#!/usr/bin/python3
"""Fuzz the C2PA content-marking assertion checker.

Input: one mode byte, then a JSON object ``{"assertion": ..., "record": ...}``
where ``record`` is the text served at the assertion's URL. With mode bit 0
set, the assertion is rebuilt over those exact bytes with ``build_assertion``,
so the fuzzer reaches the record parsing and subject and profile comparison
that only run once the hash matches.

Property: ``verify_assertion`` and ``build_assertion`` document
``ContentMarkingError`` (``RecordMismatch`` is a subclass). Both the assertion
and the served record come from whoever controls the asset and the URL, so any
other exception is that party crashing the checker.
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from agentrust_trace.content_marking import (
        ContentMarkingError,
        build_assertion,
        verify_assertion,
    )


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, body = data[0], data[1:]
    try:
        case = json.loads(body)
    except (ValueError, RecursionError):
        return
    if not isinstance(case, dict):
        return
    record_text = case.get("record")
    if not isinstance(record_text, str):
        return
    try:
        record_bytes = record_text.encode("utf-8")
    except UnicodeEncodeError:
        return
    assertion = case.get("assertion")
    if mode & 1 and isinstance(assertion, dict):
        data_obj = assertion.get("data")
        ref = data_obj.get("record") if isinstance(data_obj, dict) else None
        url = ref.get("url") if isinstance(ref, dict) else None
        try:
            assertion = build_assertion(
                record_bytes,
                url=url if isinstance(url, str) else "https://records.example/r.json",
                alg="sha384" if mode & 2 else "sha256",
                anchor=assertion.get("anchor") if mode & 4 else None,
            )
        except ContentMarkingError:
            return
    try:
        record = verify_assertion(assertion, record_bytes)
    except ContentMarkingError:
        return
    assert isinstance(record, dict), type(record)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

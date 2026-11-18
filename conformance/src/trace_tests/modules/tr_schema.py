"""Whole-record validation against the packaged TRACE schema."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from trace_tests.result import Finding, Status

_SCHEMA_NAME = "trace-claim.json"


def _schema_resource() -> Traversable:
    """Return the installed schema, or its source-checkout location during development."""
    packaged = resources.files("trace_tests").joinpath("schemas").joinpath(_SCHEMA_NAME)
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[3] / "schemas" / _SCHEMA_NAME


@lru_cache(maxsize=1)
def _validator() -> Any:
    with _schema_resource().open("r", encoding="utf-8") as stream:
        schema = json.load(stream)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _pointer(parts: Any) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else "/"


def _error_key(error: ValidationError) -> tuple[str, str, str]:
    return (
        _pointer(error.absolute_path),
        _pointer(error.absolute_schema_path),
        error.message,
    )


def _error_detail(error: ValidationError) -> str:
    # jsonschema includes the rejected value in most messages. Findings are copied
    # into shareable reports, so only schema-owned required-member names are safe to quote.
    if error.validator == "required":
        return error.message
    return (
        f"{error.validator!s} constraint at "
        f"{_pointer(error.absolute_schema_path)} failed"
    )


def check(trace: dict[str, Any]) -> list[Finding]:
    """Return a deterministic finding for every whole-record schema violation."""
    try:
        errors = sorted(_validator().iter_errors(trace), key=_error_key)
    except (OSError, UnicodeError, json.JSONDecodeError, SchemaError):
        return [
            Finding(
                "TR-ENV-006",
                Status.FAIL,
                "TR-ENV-006: packaged TRACE schema is unavailable or invalid; "
                "whole-record validation could not be completed",
            )
        ]
    except RecursionError:
        return [
            Finding(
                "TR-ENV-006",
                Status.FAIL,
                "TR-ENV-006: record nests too deeply for whole-record schema validation",
            )
        ]

    if not errors:
        return [
            Finding(
                "TR-ENV-006",
                Status.PASS,
                "complete record matches the packaged TRACE schema",
            )
        ]

    return [
        Finding(
            "TR-ENV-006",
            Status.FAIL,
            # Instance paths can contain attacker-supplied map keys, including
            # JWK extension names. Only schema-owned locations belong in a
            # report that may be shared without the original record.
            f"TR-ENV-006: schema violation: {_error_detail(error)}",
        )
        for error in errors
    ]

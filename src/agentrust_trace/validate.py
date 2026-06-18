from __future__ import annotations

import importlib.resources
import json
from functools import lru_cache
from typing import Any, cast

import jsonschema


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    ref = importlib.resources.files("agentrust_trace") / "schema" / "trace-v0.1.json"
    return cast(dict[str, Any], json.loads(ref.read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(_schema(), format_checker=jsonschema.FormatChecker())


# Canonical schema exposed for downstream tooling that needs the raw dict.
SCHEMA: dict[str, Any] = _schema()


def validate_json(record: dict[str, Any]) -> None:
    """Validate *record* against the canonical TRACE v0.1 JSON Schema.

    Raises :class:`jsonschema.ValidationError` on the first violation found.
    Use :func:`iter_errors` for all violations.
    """
    _validator().validate(record)


def iter_errors(record: dict[str, Any]) -> list[jsonschema.exceptions.ValidationError]:
    """Return all JSON Schema violations for *record* (empty list if valid)."""
    return list(_validator().iter_errors(record))

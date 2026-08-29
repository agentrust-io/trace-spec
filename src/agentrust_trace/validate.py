from __future__ import annotations

import copy
import importlib.resources
import json
from functools import lru_cache
from typing import Any, cast

import jsonschema


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    ref = importlib.resources.files("agentrust_trace") / "schema" / "trace-v0.2.json"
    return cast(dict[str, Any], json.loads(ref.read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(_schema(), format_checker=jsonschema.FormatChecker())


#: Canonical schema exposed for downstream tooling that needs the raw dict.
#:
#: A copy, deliberately. `_schema()` is `lru_cache`d and `_validator()` is built over
#: whatever it returns, so this name used to be the live object the validator reads.
#: Mutating it, which is the ordinary thing to do with a dict handed over to adapt,
#: silently reconfigured `validate_json`, `iter_errors` and the structural gate inside
#: `sign.verify_record`, process-wide, for every later call.
SCHEMA: dict[str, Any] = copy.deepcopy(_schema())


def validate_json(record: dict[str, Any]) -> None:
    """Validate *record* against the canonical TRACE v0.2 JSON Schema.

    Raises :class:`jsonschema.ValidationError` on the first violation found.
    Use :func:`iter_errors` for all violations.
    """
    _validator().validate(record)


def iter_errors(record: dict[str, Any]) -> list[jsonschema.exceptions.ValidationError]:
    """Return all JSON Schema violations for *record* (empty list if valid)."""
    return list(_validator().iter_errors(record))

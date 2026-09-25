from __future__ import annotations

import copy
import importlib.resources
import json
import re
from collections.abc import Iterator
from functools import lru_cache
from ipaddress import IPv6Address
from typing import Any, cast

import jsonschema
from jsonschema.protocols import Validator


from agentrust_trace._patterns import _ECMA_PATTERNS, _PYTHON_PATTERNS  # noqa: F401


def _ecma_pattern(
    validator: Validator, pattern: str, instance: Any, schema: Any
) -> Iterator[jsonschema.ValidationError]:
    if validator.is_type(instance, "string") and not _PYTHON_PATTERNS[pattern].search(instance):
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")


_TraceValidator = jsonschema.validators.extend(  # type: ignore[no-untyped-call]
    jsonschema.Draft202012Validator, {"pattern": _ecma_pattern}
)


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    ref = importlib.resources.files("agentrust_trace") / "schema" / "trace-v0.2.json"
    return cast(dict[str, Any], json.loads(ref.read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def _validator() -> Validator:
    base_uri_checker = jsonschema.FormatChecker(formats=["uri"])
    checker = jsonschema.FormatChecker()

    # Convert IPv6Address failures into schema validation errors.
    @checker.checks("uri", raises=ValueError)
    def is_uri(value: Any) -> bool:
        # URI grammar excludes literal line breaks; Python regex end anchors can
        # otherwise accept a final LF. Percent-encoded characters remain valid.
        if isinstance(value, str) and any(c in value for c in "\n\r\u2028\u2029"):
            return False
        if not base_uri_checker.conforms(value, "uri"):
            return False
        if isinstance(value, str):
            authority = re.match(r"^[^:]+://([^/?#]*)", value)
            if authority is not None:
                host = authority[1].rsplit("@", 1)[-1]
                if host.startswith("["):
                    literal = host[1:host.index("]")]
                    # IPvFuture has its own grammar; it is not an IPv6 address.
                    if not literal.startswith(("v", "V")):
                        IPv6Address(literal)
        return True

    return cast(Validator, _TraceValidator(_schema(), format_checker=checker))


@lru_cache(maxsize=1)
def profiles_with_schema() -> frozenset[str]:
    """The ``eat_profile`` URIs this build carries a schema for.

    Read out of the packaged schema files rather than restated here. A verifier can
    only honestly accept a profile whose shape it can check, so this is the ceiling
    on any accepted set: see :func:`agentrust_trace.verify_record`, which refuses a
    configuration naming anything outside it.

    Carrying a schema is necessary, not sufficient. ``trace-v0.1.json`` ships so the
    identifier can be recognised and refused with a specific message, and the cutover
    forbids accepting it regardless.
    """
    found: set[str] = set()
    for entry in (importlib.resources.files("agentrust_trace") / "schema").iterdir():
        if not entry.name.endswith(".json"):
            continue
        schema = json.loads(entry.read_text(encoding="utf-8"))
        const = schema.get("properties", {}).get("eat_profile", {}).get("const")
        if isinstance(const, str):
            found.add(const)
    if not found:
        raise RuntimeError(
            "no packaged schema declares an eat_profile const: the accepted-set ceiling "
            "would be empty and every configuration would be refused"
        )
    return frozenset(found)


#: Canonical schema exposed for downstream tooling that needs the raw dict.
#:
#: A copy, deliberately. `_schema()` is `lru_cache`d and `_validator()` is built over
#: whatever it returns, so this name used to be the live object the validator reads.
#: Mutating it, which is the ordinary thing to do with a dict handed over to adapt,
#: silently reconfigured `validate_json`, `iter_errors` and the structural gate inside
#: `sign.verify_record`, process-wide, for every later call.
SCHEMA: dict[str, Any] = copy.deepcopy(_schema())


def _too_deep() -> jsonschema.ValidationError:
    # `cnf.jwk` admits extra members of any canonicalizable shape, recursively, and
    # jsonschema walks them recursively. A few hundred nested arrays, well under a
    # kilobyte, exhaust the interpreter stack, and the RecursionError escaped every
    # caller written against ValidationError, `sign.verify_record` included. A
    # record the validator cannot walk has not been shown to conform, so it is a
    # violation, reported as one.
    return jsonschema.ValidationError(
        "record nests too deeply to validate against the schema"
    )


def validate_json(record: dict[str, Any]) -> None:
    """Validate *record* against the canonical TRACE v0.2 JSON Schema.

    Raises :class:`jsonschema.ValidationError` on the first violation found,
    including nesting too deep for the validator to walk.
    Use :func:`iter_errors` for all violations.
    """
    try:
        _validator().validate(record)
    except RecursionError:
        raise _too_deep() from None


def iter_errors(record: dict[str, Any]) -> list[jsonschema.exceptions.ValidationError]:
    """Return all JSON Schema violations for *record* (empty list if valid).

    Nesting too deep for the validator to walk is returned as the single violation.
    """
    try:
        return list(_validator().iter_errors(record))
    except RecursionError:
        return [_too_deep()]

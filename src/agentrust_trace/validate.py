from __future__ import annotations

import copy
import importlib.resources
import json
import re
from functools import lru_cache
from ipaddress import IPv6Address
from typing import Any, cast

import jsonschema


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    ref = importlib.resources.files("agentrust_trace") / "schema" / "trace-v0.2.json"
    return cast(dict[str, Any], json.loads(ref.read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    # Keep jsonschema's URI grammar, then close its permissive embedded-IPv4 check.
    # Use instance-local registration so other consumers' format checkers are untouched.
    base_uri_checker = jsonschema.FormatChecker(formats=["uri"])
    checker = jsonschema.FormatChecker()

    @checker.checks("uri", raises=ValueError)
    def is_uri(value: Any) -> bool:
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

    return jsonschema.Draft202012Validator(_schema(), format_checker=checker)


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


def validate_json(record: dict[str, Any]) -> None:
    """Validate *record* against the canonical TRACE v0.2 JSON Schema.

    Raises :class:`jsonschema.ValidationError` on the first violation found.
    Use :func:`iter_errors` for all violations.
    """
    _validator().validate(record)


def iter_errors(record: dict[str, Any]) -> list[jsonschema.exceptions.ValidationError]:
    """Return all JSON Schema violations for *record* (empty list if valid)."""
    return list(_validator().iter_errors(record))

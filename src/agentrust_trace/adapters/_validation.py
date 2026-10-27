"""Validation shared by the AGT and sandbox adapters."""

from __future__ import annotations

from ipaddress import IPv6Address
import re

import jsonschema

from agentrust_trace.models import JCS_SAFE_INTEGER

_URI_FORMAT_CHECKER = jsonschema.FormatChecker(formats=["uri"])
_AUTHORITY_RE = re.compile(r"^[^:]+://([^/?#]*)")


def _is_valid_uri(value: str) -> bool:
    if not value or any(c in value for c in "\n\r\u2028\u2029"):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if not _URI_FORMAT_CHECKER.conforms(value, "uri"):
        return False
    authority = _AUTHORITY_RE.match(value)
    if authority is not None:
        host = authority[1].rsplit("@", 1)[-1]
        if host.startswith("["):
            if "]" not in host:
                return False
            literal = host[1 : host.index("]")]
            if not literal.startswith(("v", "V")):
                try:
                    IPv6Address(literal)
                except ValueError:
                    return False
    return True


def _check_uri(value: object, field: str, *, optional: bool = True) -> None:
    if value is None:
        if optional:
            return
        raise ValueError(f"{field} must be a valid RFC 3986 URI string, got None")
    if not isinstance(value, str) or not _is_valid_uri(value):
        qual = " or None" if optional else ""
        raise ValueError(
            f"{field} must be a valid RFC 3986 URI string{qual}, got {value!r}"
        )


def _check_utf8_str(
    value: object,
    field: str,
    *,
    optional: bool = False,
) -> None:
    if value is None and optional:
        return
    qual = " or None" if optional else ""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string{qual}, got {value!r}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"{field} must be a non-empty string{qual} without lone surrogates, "
            f"got {value!r}"
        ) from exc


def _check_data_class(value: object) -> None:
    _check_utf8_str(value, "data_class")


def _check_policy_bundle_bytes(value: object) -> None:
    if not isinstance(value, bytes):
        raise ValueError(
            f"policy_bundle_bytes must be bytes, got {type(value).__name__}"
        )


def _check_call_count(value: object) -> None:
    if value is None:
        return
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > JCS_SAFE_INTEGER
    ):
        raise ValueError(
            f"call_count must be an integer within [0, {JCS_SAFE_INTEGER}] or None, "
            f"got {value!r}"
        )


def _check_transparency(value: object) -> None:
    _check_uri(value, "transparency", optional=True)

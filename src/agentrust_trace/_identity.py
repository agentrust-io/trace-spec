"""Validation shared by every Python surface that accepts a TRACE subject."""

from __future__ import annotations

import string

# SPIFFE ID paths use one or more non-empty unreserved segments. RFC 3986 dot
# segments are not workload names, so the one- and two-character alternatives
# deliberately exclude "." and ".." while allowing longer segments containing dots.
_SPIFFE_SEGMENT = (
    r"(?:[A-Za-z0-9_-]|"
    r"[A-Za-z0-9_-][A-Za-z0-9_\x2E-]|"
    r"\x2E[A-Za-z0-9_-]|"
    r"[A-Za-z0-9_\x2E-]{3,})"
)
_DID_IDCHAR = r"(?:[A-Za-z0-9_\x2E-]|%[0-9A-Fa-f]{2})"

# This is the portable, schema-facing spelling of the parser below. ``\x2E``
# avoids a literal dot in a character class because _patterns.py adapts literal
# ECMA-262 dots to Python explicitly. The trailing-control guard beside this
# pattern in each schema closes ECMA-262's special `$`-before-final-newline case.
_SUBJECT_PATTERN = (
    rf"^(?:spiffe://[a-z0-9_\x2E-]{{1,255}}/{_SPIFFE_SEGMENT}"
    rf"(?:/{_SPIFFE_SEGMENT})*|"
    rf"did:[a-z0-9]+:(?:{_DID_IDCHAR}|:)*{_DID_IDCHAR})$"
)

_SPIFFE_TRUST_DOMAIN_CHARS = frozenset(string.ascii_lowercase + string.digits + "._-")
_SPIFFE_PATH_CHARS = frozenset(string.ascii_letters + string.digits + "._-")
_DID_METHOD_CHARS = frozenset(string.ascii_lowercase + string.digits)
_DID_ID_CHARS = frozenset(string.ascii_letters + string.digits + "._-")
_HEX_CHARS = frozenset(string.hexdigits)


def _is_spiffe_id(value: str) -> bool:
    """Apply the SPIFFE ID trust-domain and workload-path grammar without URI repair."""
    if not value.startswith("spiffe://"):
        return False
    trust_domain, separator, path = value[len("spiffe://") :].partition("/")
    if (
        not separator
        or not 1 <= len(trust_domain) <= 255
        or any(ch not in _SPIFFE_TRUST_DOMAIN_CHARS for ch in trust_domain)
    ):
        # This also rejects userinfo, ports, percent encoding, queries, fragments,
        # controls, and non-ASCII authorities instead of normalizing any of them.
        return False
    segments = path.split("/")
    return all(
        segment not in {"", ".", ".."}
        and all(ch in _SPIFFE_PATH_CHARS for ch in segment)
        for segment in segments
    )


def _is_did(value: str) -> bool:
    """Apply DID Core section 3.1's generic DID ABNF, excluding DID URL suffixes."""
    if not value.startswith("did:"):
        return False
    method, separator, identifier = value[len("did:") :].partition(":")
    if (
        not separator
        or not method
        or any(ch not in _DID_METHOD_CHARS for ch in method)
    ):
        return False

    # method-specific-id = *( *idchar ":" ) 1*idchar. Colons may separate
    # method-defined components, but the identifier cannot end with one.
    index = 0
    ends_in_idchar = False
    while index < len(identifier):
        ch = identifier[index]
        if ch == ":":
            ends_in_idchar = False
            index += 1
            continue
        if ch == "%":
            if (
                index + 2 >= len(identifier)
                or identifier[index + 1] not in _HEX_CHARS
                or identifier[index + 2] not in _HEX_CHARS
            ):
                return False
            ends_in_idchar = True
            index += 3
            continue
        if ch not in _DID_ID_CHARS:
            # Raw Unicode, controls, and DID URL /, ? and # suffixes are not idchar.
            return False
        ends_in_idchar = True
        index += 1
    return ends_in_idchar


def _is_subject(value: object) -> bool:
    """Return whether *value* is a complete SPIFFE workload ID or DID Core DID."""
    return isinstance(value, str) and (_is_spiffe_id(value) or _is_did(value))


def _require_subject(value: str) -> str:
    """Pydantic after-validator for a TRACE workload identity."""
    if not _is_subject(value):
        raise ValueError(
            f"{value!r} is not a valid SPIFFE workload ID or DID Core DID"
        )
    return value

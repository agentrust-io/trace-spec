"""Shared HTTPS pointer shape, without fetching or endpoint trust policy."""

from typing import Any, TypeGuard
from urllib.parse import urlsplit


def valid_https_uri(value: Any) -> TypeGuard[str]:
    if not isinstance(value, str):
        return False
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return False
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        _, _, hostinfo = parsed.netloc.rpartition("@")
        prefix, have_open_br, bracketed = hostinfo.partition("[")
        if have_open_br:
            _, _, tail = bracketed.partition("]")
            if prefix or (tail and not tail.startswith(":")):
                return False
        # urllib validates the port lazily, separately from splitting the URL.
        parsed.port
    except ValueError:
        return False
    return True

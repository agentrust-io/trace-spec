"""Shared execution semantics for the closed set of shipped TRACE patterns."""

import re

# Only the four pattern forms shipped in TRACE v0.2 are adapted here. This is
# not a general ECMA-262 translator: a new schema pattern needs explicit review.
# None of these forms has a literal/escaped dot or dollar, or a dot in a class.
_ECMA_PATTERNS = (
    '^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$',
    '^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$',
    (r"^P(\d+W|(\d+Y(\d+M)?(\d+D)?|\d+M(\d+D)?|\d+D)"
     r"(T(\d+H(\d+M)?(\d+S)?|\d+M(\d+S)?|\d+S))?"
     r"|T(\d+H(\d+M)?(\d+S)?|\d+M(\d+S)?|\d+S))$"),
    '^[A-Za-z0-9_-]+$',
)
_PYTHON_PATTERNS = {
    pattern: re.compile(
        pattern.replace("$", r"\Z")
        .replace(".", r"[^\n\r\u2028\u2029]")
        .replace(r"\d", "[0-9]")
    )
    for pattern in _ECMA_PATTERNS
}


def _require_pattern(value: str, *, pattern: str) -> str:
    if not _PYTHON_PATTERNS[pattern].search(value):
        raise ValueError(f"{value!r} does not match {pattern!r}")
    return value

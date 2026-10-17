"""Validation shared by the AGT and sandbox adapters."""

from __future__ import annotations

from agentrust_trace.models import JCS_SAFE_INTEGER


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
    if value is not None and (not isinstance(value, str) or not value):
        raise ValueError("transparency must be a non-empty URI string or None")

"""Tests for verify_record caller-option validation at entry (#556)."""

from __future__ import annotations

from typing import Any

import pytest

from agentrust_trace import generate_key, key_to_jwk, sign_record, verify_record


def _signed_record() -> tuple[dict[str, Any], dict[str, str]]:
    key = generate_key()
    jwk = key_to_jwk(key)
    record = sign_record(
        {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": 1_791_936_000,
            "subject": "spiffe://example.org/agent/demo",
            "model": {"provider": "example", "model_id": "demo"},
            "runtime": {
                "platform": "software-only",
                "measurement": "sha256:" + "0" * 64,
            },
            "policy": {
                "bundle_hash": "sha256:" + "b" * 64,
                "enforcement_mode": "declared",
            },
            "data_class": "internal",
            "build_provenance": {
                "slsa_level": 1,
                "digest": "sha256:" + "e" * 64,
            },
            "appraisal": {
                "status": "none",
                "verifier": "https://verifier.example.org",
            },
        },
        key,
    )
    return record, jwk


@pytest.mark.parametrize("bad_now", [-1, -100], ids=["minus-1", "minus-100"])
def test_verify_record_rejects_negative_now(bad_now: int) -> None:
    """`now` must be a non-negative integer Unix timestamp whether or not a bundle is passed."""
    record, jwk = _signed_record()
    with pytest.raises(ValueError, match=r"^now must be .*non-negative"):
        verify_record(
            record,
            jwk,
            now=bad_now,
            max_future_skew_seconds=2_000_000_000,
        )
    with pytest.raises(ValueError, match=r"^now must be .*non-negative"):
        verify_record(
            record,
            jwk,
            now=bad_now,
            max_future_skew_seconds=2_000_000_000,
            revocation_bundle={},
        )


@pytest.mark.parametrize(
    "bad_keys",
    [
        {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
        "str",
        b"bytes",
        False,
        0,
        123,
        [123],
        [None],
    ],
    ids=["bare-jwk-dict", "str", "bytes", "False", "0", "int", "list-of-int", "list-of-None"],
)
def test_verify_record_rejects_invalid_trusted_bundle_keys_when_bundle_is_none(
    bad_keys: Any,
) -> None:
    """`trusted_bundle_keys` is validated even when `revocation_bundle` is `None`."""
    record, jwk = _signed_record()
    with pytest.raises(ValueError, match=r"^trusted_bundle_keys must "):
        verify_record(
            record,
            jwk,
            now=record["iat"],
            revocation_bundle=None,
            trusted_bundle_keys=bad_keys,
        )


@pytest.mark.parametrize(
    "malformed_record",
    [
        "not-a-dict",
        {},
        {"eat_profile": "tag:agentrust-io.com,2026:trace-v0.2", "signature": "AAAA"},
    ],
    ids=["non-dict", "missing-eat-profile", "schema-invalid"],
)
@pytest.mark.parametrize(
    ("option_kwargs", "expected_pattern"),
    [
        ({"max_age_seconds": -1}, r"^max_age_seconds must be non-negative"),
        ({"max_age_seconds": True}, r"^max_age_seconds must be an integer"),
        ({"expected_nonce": 123}, r"^expected_nonce must be a string$"),
        (
            {"revocation": {"kty": "OKP"}},
            r"^revocation must be a container of key identifier strings or a callable",
        ),
        (
            {"revocation": [123]},
            r"^revocation must contain only str values",
        ),
        (
            {"trusted_bundle_keys": {"kty": "OKP"}},
            r"^trusted_bundle_keys must be an iterable of dict values",
        ),
        ({"now": -1}, r"^now must be .*non-negative"),
    ],
    ids=[
        "negative-max-age",
        "bool-max-age",
        "non-str-expected-nonce",
        "dict-revocation",
        "non-str-element-revocation",
        "bare-dict-trusted-bundle-keys",
        "negative-now",
    ],
)
def test_verify_record_validates_caller_options_at_entry_before_record(
    malformed_record: Any,
    option_kwargs: dict[str, Any],
    expected_pattern: str,
) -> None:
    """Caller options are checked at entry before inspecting an untrusted `record`."""
    _record, jwk = _signed_record()
    with pytest.raises(ValueError, match=expected_pattern):
        verify_record(malformed_record, jwk, **option_kwargs)
    with pytest.raises(ValueError, match=r"^allow_embedded_key must be a bool"):
        verify_record(malformed_record, jwk, allow_embedded_key="false")  # type: ignore[arg-type]

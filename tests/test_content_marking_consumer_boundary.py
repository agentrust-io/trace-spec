"""Consumer and RFC 8259 UTF-8 / JSON boundary tests for content_marking."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from agentrust_trace.content_marking import (
    ASSERTION_LABEL,
    ContentMarkingError,
    RecordMismatch,
    _loads,
    build_assertion,
    verify_assertion,
)

URL = "https://registry.example/records/abc123.json"
ANCHOR = "https://registry.example/entries/2026-08-09-001"


def _valid_record(
    *,
    subject: str = "spiffe://example.org/agent/image-bot",
    eat_profile: str = "tag:agentrust-io.com,2026:trace-v0.2",
) -> dict[str, Any]:
    return {
        "eat_profile": eat_profile,
        "iat": 1760000000,
        "subject": subject,
        "data_class": "public",
    }


def _assert_positive_controls() -> None:
    for subject in ("spiffe://example.org/agent/image-bot", "did:web:example.com"):
        raw = json.dumps(_valid_record(subject=subject)).encode()
        for alg in ("sha256", "sha384"):
            for anchor in (None, ANCHOR):
                built = build_assertion(raw, url=URL, alg=alg, anchor=anchor)
                verified = verify_assertion(built, raw)
                assert verified["subject"] == subject


def _crafted_pair(
    *,
    subject: Any = "spiffe://example.org/agent/image-bot",
    eat_profile: Any = "tag:agentrust-io.com,2026:trace-v0.2",
    anchor: Any = ...,
    extra_record: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], bytes]:
    record_obj: dict[str, Any] = {
        "eat_profile": eat_profile,
        "iat": 1760000000,
        "subject": subject,
        "data_class": "public",
    }
    if extra_record:
        record_obj.update(extra_record)
    raw = json.dumps(record_obj).encode()
    data: dict[str, Any] = {
        "version": 1,
        "record": {
            "url": URL,
            "alg": "sha256",
            "hash": "sha256:" + hashlib.sha256(raw).hexdigest(),
        },
        "subject": subject,
        "eat_profile": eat_profile,
    }
    if anchor is not ...:
        data["anchor"] = anchor
    return {"label": ASSERTION_LABEL, "data": data}, raw


@pytest.mark.parametrize(
    "bad_subject",
    [123, True, False, 0, None, "", "not-a-uri", "spiffe://host-only", [], {}],
)
def test_verify_assertion_rejects_invalid_subject_even_when_record_agrees(
    bad_subject: Any,
) -> None:
    _assert_positive_controls()

    valid_a, _ = _crafted_pair(subject="spiffe://example.org/agent/image-bot")
    _, other_raw = _crafted_pair(subject="did:web:example.com")
    valid_a["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(other_raw).hexdigest()
    with pytest.raises(RecordMismatch, match="assertion names subject"):
        verify_assertion(valid_a, other_raw)

    assertion, raw = _crafted_pair(subject=bad_subject)
    with pytest.raises(ContentMarkingError, match="SPIFFE or DID subject"):
        build_assertion(raw, url=URL)
    with pytest.raises(
        ContentMarkingError, match="assertion subject must be a SPIFFE or DID URI"
    ) as exc_info:
        verify_assertion(assertion, raw)
    assert not isinstance(exc_info.value, RecordMismatch)


@pytest.mark.parametrize("bad_profile", ["", None, 0, False, 123, [], {}])
def test_verify_assertion_rejects_invalid_eat_profile_even_when_record_agrees(
    bad_profile: Any,
) -> None:
    _assert_positive_controls()

    valid_a, _ = _crafted_pair(eat_profile="tag:agentrust-io.com,2026:trace-v0.2")
    _, other_raw = _crafted_pair(eat_profile="tag:agentrust.io,2026:trace-v0.1")
    valid_a["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(other_raw).hexdigest()
    with pytest.raises(RecordMismatch, match="eat_profile"):
        verify_assertion(valid_a, other_raw)

    assertion, raw = _crafted_pair(eat_profile=bad_profile)
    with pytest.raises(
        ContentMarkingError, match="assertion eat_profile must be a non-empty string"
    ) as exc_info:
        verify_assertion(assertion, raw)
    assert not isinstance(exc_info.value, RecordMismatch)


@pytest.mark.parametrize("bad_anchor", ["", None, 0, False, 123, [], {}, "\ud800"])
def test_verify_assertion_rejects_invalid_anchor_when_present(bad_anchor: Any) -> None:
    _assert_positive_controls()

    assertion, raw = _crafted_pair(
        anchor=bad_anchor,
        extra_record={"anchor": bad_anchor if bad_anchor != "\ud800" else "ok"},
    )
    with pytest.raises(ContentMarkingError, match="assertion anchor must") as exc_info:
        verify_assertion(assertion, raw)
    assert not isinstance(exc_info.value, RecordMismatch)


@pytest.mark.parametrize(
    "surrogate",
    ["\ud800", "\udfff", "\ud800\udc00", "\ud83d\ude00", "https://example.com/\ud800"],
)
def test_build_assertion_rejects_unpaired_surrogate_in_anchor(surrogate: str) -> None:
    _assert_positive_controls()
    raw = json.dumps(_valid_record()).encode()
    escaped_pair_raw = (
        b'{"subject":"spiffe://example.org/agent/image-bot",'
        b'"eat_profile":"tag:agentrust-io.com,2026:trace-v0.2",'
        b'"note":"\\ud83d\\ude00"}'
    )
    built_pair = build_assertion(
        escaped_pair_raw, url=URL, anchor="https://example.com/\U0001f600"
    )
    assert verify_assertion(built_pair, escaped_pair_raw)["note"] == "\U0001f600"
    with pytest.raises(
        ContentMarkingError, match="anchor must not contain an unpaired UTF-16 surrogate"
    ):
        build_assertion(raw, url=URL, anchor=surrogate)


@pytest.mark.parametrize(
    ("encoding", "bom"),
    [
        ("utf-16-le", b"\xff\xfe"),
        ("utf-16-be", b"\xfe\xff"),
        ("utf-32-le", b"\xff\xfe\x00\x00"),
        ("utf-32-be", b"\x00\x00\xfe\xff"),
    ],
)
def test_utf16_and_utf32_bom_encoded_record_bytes_are_rejected(
    encoding: str, bom: bytes
) -> None:
    _assert_positive_controls()
    encoded = bom + json.dumps(_valid_record()).encode(encoding)
    with pytest.raises(ContentMarkingError, match="is not valid UTF-8"):
        build_assertion(encoded, url=URL)

    assertion, _ = _crafted_pair()
    assertion["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    with pytest.raises(ContentMarkingError, match="is not valid UTF-8"):
        verify_assertion(assertion, encoded)


def test_utf8_bom_prefixed_record_bytes_are_rejected() -> None:
    _assert_positive_controls()
    bom_bytes = json.dumps(_valid_record()).encode("utf-8-sig")
    with pytest.raises(
        ContentMarkingError, match="must not start with a UTF-8 byte-order mark"
    ):
        build_assertion(bom_bytes, url=URL)

    assertion, _ = _crafted_pair()
    assertion["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(bom_bytes).hexdigest()
    with pytest.raises(
        ContentMarkingError, match="must not start with a UTF-8 byte-order mark"
    ):
        verify_assertion(assertion, bom_bytes)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_rfc8259_numeric_constants_are_rejected(token: str) -> None:
    _assert_positive_controls()
    raw = (
        '{"subject":"spiffe://example.org/agent/image-bot",'
        f'"eat_profile":"tag:agentrust-io.com,2026:trace-v0.2","iat":{token}}}'
    ).encode()
    with pytest.raises(ContentMarkingError, match="contains non-RFC-8259 numeric constant"):
        build_assertion(raw, url=URL)

    assertion, _ = _crafted_pair()
    assertion["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    with pytest.raises(ContentMarkingError, match="contains non-RFC-8259 numeric constant"):
        verify_assertion(assertion, raw)


@pytest.mark.parametrize("escape", [r"\ud800", r"\udfff"])
@pytest.mark.parametrize("location", ["value", "key"])
def test_unpaired_surrogates_in_record_bytes_are_rejected(
    escape: str, location: str
) -> None:
    _assert_positive_controls()
    if location == "value":
        raw = (
            '{"subject":"spiffe://example.org/agent/image-bot",'
            '"eat_profile":"tag:agentrust-io.com,2026:trace-v0.2",'
            f'"note":"{escape}"}}'
        ).encode()
    else:
        raw = (
            '{"subject":"spiffe://example.org/agent/image-bot",'
            '"eat_profile":"tag:agentrust-io.com,2026:trace-v0.2",'
            f'"{escape}":1}}'
        ).encode()

    with pytest.raises(ContentMarkingError, match="contains an unpaired UTF-16 surrogate"):
        build_assertion(raw, url=URL)

    assertion, _ = _crafted_pair()
    assertion["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    with pytest.raises(ContentMarkingError, match="contains an unpaired UTF-16 surrogate"):
        verify_assertion(assertion, raw)


@pytest.mark.parametrize("surrogate", ["\ud800", "\udfff", "\ud800\udc00", "\ud83d\ude00"])
def test_unpaired_surrogates_anywhere_in_assertion_are_rejected(
    surrogate: str,
) -> None:
    _assert_positive_controls()
    assertion, raw = _crafted_pair()
    assertion["data"]["extra"] = {"nested": [surrogate]}
    with pytest.raises(ContentMarkingError, match="contains an unpaired UTF-16 surrogate"):
        verify_assertion(assertion, raw)


@pytest.mark.parametrize(
    ("bad_record_overrides", "expected_match"),
    [
        ({"subject": 123}, "the record has no SPIFFE or DID subject to bind to"),
        ({"subject": "not-a-uri"}, "the record has no SPIFFE or DID subject to bind to"),
        ({"eat_profile": ""}, "the record declares no non-empty string eat_profile"),
        ({"eat_profile": 123}, "the record declares no non-empty string eat_profile"),
        ({"anchor": ""}, "the record anchor must be a non-empty string"),
        ({"anchor": 123}, "the record anchor must be a non-empty string"),
    ],
)
def test_fetched_record_with_invalid_fields_raises_content_marking_error_not_mismatch(
    bad_record_overrides: dict[str, Any], expected_match: str
) -> None:
    _assert_positive_controls()
    assertion, _ = _crafted_pair(anchor=ANCHOR)
    bad_record = {**_valid_record(), **bad_record_overrides}
    bad_raw = json.dumps(bad_record).encode()
    assertion["data"]["record"]["hash"] = "sha256:" + hashlib.sha256(bad_raw).hexdigest()
    with pytest.raises(ContentMarkingError, match=expected_match) as exc_info:
        verify_assertion(assertion, bad_raw)
    assert not isinstance(exc_info.value, RecordMismatch)


def test_loads_rejects_non_bytes_input() -> None:
    _assert_positive_controls()
    with pytest.raises(
        ContentMarkingError, match="record_bytes must be bytes or bytearray, got str"
    ):
        _loads("{}", "record_bytes")  # type: ignore[arg-type]

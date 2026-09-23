"""Integer-typed members are decided by value, not by spelling (agentrust-io/trace-spec#247).

Proposed, not accepted: see `examples/number-spelling/README.md`.

JSON has one number type. `1785000000`, `1785000000.0` and `1.785e9` are one value,
RFC 8785 writes all three as `1785000000`, and a record carrying any of them has one
signing pre-image and one signature. `json.loads` returns an `int` for the first
spelling and a `float` for the other two, so a Python type test decides what the
signature cannot see. This module holds every layer to the value instead:

- the decision itself, `_integer_value`, over the boundary cases;
- the schema, which already decided by value, and the model, which now does;
- the freshness check in `verify_record`, which rejected a correctly signed record
  whose `iat` was written `1785000000.0`;
- the canonicalizer, which refuses a whole number past the safe-integer range however
  it is written, and every digest that goes through it;
- the bridge and the revocation bundle, whose integer members are decided the same way;
- the vectors in `examples/number-spelling/`, recomputed from their committed bytes,
  graded against plausible shortcuts, and run from JavaScript when Node is present;
- the scan that counts which published records the rule changes.
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import jsonschema
import pydantic
import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import TraceAGTAdapter, TraceSandboxAdapter
from agentrust_trace.intent_bridge import IntentBridgeError, digest_jcs, sign_bridge, verify_bridge
from agentrust_trace.models import TrustRecord
from agentrust_trace.revocation import bundle_digest
from agentrust_trace.sign import (
    JCS_SAFE_INTEGER,
    _canonical_bytes,
    _integer_value,
    _pubkey_from_jwk,
    key_to_jwk,
    sign_record,
    verify_record,
)
from agentrust_trace.validate import validate_json
from tests.test_intent_bridge import _fixture as _bridge_fixture

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples" / "number-spelling"
FILES = sorted(VECTORS.glob("*.json"))
assert FILES, "no number-spelling vectors on disk; this module would measure nothing"

NOW = 1785000100


# ---- the decision ---------------------------------------------------------------

# Spellings as they arrive in a document, parsed by `json.loads` exactly as a verifier
# reading one would parse them.
WHOLE = [
    ("1785000000", 1785000000),
    ("1785000000.0", 1785000000),
    ("1.785e9", 1785000000),
    ("17850000000e-1", 1785000000),
    # More digits than a double carries: the value is the double, which is what RFC 8785
    # writes and a signature covers.
    ("1785000000.0000000001", 1785000000),
    ("9007199254740991", JCS_SAFE_INTEGER),
    ("9007199254740991.0", JCS_SAFE_INTEGER),
    ("-9007199254740991", -JCS_SAFE_INTEGER),
    ("0", 0),
    ("-0.0", 0),
]
NOT_AN_INTEGER = [
    "1785000000.5", "17850000005e-1", "0.5", "true", "false", '"1785000000"', "null",
    "[]", "{}", "NaN", "Infinity",
]
# `9.007199254740993e15` parses to 2**53: the value outside the range is the parsed
# one, and the message reports it rather than the digits that were written.
OUTSIDE_THE_RANGE = [
    ("9007199254740992", 2**53),
    ("-9007199254740992", -(2**53)),
    ("9007199254740992.0", 2**53),
    ("9.007199254740993e15", 2**53),
    ("1e21", 10**21),
    ("1.0e+21", 10**21),
]


@pytest.mark.parametrize(("text", "value"), WHOLE, ids=[t for t, _ in WHOLE])
def test_a_whole_number_is_the_integer_it_denotes(text: str, value: int) -> None:
    decided = _integer_value(json.loads(text), "m")
    assert decided == value
    assert type(decided) is int


@pytest.mark.parametrize("text", NOT_AN_INTEGER)
def test_anything_else_is_not_an_integer_value(text: str) -> None:
    with pytest.raises(ValueError, match=r"^m is not an integer value: "):
        _integer_value(json.loads(text), "m")


@pytest.mark.parametrize(("text", "value"), OUTSIDE_THE_RANGE,
                         ids=[t for t, _ in OUTSIDE_THE_RANGE])
def test_a_whole_number_past_the_range_is_refused_as_that(text: str, value: int) -> None:
    with pytest.raises(ValueError, match=rf"^m is {value}, outside the safe-integer range "):
        _integer_value(json.loads(text), "m")


def test_a_boolean_is_refused_although_python_calls_it_an_int() -> None:
    assert isinstance(True, int)
    for value in (True, False):
        with pytest.raises(ValueError, match="it is a bool, not a JSON number"):
            _integer_value(value, "m")


# ---- the schema and the model ---------------------------------------------------


def _base() -> dict[str, Any]:
    """Vector 01's record, unsigned, carrying all five integer members of the schema."""
    record = json.loads((VECTORS / "01-integer-spelling-verified.json").read_text())["record"]
    record.pop("signature")
    record["tool_transcript"] = {"hash": "sha256:" + "c" * 64, "call_count": 7}
    record["origin"] = {"kind": "self", "producer": "producer.example",
                        "ingested_at": 1785000000}
    record["appraisal"]["timestamp"] = 1785000000
    return record


def _set(record: dict[str, Any], member: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(record)
    *parents, last = member.split(".")
    target = out
    for name in parents:
        target = target[name]
    target[last] = value
    return out


def _get(record: dict[str, Any], member: str) -> Any:
    target: Any = record
    for name in member.split("."):
        target = target[name]
    return target


MEMBERS = ["iat", "origin.ingested_at", "tool_transcript.call_count",
           "build_provenance.slsa_level", "appraisal.timestamp"]


def test_the_base_record_is_valid_as_it_stands() -> None:
    validate_json(_base())
    TrustRecord.model_validate(_base())


@pytest.mark.parametrize("member", MEMBERS)
def test_every_integer_member_takes_its_value_written_as_a_float(member: str) -> None:
    whole = float(_get(_base(), member))
    record = _set(_base(), member, whole)
    validate_json(record)
    dumped = TrustRecord.model_validate(record).model_dump(mode="json", exclude_none=True)
    assert _get(dumped, member) == whole
    assert type(_get(dumped, member)) is int, "the model writes the plain integer back out"


@pytest.mark.parametrize("member", MEMBERS)
def test_no_integer_member_takes_a_fraction(member: str) -> None:
    record = _set(_base(), member, _get(_base(), member) + 0.5)
    with pytest.raises(jsonschema.ValidationError, match="is not of type 'integer'"):
        validate_json(record)
    with pytest.raises(pydantic.ValidationError, match="which is not a whole number"):
        TrustRecord.model_validate(record)


# (member, spelling, the schema keyword that refuses it or None, the model's message)
BOUNDARIES = [
    ("iat", "1785000000", None, None),
    ("iat", "1785000000.0", None, None),
    ("iat", "1.785e9", None, None),
    ("iat", "1785000000.0000000001", None, None),
    ("iat", "1785000000.5", "type", "which is not a whole number"),
    ("iat", "true", "type", "got a boolean"),
    ("iat", "false", "type", "got a boolean"),
    ("iat", '"1785000000"', "type", "got a str"),
    ("iat", "0", "minimum", "greater than or equal to 1700000000"),
    ("iat", "-0.0", "minimum", "greater than or equal to 1700000000"),
    ("tool_transcript.call_count", "-0.0", None, None),
    ("build_provenance.slsa_level", "3.0", None, None),
    ("build_provenance.slsa_level", "4.0", "maximum", "less than or equal to 3"),
    ("appraisal.timestamp", "9007199254740991", None, None),
    ("appraisal.timestamp", "9007199254740991.0", None, None),
    ("appraisal.timestamp", "-9007199254740991.0", None, None),
    ("appraisal.timestamp", "9007199254740992", "maximum",
     "less than or equal to 9007199254740991"),
    ("appraisal.timestamp", "9.007199254740993e15", "maximum",
     "less than or equal to 9007199254740991"),
    ("appraisal.timestamp", "1e21", "maximum", "less than or equal to 9007199254740991"),
    ("appraisal.timestamp", "-1e21", "minimum", "greater than or equal to -9007199254740991"),
]


@pytest.mark.parametrize(("member", "text", "keyword", "message"), BOUNDARIES,
                         ids=[f"{m}={t}" for m, t, _, _ in BOUNDARIES])
def test_the_schema_and_the_model_draw_each_boundary_in_the_same_place(
    member: str, text: str, keyword: str | None, message: str | None
) -> None:
    """The schema decided by value before this change; `jsonschema` follows JSON Schema
    2020-12, whose `integer` matches any number with a zero fractional part. The model
    decided by Python type, and read a numeric string as the number it spells."""
    record = _set(_base(), member, json.loads(text))
    errors = list(jsonschema.Draft202012Validator(
        json.loads((ROOT / "schema" / "trace-claim.json").read_text())
    ).iter_errors(record))
    if keyword is None:
        assert errors == []
        model = TrustRecord.model_validate(record)
        assert _get(model.model_dump(mode="json", exclude_none=True), member) == json.loads(text)
        return
    assert [e.validator for e in errors] == [keyword]
    with pytest.raises(pydantic.ValidationError, match=re.escape(message or "")):
        TrustRecord.model_validate(record)


def test_the_model_refuses_bytes_that_spell_a_number() -> None:
    with pytest.raises(pydantic.ValidationError, match="got a bytes"):
        TrustRecord.model_validate(_set(_base(), "iat", b"1785000000"))


# ---- a signed record, re-spelled ------------------------------------------------


def _unsigned(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "signature"}


def _respell(record: dict[str, Any], spelling: str) -> dict[str, Any]:
    """*record* with its `iat` rewritten in the text, as a producer's serializer might."""
    text = json.dumps(record)
    written = f'"iat": {record["iat"]},'
    assert text.count(written) == 1
    return json.loads(text.replace(written, f'"iat": {spelling},'))


@pytest.mark.parametrize("spelling", ["1785000000.0", "1.785e9"])
def test_a_signed_record_verifies_however_iat_is_written(spelling: str) -> None:
    key = Ed25519PrivateKey.generate()
    record = sign_record(_base(), key)
    respelled = _respell(record, spelling)
    assert type(respelled["iat"]) is float
    assert respelled["signature"] == record["signature"]
    assert _canonical_bytes(_unsigned(respelled)) == _canonical_bytes(_unsigned(record))
    verify_record(respelled, key_to_jwk(key), now=NOW)
    assert sign_record(_unsigned(respelled), key)["signature"] == record["signature"], (
        "a producer writing either spelling signs the same bytes"
    )


@pytest.mark.parametrize("spelling", ["1785000000.5", "17850000005e-1"])
def test_a_signed_record_whose_iat_is_not_whole_is_rejected(spelling: str) -> None:
    key = Ed25519PrivateKey.generate()
    record = sign_record(_set(_base(), "iat", json.loads(spelling)), key)
    with pytest.raises(ValueError, match="at iat: 1785000000.5 is not of type 'integer'"):
        verify_record(record, key_to_jwk(key), now=NOW)


@pytest.mark.parametrize(("value", "reason"), [
    (1785000000.5, "'iat' is not an integer value: 1785000000.5 is not a whole number"),
    ("1785000000", "'iat' is not an integer value: it is a str, not a JSON number"),
    (True, "'iat' is not an integer value: it is a bool, not a JSON number"),
    (1e21, "'iat' is 1000000000000000000000, outside the safe-integer range"),
])
def test_the_freshness_check_names_the_rule_it_applies(
    monkeypatch: pytest.MonkeyPatch, value: Any, reason: str
) -> None:
    """With the schema out of the way, the freshness check is the one deciding. It used
    to say only that `iat` was not a valid integer, and said it of `1785000000.0` too."""
    import agentrust_trace.validate as validate

    monkeypatch.setattr(validate, "validate_json", lambda record: None)
    key = Ed25519PrivateKey.generate()
    record = {**sign_record(_base(), key), "iat": value}
    with pytest.raises(ValueError, match=re.escape(
        f"record has no valid integer 'iat' for freshness check: {reason}"
    )):
        verify_record(record, key_to_jwk(key), now=NOW)


# ---- the canonicalizer, and every digest taken through it -----------------------


def test_the_canonical_form_is_written_by_value() -> None:
    assert _canonical_bytes({"n": 1785000000.0}) == b'{"n":1785000000}'
    assert _canonical_bytes({"n": 1.785e9}) == _canonical_bytes({"n": 1785000000})
    excess = json.loads("1785000000.0000000001")
    assert _canonical_bytes({"n": excess}) == _canonical_bytes({"n": 1785000000})
    assert _canonical_bytes({"n": -0.0}) == b'{"n":0}'


@pytest.mark.parametrize(("text", "value"), OUTSIDE_THE_RANGE,
                         ids=[t for t, _ in OUTSIDE_THE_RANGE])
def test_a_whole_number_past_the_range_has_no_canonical_form_however_written(
    text: str, value: int
) -> None:
    parsed = json.loads(text)
    for container in ({"n": parsed}, {"a": [{"n": parsed}]}, [parsed], ({"n": parsed},)):
        with pytest.raises(rfc8785.IntegerDomainError, match=rf"^{value} exceeds"):
            _canonical_bytes(container)


def test_the_rfc8785_package_refuses_the_int_and_writes_the_float() -> None:
    """Why `_canonical_bytes` checks the range itself. Pinned, so a release of the
    package that changes either half is noticed here rather than in a verdict."""
    with pytest.raises(rfc8785.IntegerDomainError):
        rfc8785.dumps({"n": 2**53})
    assert rfc8785.dumps({"n": float(2**53)}) == b'{"n":9007199254740992}'
    assert rfc8785.dumps({"n": 1e21}) == b'{"n":1e+21}'


def test_a_float_that_is_not_whole_is_left_to_rfc8785_as_before() -> None:
    assert _canonical_bytes({"n": 0.5}) == b'{"n":0.5}'
    assert _canonical_bytes({"n": 1785000000.5}) == b'{"n":1785000000.5}'
    for value in (float("inf"), float("-inf"), float("nan")):
        with pytest.raises(rfc8785.FloatDomainError):
            _canonical_bytes({"n": value})


def test_every_digest_refuses_a_whole_number_past_the_range_written_as_a_float() -> None:
    """A nanosecond timestamp that went through a double is a float past the range. The
    same value written as an integer was already refused by all three digests."""
    nanoseconds = 1.7850000001234568e18
    with pytest.raises(IntentBridgeError, match="no RFC 8785 canonical form"):
        digest_jcs({"ts_ns": nanoseconds})
    assert digest_jcs({"ts": 1785000000.0}) == digest_jcs({"ts": 1785000000})
    hashes: list[Callable[[list[dict[str, Any]]], str]] = [
        TraceAGTAdapter._transcript_hash, TraceSandboxAdapter.transcript_hash,
    ]
    for transcript_hash in hashes:
        with pytest.raises(rfc8785.IntegerDomainError):
            transcript_hash([{"ts_ns": nanoseconds}])
        assert transcript_hash([{"ts": 1785000000.0}]) == transcript_hash([{"ts": 1785000000}])
        assert transcript_hash([{"risk": 0.5}]).startswith("sha256:")


# ---- the bridge -----------------------------------------------------------------


def _verify_bridge(bridge: dict[str, Any], key: Ed25519PrivateKey, declaration: dict,
                   intent: str, args: str, tool_call: dict, transcript: dict) -> dict:
    return verify_bridge(
        bridge, {**key_to_jwk(key), "kid": "key-7"}, declaration=declaration,
        pic_intent_digest=intent, pic_args_digest=args, tool_call=tool_call,
        transcript=transcript, now=150,
    )


def _resigned(bridge: dict[str, Any], key: Ed25519PrivateKey, **changes: Any) -> dict:
    return sign_bridge({**copy.deepcopy(bridge["authorization"]), **changes}, key)


def test_bridge_times_written_as_whole_floats_are_the_times_signed() -> None:
    bridge, key, *rest = _bridge_fixture()
    respelled = _resigned(bridge, key, authorized_at=100.0, expires_at=200.0)
    assert respelled["signature"] == bridge["signature"]
    assert _verify_bridge(respelled, key, *rest)["authorization_id"] == "auth-7"


@pytest.mark.parametrize(("value", "reason"), [
    (100.5, "authorization.authorized_at is not an integer value: 100.5 is not a whole number"),
    ("100", "authorization.authorized_at is not an integer value: it is a str"),
    (True, "authorization.authorized_at is not an integer value: it is a bool"),
    (-1, "it is -1"),
    (-1.0, "it is -1"),
])
def test_a_bridge_time_that_is_not_a_non_negative_integer_is_refused_with_its_reason(
    value: Any, reason: str
) -> None:
    bridge, key, *rest = _bridge_fixture()
    with pytest.raises(IntentBridgeError, match=re.escape(
        f"authorized_at must be a non-negative integer Unix timestamp: {reason}"
    )):
        _verify_bridge(_resigned(bridge, key, authorized_at=value), key, *rest)


def test_a_bridge_time_past_the_range_has_no_canonical_form_to_check_a_signature_over() -> None:
    bridge, key, *rest = _bridge_fixture()
    tampered = copy.deepcopy(bridge)
    tampered["authorization"]["expires_at"] = 1e21
    with pytest.raises(IntentBridgeError, match="no RFC 8785 canonical form"):
        _verify_bridge(tampered, key, *rest)


def test_an_observation_time_written_as_a_whole_float_binds_to_the_signed_digest() -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _bridge_fixture()
    respelled = copy.deepcopy(transcript)
    respelled["after"]["observed_at"] = 150.0
    signed = bridge["authorization"]["successor_observation_digest"]
    assert digest_jcs(respelled["after"]) == signed
    _verify_bridge(bridge, key, declaration, intent, args, tool_call, respelled)


@pytest.mark.parametrize(("value", "reason"), [
    (150.5, "is not a whole number"),
    ("150", "it is a str"),
    (1e21, "outside the safe-integer range"),
    (-1.0, "it is -1"),
])
def test_an_observation_time_that_is_not_an_integer_is_refused(value: Any, reason: str) -> None:
    bridge, key, declaration, intent, args, tool_call, transcript = _bridge_fixture()
    changed = copy.deepcopy(transcript)
    changed["after"]["observed_at"] = value
    with pytest.raises(IntentBridgeError, match=re.escape(reason)):
        _verify_bridge(bridge, key, declaration, intent, args, tool_call, changed)


# ---- the revocation bundle ------------------------------------------------------


def test_a_revocation_bundle_decides_its_times_by_value() -> None:
    doc = json.loads(
        (ROOT / "examples" / "revocation-bundle" / "01-fresh-well-inside-both-bounds.json")
        .read_text()
    )
    ctx = doc["context"]

    def run(bundle: dict[str, Any]) -> Any:
        return verify_record(
            doc["records"][0], ctx["trusted_key"], now=ctx["now"],
            max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
            max_future_skew_seconds=ctx["max_future_skew_seconds"],
            revocation_bundle=bundle, trusted_bundle_keys=ctx["trusted_bundle_keys"],
        )

    bundle = ctx["bundle"]
    respelled = {**bundle, "issued_at": float(bundle["issued_at"]),
                 "valid_until": float(bundle["valid_until"])}
    assert run(respelled).revocation.outcome == "verified"
    assert bundle_digest(respelled) == bundle_digest(bundle)
    fractional = run({**bundle, "issued_at": bundle["issued_at"] + 0.5}).revocation
    assert (fractional.outcome, fractional.cause) == ("unverified_for_revocation",
                                                      "bundle_malformed")


# ---- the vectors, from their committed bytes ------------------------------------


def _doc(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _through_a_double(value: Any) -> Any:
    """*value* as RFC 8785 section 3.2.2.3 reads it: every number through a double."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and abs(value) > JCS_SAFE_INTEGER:
        return float(value)
    if isinstance(value, dict):
        return {k: _through_a_double(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_through_a_double(v) for v in value]
    return value


def _preimage(record: dict[str, Any]) -> bytes:
    return rfc8785.dumps(_through_a_double(_unsigned(record)))


def _expected(doc: dict[str, Any]) -> str | None:
    return None if doc["expected"]["outcome"] == "verified" else doc["expected"]["failure"]


def test_the_vector_set_is_complete() -> None:
    assert [p.name for p in FILES] == [
        "01-integer-spelling-verified.json",
        "02-fraction-spelling-verified.json",
        "03-exponent-spelling-verified.json",
        "04-fractional-value-rejected.json",
        "05-fractional-value-exponent-spelling-rejected.json",
        "06-above-range-integer-spelling-rejected.json",
        "07-above-range-exponent-spelling-rejected.json",
    ]


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_each_file_writes_its_member_in_the_spelling_it_declares(path: Path) -> None:
    """The spelling survives only in the file's text, so it is read from there. A tool
    that rewrites numbers while reformatting a fixture fails this, loudly."""
    text = path.read_text(encoding="utf-8")
    doc = json.loads(text)
    last = doc["member"].rsplit(".", 1)[-1]
    assert re.findall(rf'"{re.escape(last)}": ([^,\n]+)', text) == [doc["spelling"]]
    value, declared = _get(doc["record"], doc["member"]), json.loads(doc["spelling"])
    assert value == declared and type(value) is type(declared)


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_every_signature_in_the_set_is_valid(path: Path) -> None:
    """A rejecting vector with a broken signature would be rejected for the wrong reason
    and stop testing the rule it names."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    signature = doc["record"]["signature"]
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    _pubkey_from_jwk(doc["trusted_key"]).verify(raw, _preimage(doc["record"]))


def test_a_re_spelled_vector_is_its_twin_once_parsed() -> None:
    twins = {p.name: _doc(p.name)["same_signature_as"] for p in FILES
             if "same_signature_as" in _doc(p.name)}
    assert twins == {
        "02-fraction-spelling-verified.json": "01-integer-spelling-verified.json",
        "03-exponent-spelling-verified.json": "01-integer-spelling-verified.json",
        "05-fractional-value-exponent-spelling-rejected.json":
            "04-fractional-value-rejected.json",
    }
    for name, twin in twins.items():
        assert _doc(name)["record"] == _doc(twin)["record"]
        assert _preimage(_doc(name)["record"]) == _preimage(_doc(twin)["record"])
        assert (VECTORS / name).read_bytes() != (VECTORS / twin).read_bytes()


def test_each_vector_differs_from_01_in_its_member_alone() -> None:
    """With valid signatures, this leaves the member under test as the only reason a
    verifier can have to reject a vector that 01's verdict does not also cover."""
    def without(doc: dict[str, Any]) -> dict[str, Any]:
        record = _unsigned(copy.deepcopy(doc["record"]))
        *parents, last = doc["member"].split(".")
        target = record
        for name in parents:
            target = target[name]
        target.pop(last, None)
        return record

    first = _doc("01-integer-spelling-verified.json")
    for path in FILES:
        doc = _doc(path.name)
        assert without(doc) == without({**first, "member": doc["member"]}), path.name


def test_vector_01_is_the_verifier_compatibility_record_unchanged() -> None:
    ours = _doc("01-integer-spelling-verified.json")
    theirs = json.loads(
        (ROOT / "examples" / "verifier-compatibility" / "01-known-version-verified.json")
        .read_text(encoding="utf-8")
    )
    assert json.dumps(ours["record"]) == json.dumps(theirs["record"])
    assert ours["trusted_key"] == theirs["trusted_key"]


SCHEMA_SAYS = {
    "not_an_integer_value": "is not of type 'integer'",
    "outside_safe_integer_range": "is greater than the maximum of 9007199254740991",
}


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_the_reference_reaches_each_expected_outcome(path: Path) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    verifier = doc["verifier"]

    def run() -> Any:
        return verify_record(
            doc["record"], doc["trusted_key"], now=verifier["verification_time"],
            max_age_seconds=verifier["max_age_seconds"],
            max_future_skew_seconds=verifier["max_future_skew_seconds"],
        )

    failure = _expected(doc)
    if failure is None:
        run()
        return
    with pytest.raises(ValueError, match=re.escape(SCHEMA_SAYS[failure])):
        run()


# ---- adequacy: shortcuts the set has to catch -----------------------------------
# Criteria 3 and 4 of `tests/adequacy.py`, which each set implements for itself: a rule
# nothing pins, and a weakness shared by a rule's two vectors. Each shortcut below is a
# plausible way to implement "an integer member" that is not the value rule.


def _by_value(value: Any, spelling: str) -> str | None:
    try:
        _integer_value(value, "m")
    except ValueError as exc:
        return ("outside_safe_integer_range" if "outside the safe-integer range" in str(exc)
                else "not_an_integer_value")
    return None


def _range(n: int) -> str | None:
    return None if abs(n) <= JCS_SAFE_INTEGER else "outside_safe_integer_range"


def _by_python_type(value: Any, spelling: str) -> str | None:
    """The reference's freshness check before this change."""
    if isinstance(value, bool) or not isinstance(value, int):
        return "not_an_integer_value"
    return _range(value)


def _refuses_an_exponent(value: Any, spelling: str) -> str | None:
    return "not_an_integer_value" if "e" in spelling.lower() else _by_value(value, spelling)


def _strips_a_trailing_point_zero(value: Any, spelling: str) -> str | None:
    text = spelling[:-2] if spelling.endswith(".0") else spelling
    try:
        return _range(int(text))
    except ValueError:
        return "not_an_integer_value"


def _finds_a_fraction_by_its_decimal_point(value: Any, spelling: str) -> str | None:
    mantissa = spelling.lower().split("e")[0]
    if "." in mantissa and mantissa.split(".")[1].strip("0"):
        return "not_an_integer_value"
    return _range(int(value))


def _leaves_the_range_to_rfc8785(value: Any, spelling: str) -> str | None:
    """The range as the `rfc8785` package enforces it: on an `int` only."""
    failure = _by_value(value, spelling)
    return None if failure == "outside_safe_integer_range" and type(value) is float else failure


def _truncates(value: Any, spelling: str) -> str | None:
    """`int(value)`, with nothing checking what was cut off."""
    return _range(int(value))


SHORTCUTS: dict[str, Callable[[Any, str], str | None]] = {
    "by Python type": _by_python_type,
    "refuses an exponent": _refuses_an_exponent,
    "strips a trailing .0": _strips_a_trailing_point_zero,
    "finds a fraction by its decimal point": _finds_a_fraction_by_its_decimal_point,
    "leaves the range to rfc8785": _leaves_the_range_to_rfc8785,
    "truncates": _truncates,
}

# Which vectors each shortcut gets wrong: the README's claims, held to the set.
CAUGHT_BY = {
    "by Python type": ["02", "03", "07"],
    "refuses an exponent": ["03", "07"],
    "strips a trailing .0": ["03", "07"],
    "finds a fraction by its decimal point": ["03", "05"],
    "leaves the range to rfc8785": ["07"],
    "truncates": ["04", "05"],
}


def _wrong(decide: Callable[[Any, str], str | None]) -> list[str]:
    wrong = []
    for path in FILES:
        doc = _doc(path.name)
        if decide(_get(doc["record"], doc["member"]), doc["spelling"]) != _expected(doc):
            wrong.append(path.name[:2])
    return wrong


def test_the_value_rule_reproduces_every_vector() -> None:
    assert _wrong(_by_value) == []


@pytest.mark.parametrize("name", sorted(SHORTCUTS))
def test_each_shortcut_fails_the_vectors_the_readme_says_it_fails(name: str) -> None:
    assert _wrong(SHORTCUTS[name]) == CAUGHT_BY[name]


def test_each_rule_has_two_vectors_that_a_shortcut_tells_apart() -> None:
    """Two vectors for one rule are independent when some plausible shortcut is caught
    by one and not the other; two copies of one vector would never be told apart."""
    pairs = {"whole, however written": ("02", "03"),
             "not_an_integer_value": ("04", "05"),
             "outside_safe_integer_range": ("06", "07")}
    for rule, (a, b) in pairs.items():
        assert any((a in caught) != (b in caught) for caught in CAUGHT_BY.values()), rule


# ---- the scan and the JavaScript side -------------------------------------------


def _scan_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "scan_published_numbers", VECTORS / "scan_published_numbers.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_scan_knows_every_integer_member() -> None:
    assert _scan_module().integer_members() == {
        ("iat",), ("origin", "ingested_at"), ("tool_transcript", "call_count"),
        ("build_provenance", "slsa_level"), ("appraisal", "timestamp"),
        ("authorization", "authorized_at"), ("authorization", "expires_at"),
        ("issued_at",), ("valid_until",), ("revoked_at",),
        ("after", "observed_at"), ("tool_catalog", "tool_count"),
    }


def test_the_scan_finds_no_published_example_the_rule_changes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _scan_module().main([str(ROOT / "examples")]) == 0
    assert "skipped number-spelling/" in capsys.readouterr().out


def test_the_scan_finds_the_five_members_re_spelled_here() -> None:
    scan = _scan_module()
    found = scan.scan(VECTORS, scan.integer_members())["findings"]
    assert [f.split(":")[0][:2] for f in found] == ["02", "03", "04", "05", "07"]
    assert scan.main([str(VECTORS)]) == 1


def test_the_javascript_side_agrees() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed to run the JavaScript side of the proposal")
    version = subprocess.run([node, "--version"], capture_output=True, text=True, check=True)
    if int(version.stdout.strip().lstrip("v").split(".")[0]) < 20:
        pytest.skip("the JavaScript test runs on Node.js 20 or later")
    result = subprocess.run(
        [node, "--test", str(VECTORS / "spelling.test.mjs")],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr

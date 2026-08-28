"""Two validators, one record shape. A caller may reach either, so they have to agree.

``schema/trace-claim.json`` is the published artifact an implementation in any language
validates against. ``models.TrustRecord`` is the artifact a Python producer builds against,
and ``models.py`` already says why that matters: *"a model that accepts what the schema
rejects sends the failure downstream to whichever canonicalizer the producer happens to be
using."* Nothing checked the two against each other.

Mutating every field of a valid record across a value matrix found eight records the two
disagreed about. Four were booleans where JSON says integer. ``isinstance(True, int)`` is a
Python fact and not a JSON one: JSON Schema's ``"type": "integer"`` does not match ``true``,
so the schema rejected ``{"slsa_level": true}`` and the model accepted it **and coerced it
to 1**. The record was then a claim of SLSA build level 1 assembled out of a boolean, which
no other implementation would have validated. ``appraisal.timestamp`` did the same and read
``true`` as 1 January 1970.

``iat`` and ``origin.ingested_at`` did not have the hole, and were safe by accident rather
than by design: their lower bound sits above 1, so the coerced value failed the range check
after the coercion. They carry the guard now too, so the safety does not depend on a bound
nobody is thinking about when they change it.

The remaining four disagreements are one question and are declared below rather than fixed,
because answering it is a change to the published schema or a break for Python callers, and
neither is a test's decision to make.
"""
from __future__ import annotations

import copy
from typing import Any

import jsonschema
import pytest

from agentrust_trace import TrustRecord, validate_json

BASE: dict[str, Any] = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1750000000,
    "subject": "did:mesh:spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://agt.example.org/verifier"},
    "transparency": "https://rekor.sigstore.dev/api/v1/log/entries/example",
    "tool_transcript": {"hash": "sha256:" + "c" * 64, "call_count": 3},
    "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519",
                    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},
}

MUTANTS: tuple[Any, ...] = (
    "a-string", 123, None, [1, 2], True, False, 0, {}, "", -1, 1.5,
    10**20, 9007199254740992, "sha256:" + "z" * 64, "sha1:" + "a" * 40,
    "SHA256:" + "a" * 64, " ", "\t", "x" * 5000, "https://", "not-a-uri",
    "sha256:" + "A" * 64, "sha256:" + "a" * 63, "sha256:" + "a" * 65,
)

#: (path, repr of the value) the two are known to disagree about, and why it is not
#: fixed here. A disagreement not in this set fails the test. Removing one that has
#: been resolved is the other half: this set may not carry a row that now agrees.
#: Fields the schema types `format: uri` and the models type a bare `str`.
#:
#: `jsonschema` enforces `format` only when a checker for it is installed, so whether
#: these fields diverge depends on the environment rather than on either artifact. With
#: the checker absent the format is inert and the two agree; with it present the schema
#: refuses any non-URI and the models accept it. Both readings are correct about the
#: code, so the set is computed rather than fixed, and the reason is the same either
#: way: mirroring `format: uri` in the models is its own change.
_URI_FORMAT_ENFORCED = "uri" in jsonschema.FormatChecker().checkers
FIELDS_WITH_NO_URI_VALIDATION_IN_THE_MODEL = (
    {"appraisal.verifier", "transparency"} if _URI_FORMAT_ENFORCED else set()
)

DECLARED_DIVERGENCES: dict[tuple[str, str], str] = {
    ("transparency", "None"):
        "explicit JSON null for an optional field: the schema types it 'string' and "
        "does not permit null, the model types it 'str | None'. Resolving it means "
        "either 'type': ['string', 'null'] in the published schema or refusing None "
        "from Python callers, and both are somebody's decision rather than a test's.",
    ("tool_transcript", "None"): "the same question, on an optional object.",
    ("tool_transcript.call_count", "None"): "the same question, on an optional integer.",
    ("transparency", "''"):
        "the opposite direction: the model carries min_length=1 and the schema has no "
        "minLength, so the schema admits an empty URI that the model refuses. Adding "
        "minLength to the schema is a change to the published artifact.",
}


def _by_schema(record: dict[str, Any]) -> bool:
    try:
        validate_json(record)
    except Exception:  # noqa: BLE001 - accept or reject is the whole signal
        return False
    return True


def _by_model(record: dict[str, Any]) -> bool:
    try:
        TrustRecord.model_validate(record)
    except Exception:  # noqa: BLE001
        return False
    return True


def _paths(obj: Any, prefix: tuple[str, ...] = ()) -> Any:
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield prefix + (key,)
            yield from _paths(value, prefix + (key,))


def _set(obj: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = value


def test_the_base_record_passes_both() -> None:
    """The control. Every comparison below is meaningless if the starting point is not
    valid to both, and an incomplete fixture is the easy way to get a clean run that
    measured nothing."""
    assert _by_schema(BASE), "the schema rejects the base record"
    assert _by_model(BASE), "the model rejects the base record"


def _disagreements() -> dict[tuple[str, str], tuple[bool, bool]]:
    found: dict[tuple[str, str], tuple[bool, bool]] = {}
    for path in list(_paths(BASE)):
        for mutant in MUTANTS:
            record = copy.deepcopy(BASE)
            _set(record, path, mutant)
            schema, model = _by_schema(record), _by_model(record)
            if schema != model:
                found[(".".join(path), repr(mutant)[:26])] = (schema, model)
    return found


def test_the_sweep_covers_the_record() -> None:
    """A walk that found nothing to mutate would pass every test in this file."""
    assert len(list(_paths(BASE))) >= 25
    assert len(MUTANTS) >= 20


def test_the_two_validators_agree_except_where_declared() -> None:
    found = _disagreements()

    undeclared = {
        k: v for k, v in found.items()
        if k not in DECLARED_DIVERGENCES
        and k[0] not in FIELDS_WITH_NO_URI_VALIDATION_IN_THE_MODEL
    }
    assert not undeclared, (
        "the schema and the model disagree about records not declared in "
        "DECLARED_DIVERGENCES:\n" + "\n".join(
            f"  {path} = {value}: schema={s}, model={m}"
            for (path, value), (s, m) in sorted(undeclared.items())
        ) + "\nOne of the two is wrong. The schema is the published artifact, so a "
        "record the model accepts and the schema rejects is one no other "
        "implementation will validate."
    )


def test_no_declared_divergence_has_quietly_been_resolved() -> None:
    """The other half of the declaration. A stale entry reads as an open question that
    somebody still owes an answer to, and it is not."""
    found = _disagreements()
    stale = sorted(
        k for k in set(DECLARED_DIVERGENCES) - set(found)
        if k[0] not in FIELDS_WITH_NO_URI_VALIDATION_IN_THE_MODEL
    )
    assert not stale, f"these now agree and should be removed from the set: {stale}"


@pytest.mark.parametrize("path", [
    ("build_provenance", "slsa_level"),
    ("tool_transcript", "call_count"),
    ("appraisal", "timestamp"),
    ("iat",),
])
@pytest.mark.parametrize("value", [True, False])
def test_no_integer_field_accepts_a_boolean(path: tuple[str, ...], value: bool) -> None:
    """Named separately from the sweep because the coercion is the part that matters.

    Accepting `true` would be a permissiveness bug. Reading it as 1 makes a claim the
    producer never wrote: SLSA build level 1, one tool call, or an appraisal timestamped
    1 January 1970.
    """
    record = copy.deepcopy(BASE)
    _set(record, path, value)

    assert not _by_schema(record), "the schema should reject a boolean here"
    assert not _by_model(record), (
        f"{'.'.join(path)} accepted {value!r}; before this guard it became "
        f"{int(value)!r} and the record claimed it"
    )

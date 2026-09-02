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

A fifth was found later, by a producer rather than by this file, and is the reason the matrix
carries four more values. ``subject``'s schema pattern was ``^(spiffe://|did:)``, a test on a
leading ``spiffe://`` or ``did:``, while the model required a full SPIFFE or DID shape.
Nothing in the matrix could see it: every value here fails the prefix as well, so both
validators rejected and agreed. Splitting them needs a value that passes the prefix and fails
the shape, and ``spiffe://bernstein.run`` is one a real producer wrote. The schema is
tightened to the model in the same change; the four values stay as the guard that would have
caught it.

That fifth one is why the second half of this file exists. A hand-written matrix swept over
one base record answers "do the two disagree about any of these values", and the floors below
keep it from answering that about nothing. What it cannot answer is "is each constraint
*discriminated* at all" - whether the values reach the constraint's own boundary, or merely
fail so early that both validators reject for an unrelated reason and agree by accident. Two
gaps followed from that, and neither produced a failing test:

1. **Half the patterns were unreachable.** ``BASE`` carries five of the schema's ten pattern
   constraints. ``model.weights_digest``, ``delegation.parent_record_hash``,
   ``references[].retention``, ``references[].digest`` and ``signature`` are all optional, all
   absent from the fixture, and therefore never mutated. A sweep cannot disagree about a field
   it never sets.
2. **The mirroring was claimed and not held.** ``models.py`` says its pattern constants are
   "mirrored verbatim in schema/trace-claim.json and its copy, and held there by
   tests/test_the_schema_and_the_models_agree.py". They were not held here. Two of the ten
   were pinned in ``test_references_block.py``; the other eight were maintained by hand under
   a comment that named this file.

The generator below closes both. It reads the ten patterns out of the schema rather than
listing them, so a new one cannot be added without appearing here; it probes each at its own
boundary with values derived from the pattern and from a valid instance of it; and for each
constraint it demands one of three outcomes - the two artifacts hold the same pattern string,
in which case no string can split them and that is a proof rather than an observation; or a
splitting value exists and is declared; or the constraint is neither, which fails.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, get_args, get_origin

import jsonschema
import pytest
from pydantic import BaseModel

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
    # A prefix the schema accepted and the model refused. The first matrix could not
    # reach this class at all: `subject`'s schema pattern was a prefix test, so every
    # value above failed it too and the two validators agreed by both rejecting. A
    # value has to pass the prefix and fail on the shape to split them, and none did.
    "spiffe://bernstein.run", "spiffe://", "did:X:abc", "did:",
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


# ---------------------------------------------------------------------------
# Per-constraint discrimination
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_SCHEMA: dict[str, Any] = json.loads(
    (REPO_ROOT / "schema" / "trace-claim.json").read_text(encoding="utf-8")
)

#: A record valid to both validators that carries every pattern-constrained field.
#: ``BASE`` above is deliberately the minimum a producer must emit; five of the ten
#: pattern constraints sit on optional members it omits, and an absent field cannot
#: be mutated into a disagreement.
FULL: dict[str, Any] = {
    **copy.deepcopy(BASE),
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6",
              "weights_digest": "sha256:" + "d" * 64},
    "delegation": {"parent_record_hash": "sha256:" + "e" * 64,
                   "credential_id": "trace-spec-delegation-credential"},
    "references": [{"rel": "behavior-trace", "id": "run-1",
                    "resolver": "https://agt.example.org",
                    "digest": "sha256:" + "f" * 64, "retention": "P30D"}],
    "signature": "abcDEF-_123",
}

#: Pattern constraints the two artifacts do NOT hold as the same string, for which no
#: probe splits them either. Empty today, and it should stay that way: a constraint
#: that is neither mirrored nor split is one nothing is checking. An entry here says
#: a human looked and decided, which is the same contract as ``DECLARED_DIVERGENCES``.
UNMIRRORED_AND_UNSPLIT: dict[str, str] = {}

_LITERAL_RUN = re.compile(r"[A-Za-z0-9_.:/\-]{2,}")


def _pattern_constraints(schema: dict[str, Any]) -> dict[tuple[str, ...], str]:
    """Every ``pattern`` in *schema*, keyed by its path in a record.

    Read out of the schema rather than listed, so a pattern added to the published
    artifact cannot be added without this file noticing it.
    """
    found: dict[tuple[str, ...], str] = {}

    def walk(node: Any, path: tuple[str, ...]) -> None:
        if not isinstance(node, dict):
            return
        if isinstance(node.get("pattern"), str):
            found[path] = node["pattern"]
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                for prop, sub in value.items():
                    walk(sub, path + (prop,))
            elif key == "items":
                walk(value, path + ("0",))
            elif key in ("allOf", "anyOf", "oneOf") and isinstance(value, list):
                for sub in value:
                    walk(sub, path)

    walk(schema, ())
    return found


def _get(obj: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        obj = obj[int(key)] if isinstance(obj, list) else obj[key]
    return obj


def _set_deep(obj: Any, path: tuple[str, ...], value: Any) -> None:
    for key in path[:-1]:
        obj = obj[int(key)] if isinstance(obj, list) else obj[key]
    if isinstance(obj, list):
        obj[int(path[-1])] = value
    else:
        obj[path[-1]] = value


def _probes(pattern: str, valid: str) -> list[str]:
    """Values that sit on *pattern*'s boundary, derived from it and from *valid*.

    The classes, and what each is for:

    * **structural prefixes of a valid value** - the #244 class. A pattern that tests a
      prefix accepts ``spiffe://`` while a model requiring the full shape refuses it;
      nothing that fails the prefix can tell the two apart, because both reject.
    * **literal runs taken out of the pattern text** - the same class reached from the
      other side, and the reason ``did:`` appears without anyone writing it here.
    * **case flip, one character shorter, one longer, one outside the class** - the
      length and alphabet boundaries of a fixed-width constraint.
    * **empty, space, tab** - the values a producer sends when a field is unset.
    """
    out: list[str] = []
    for sep in ("://", ":", "/"):
        start = valid.find(sep)
        while start != -1:
            out.append(valid[: start + len(sep)])
            start = valid.find(sep, start + 1)
    out += [valid.swapcase(), valid[:-1], valid + valid[-1:], valid[:-1] + "§", "", " ", "\t"]
    out += _LITERAL_RUN.findall(pattern)
    return list(dict.fromkeys(out))


def _splitters(path: tuple[str, ...], pattern: str) -> list[tuple[str, bool, bool]]:
    """Probes at *path* the two validators disagree about.

    Raises ``LookupError`` naming *path* when ``FULL`` does not reach it, rather than
    letting the plain ``KeyError`` out of ``_get`` propagate. This is the same gap
    ``test_the_fixture_reaches_every_pattern_in_the_schema`` already reports by field
    name via ``_reachable``; this read the path unguarded.
    """
    if not _reachable(FULL, path):
        raise LookupError(
            f"{'.'.join(path)}: pattern {pattern!r} constrains a path FULL does not "
            "reach, so nothing here can probe it"
        )
    valid = _get(FULL, path)
    split: list[tuple[str, bool, bool]] = []
    for probe in _probes(pattern, valid):
        record = copy.deepcopy(FULL)
        _set_deep(record, path, probe)
        by_schema, by_model = _by_schema(record), _by_model(record)
        if by_schema != by_model:
            split.append((probe, by_schema, by_model))
    return split


def _model_pattern_strings() -> set[str]:
    """Every pattern string the reference model constrains a field with.

    Walked rather than listed, and walked through three indirections, because the
    constraint is rarely where the obvious read looks for it. An optional field is
    ``Annotated[str, Field(pattern=...)] | None``, so the pattern sits on a union member
    and ``field.metadata`` is empty; the union member's ``__metadata__`` holds a
    ``FieldInfo``, and the pattern is inside *its* metadata in turn. Reading only the
    first of the three missed ``signature`` here, which is the same shape of miss the
    rest of this file is about.
    """
    from agentrust_trace import models

    strings = {
        value
        for name, value in vars(models).items()
        if name.endswith("_RE") and isinstance(value, str)
    }

    def constraints_of(obj: Any) -> None:
        found = getattr(obj, "pattern", None)
        if isinstance(found, str):
            strings.add(found)
        for nested in getattr(obj, "metadata", ()) or ():
            constraints_of(nested)

    seen: set[Any] = set()

    def walk(annotation: Any) -> None:
        try:
            if annotation in seen:
                return
            seen.add(annotation)
        except TypeError:  # unhashable annotation; nothing below it to revisit
            pass
        for meta in getattr(annotation, "__metadata__", ()) or ():
            constraints_of(meta)
        fields = getattr(annotation, "model_fields", None)
        if isinstance(fields, dict):
            for field in fields.values():
                for meta in field.metadata:
                    constraints_of(meta)
                walk(field.annotation)
        for arg in get_args(annotation):
            walk(arg)

    walk(TrustRecord)
    return strings


def _pattern_of(obj: Any) -> str | None:
    """The pattern *obj* itself carries, or that sits inside its own metadata.

    The single-object half of the three-indirection read ``_model_pattern_strings``
    documents: a required field's constraint is one hop down, in ``field.metadata``;
    this recurses to find it there without assuming how many hops down it is.
    """
    found = getattr(obj, "pattern", None)
    if isinstance(found, str):
        return found
    for nested in getattr(obj, "metadata", ()) or ():
        result = _pattern_of(nested)
        if result is not None:
            return result
    return None


def _own_pattern(field: Any) -> str | None:
    """The pattern *field* itself is constrained by, direct or optional.

    A required field's constraint is found by ``_pattern_of`` alone. An optional
    field is ``Annotated[str, Field(pattern=...)] | None``, so ``field.metadata`` is
    empty and the constraint sits on the ``Annotated`` union member's own
    ``__metadata__`` instead; the second loop is that indirection.
    """
    pattern = _pattern_of(field)
    if pattern is not None:
        return pattern
    for member in get_args(field.annotation):
        for meta in getattr(member, "__metadata__", ()) or ():
            pattern = _pattern_of(meta)
            if pattern is not None:
                return pattern
    return None


def _nested_model(annotation: Any) -> type[BaseModel] | None:
    """*annotation* itself, or the non-``None`` member of ``X | None``, when it is a
    ``BaseModel`` subclass."""
    for candidate in (annotation, *get_args(annotation)):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return None


def _nested_list_item_model(annotation: Any) -> type[BaseModel] | None:
    """The item type of ``list[X]``, or of ``list[X] | None``, when ``X`` is a
    ``BaseModel`` subclass."""
    for candidate in (annotation, *get_args(annotation)):
        if get_origin(candidate) is list:
            (item,) = get_args(candidate) or (None,)
            if isinstance(item, type) and issubclass(item, BaseModel):
                return item
    return None


def _model_field_patterns(
    model: type[BaseModel] = TrustRecord, prefix: tuple[str, ...] = ()
) -> dict[tuple[str, ...], str]:
    """Every field's own pattern constraint in *model*, keyed by its path in a record
    the same way ``_pattern_constraints`` keys the schema's.

    ``_model_pattern_strings`` collects every pattern the model carries, anywhere,
    into one flat set: it can say a string is spoken for *somewhere*, not that a
    given field is the one speaking for it. This keeps each pattern attached to the
    specific field it constrains, so a schema constraint at a path can be compared to
    that same path's own model constraint instead of to membership in the set of all
    of them.
    """
    found: dict[tuple[str, ...], str] = {}
    for name, field in model.model_fields.items():
        path = prefix + (name,)
        pattern = _own_pattern(field)
        if pattern is not None:
            found[path] = pattern
        nested = _nested_model(field.annotation)
        if nested is not None:
            found.update(_model_field_patterns(nested, path))
        item_model = _nested_list_item_model(field.annotation)
        if item_model is not None:
            found.update(_model_field_patterns(item_model, path + ("0",)))
    return found


def test_the_full_record_passes_both() -> None:
    """The control for everything below, same reason as the one above."""
    assert _by_schema(FULL), "the schema rejects the full record"
    assert _by_model(FULL), "the model rejects the full record"


def test_the_fixture_reaches_every_pattern_in_the_schema() -> None:
    """The gap this half of the file was written for.

    ``BASE`` reaches five of ten. A constraint on a field the fixture omits is never
    mutated, never disagreed about, and reads in a green run exactly like a constraint
    the two artifacts agree on.
    """
    constraints = _pattern_constraints(CANONICAL_SCHEMA)
    assert len(constraints) >= 10, "the schema lost pattern constraints; check before relaxing this"
    missing = sorted(".".join(p) for p in constraints if not _reachable(FULL, p))
    assert not missing, (
        "these pattern constraints are not present in FULL, so nothing probes them:\n  "
        + "\n  ".join(missing)
    )


def _reachable(record: dict[str, Any], path: tuple[str, ...]) -> bool:
    try:
        _get(record, path)
    except (KeyError, IndexError, TypeError, ValueError):
        return False
    return True


def _unaccounted_patterns(
    schema: dict[str, Any], model_field_patterns: dict[tuple[str, ...], str]
) -> list[str]:
    """Every pattern constraint in *schema* that lands in neither of the two silent
    states, checked against *model_field_patterns* (a path-keyed map, so a schema
    constraint is compared to that same field's own model constraint rather than to
    membership in the set of every pattern the model carries anywhere).

    Parameterized over both, rather than reading ``CANONICAL_SCHEMA`` and
    ``TrustRecord`` directly, so the counterfactual test below can run the same check
    against a mutated copy of the schema.
    """
    unaccounted: list[str] = []
    for path, pattern in sorted(_pattern_constraints(schema).items()):
        dotted = ".".join(path)
        if model_field_patterns.get(path) == pattern:
            continue
        try:
            split = _splitters(path, pattern)
        except LookupError as exc:
            unaccounted.append(str(exc))
            continue
        declared = [s for s in split if (dotted, repr(s[0])[:26]) in DECLARED_DIVERGENCES]
        if split and len(declared) == len(split):
            continue
        if dotted in UNMIRRORED_AND_UNSPLIT:
            continue
        undeclared = [repr(s[0]) for s in split if s not in declared]
        unaccounted.append(
            f"{dotted}: schema pattern {pattern!r} is not one the model carries; "
            + (
                f"probes that split the two and are not declared: {undeclared}"
                if undeclared
                else "and no probe splits them, so nothing here is checking this constraint"
            )
        )
    return unaccounted


def test_every_pattern_is_mirrored_or_split_or_declared() -> None:
    """Each of the ten constraints must land in one of three states, none of them silent.

    *Mirrored*: the model constrains the field with the same pattern string the schema
    publishes. Then no string can split the two, and saying so is a proof rather than an
    observation about the values that happened to be tried.

    *Split*: a probe the two disagree about, which belongs in ``DECLARED_DIVERGENCES``
    with the reason it is not simply fixed.

    *Neither*: the two carry different patterns and nothing here can tell them apart.
    That is the state ``models.py`` already claims is impossible, and the one that
    produced #244, so it fails unless a human has written down why.
    """
    unaccounted = _unaccounted_patterns(CANONICAL_SCHEMA, _model_field_patterns())
    assert not unaccounted, "\n".join(unaccounted)


def test_no_unmirrored_declaration_has_quietly_been_resolved() -> None:
    """The other half of ``UNMIRRORED_AND_UNSPLIT``, same contract as the divergence set."""
    model_patterns = _model_pattern_strings()
    constraints = {".".join(p): pat for p, pat in _pattern_constraints(CANONICAL_SCHEMA).items()}
    stale = sorted(
        dotted
        for dotted in UNMIRRORED_AND_UNSPLIT
        if dotted not in constraints or constraints[dotted] in model_patterns
    )
    assert not stale, f"these are mirrored or gone and should leave the set: {stale}"


def test_the_generator_reaches_the_prefix_class_the_matrix_could_not() -> None:
    """The counterfactual. Without it the eight tests above prove only that today is fine.

    #244 is replayed by putting the pre-fix prefix pattern back on ``subject`` in a copy
    of the schema, and asserting the generated probes split the two validators against
    it. They do, on ``spiffe://`` among others - a value nobody wrote into this file, and
    the class the hand-written matrix could not reach, because every value in it fails a
    prefix test as well and both validators agreed by rejecting.
    """
    before = copy.deepcopy(CANONICAL_SCHEMA)
    before["properties"]["subject"]["pattern"] = "^(spiffe://|did:)"
    validator = jsonschema.Draft202012Validator(
        before, format_checker=jsonschema.FormatChecker()
    )

    split = []
    for probe in _probes(CANONICAL_SCHEMA["properties"]["subject"]["pattern"], FULL["subject"]):
        record = copy.deepcopy(FULL)
        record["subject"] = probe
        if validator.is_valid(record) != _by_model(record):
            split.append(probe)

    assert "spiffe://" in split, (
        "the generator no longer reaches the prefix class: against the pre-#244 schema it "
        f"split the validators on {split!r}, which does not include the value a producer "
        "actually sent"
    )


def test_the_mirror_check_is_by_field_not_flat_membership() -> None:
    """Review counterfactual: a pattern *string* genuinely used somewhere in the model
    must not read as mirroring a field it does not itself constrain.

    Reassigns ``references[].retention``'s own model pattern onto
    ``build_provenance.digest`` in a copy of the schema. The model still constrains
    ``build_provenance.digest`` with the digest pattern, not the duration one, so a
    check that only asks "is this string spoken for somewhere in the model" - a flat
    set, checked by membership - would wrongly call the two mirrored and skip probing
    the field entirely. ``_model_field_patterns`` is keyed by field for exactly this
    reason.
    """
    model_field_patterns = _model_field_patterns()
    duration_pattern = model_field_patterns[("references", "0", "retention")]
    collision_path = ("build_provenance", "digest")
    assert model_field_patterns[collision_path] != duration_pattern, (
        "setup: build_provenance.digest must genuinely carry a different constraint "
        "from references[].retention for this to test anything"
    )

    mutated = copy.deepcopy(CANONICAL_SCHEMA)
    mutated["properties"]["build_provenance"]["properties"]["digest"]["pattern"] = (
        duration_pattern
    )

    unaccounted = _unaccounted_patterns(mutated, model_field_patterns)
    assert any(entry.startswith("build_provenance.digest:") for entry in unaccounted), (
        "a schema pattern reassigned onto a field the model does not constrain with it "
        "must be flagged, even though the pattern string itself is genuinely in use "
        "elsewhere in the model:\n" + "\n".join(unaccounted)
    )


def test_a_missing_path_fails_with_the_field_name_not_a_keyerror() -> None:
    """Review counterfactual: a pattern on a field ``FULL`` omits must fail naming
    that field, not with a raw ``KeyError`` out of ``_get``.

    ``test_the_fixture_reaches_every_pattern_in_the_schema`` already catches the same
    reachability gap cleanly, by field name, via ``_reachable``. ``_splitters`` is the
    other place that reads an arbitrary schema path out of ``FULL``, and it read the
    path unguarded, so the same gap surfaced there as a bare ``KeyError`` instead.
    """
    bogus_path = ("build_provenance", "does_not_exist_in_full")
    assert not _reachable(FULL, bogus_path), "setup: the path must genuinely be absent from FULL"

    with pytest.raises(Exception) as excinfo:
        _splitters(bogus_path, "^irrelevant$")

    assert not isinstance(excinfo.value, KeyError), (
        f"a missing path must not surface as a raw KeyError: {excinfo.value!r}"
    )
    assert "build_provenance.does_not_exist_in_full" in str(excinfo.value), (
        f"the failure must name the missing field; got {excinfo.value!r}"
    )

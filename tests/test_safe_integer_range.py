"""The JCS safe-integer range, spec section 3.2.2 (issue: number serialization).

Section 3.2.2 serializes numbers as IEEE 754 doubles, so `9007199254740992` and
`9007199254740993` reach one canonical form and one signature stands for two
objects. RFC 8785 Appendix B note 1 names the range this repository now holds
every signed object to, and section 3.2.2 raises that note's SHOULD to a MUST.

These tests grew out of `test_canonicalization_boundary.py`, whose subject is the
four vectors that separate a conformant canonicalizer from `json.dumps`. The
number surface cannot be carried by a vector at all, because a positive vector is
a schema-valid record and these are exactly the records the schema now rejects,
so it is carried here instead: structurally, behaviourally, and by pinning the
prose that states the rule to the fact it states.

`examples/canonicalization-boundary/number_divergence_repro.py` reproduces the
whole argument on the standard library alone, and one of the tests below runs it.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import rfc8785

from agentrust_trace.validate import validate_json

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_DIR = REPO_ROOT / "examples" / "canonicalization-boundary"
# Named rather than indexed off a glob: the vector list is pinned in
# test_canonicalization_boundary.py, not here, so `sorted(...)[0]` would quietly
# become a different record the day a vector is added.
BASE_RECORD = FIXTURE_DIR / "01-non-ascii-values.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _signing_input(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "signature"}


SAFE_INTEGER = 2**53 - 1

# Every JSON Schema in the repository, classified. A schema whose signature is
# defined over an RFC 8785 canonical form must bound its integer fields to the
# safe-integer domain; the rest carry the reason they do not.
BOUNDED_SCHEMAS = (
    "schema/pic-trace-bridge-v1.json",
    "schema/trace-claim.json",
    "schema/trace-revocation.json",
    "schema/trace-revocation-bundle.json",
    "src/agentrust_trace/schema/trace-v0.2.json",
    # Packaged copies of the two revocation schemas, read by `revocation.py` so the
    # installed package validates bundles without the repository and without the
    # network. `tests/test_revocation_bundle.py` holds each byte-identical to its
    # source under `schema/`.
    "src/agentrust_trace/schema/trace-revocation.json",
    "src/agentrust_trace/schema/trace-revocation-bundle.json",
)
UNBOUNDED_SCHEMAS = {
    "src/agentrust_trace/schema/trace-v0.1.json": (
        "superseded, and loaded by nothing: verify_record rejects the v0.1 profile "
        "identifier outright, so no record in this repository is validated against "
        "this file and editing it would change a published artifact for no effect"
    ),
}


def _integer_nodes(node: Any, path: str = "") -> list[tuple[str, dict[str, Any]]]:
    """Every ``"type": "integer"`` subschema, located by walking, not by grep.

    A regex over the file counts a field once per textual match and misses one
    written inside a ``$defs`` block or a composed ``allOf``.
    """
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(node, dict):
        if node.get("type") == "integer":
            found.append((path, node))
        for key, value in node.items():
            found += _integer_nodes(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found += _integer_nodes(value, f"{path}/{index}")
    return found


def _within_domain(node: dict[str, Any]) -> bool:
    """True when this integer subschema admits only safe integers.

    ``exclusiveMaximum: 2**53`` bounds a field exactly as tightly as
    ``maximum: 2**53 - 1``; treating the two the same keeps the check from
    reporting a correctly bounded field as unbounded.
    """
    low, high = None, None
    if "minimum" in node:
        low = node["minimum"]
    elif "exclusiveMinimum" in node:
        low = node["exclusiveMinimum"] + 1
    if "maximum" in node:
        high = node["maximum"]
    elif "exclusiveMaximum" in node:
        high = node["exclusiveMaximum"] - 1
    if low is None or high is None:
        return False
    return -SAFE_INTEGER <= low and high <= SAFE_INTEGER


def _schemas_on_disk() -> set[str]:
    return {
        str(path.relative_to(REPO_ROOT))
        for path in list((REPO_ROOT / "schema").rglob("*.json"))
        + list((REPO_ROOT / "src" / "agentrust_trace" / "schema").rglob("*.json"))
    }


def test_every_schema_in_the_repository_is_classified() -> None:
    """The classification is pinned, so a new schema cannot arrive unclassified.

    Without this, adding a schema with an unbounded integer field leaves every
    other assertion in this file green and the boundary silently uncovered again.
    """
    assert _schemas_on_disk() == set(BOUNDED_SCHEMAS) | set(UNBOUNDED_SCHEMAS)


def test_the_superseded_schema_is_still_loaded_by_nothing() -> None:
    """The exemption rests on a fact, so the fact is checked.

    `schema/pic-trace-bridge-v1.json` was exempted here on the reasoning that it
    declared no canonicalization, which was read off the schema file. The code
    that signs a bridge artifact calls the same `_canonical_bytes` as everything
    else, so the exemption was wrong and hid the identical defect. The lesson is
    that an exemption reason nobody measures is how a defect stays exempt.

    The reason left is that nothing loads the v0.1 schema. That is checkable, and
    the exclusion below is written as `Path(__file__).name` rather than as a
    literal: the first version named the file it lived in, and renaming that file
    made this test find its own mention and fail.
    """
    referenced = [
        str(path.relative_to(REPO_ROOT))
        for path in sorted(REPO_ROOT.rglob("*.py"))
        if ".venv" not in path.parts
        and path.name != Path(__file__).name  # this file names it to exempt it
        and "trace-v0.1.json" in path.read_text(encoding="utf-8")
    ]
    assert not referenced, (
        f"trace-v0.1.json is now referenced by {referenced}, so it is no longer "
        "exempt on the grounds that nothing loads it. Bound it or record a reason "
        "that is true."
    )


@pytest.mark.parametrize("relative", sorted(UNBOUNDED_SCHEMAS))
def test_an_unbounded_schema_is_still_unbounded(relative: str) -> None:
    """The exemptions are checked in the other direction too.

    An exemption that no longer describes the file is worse than no exemption: it
    reads as a considered decision while the schema it names has quietly changed.
    If one of these acquires bounds on every integer field, it belongs in
    ``BOUNDED_SCHEMAS`` and its reason belongs deleted.
    """
    schema = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
    outside = [path for path, node in _integer_nodes(schema) if not _within_domain(node)]
    assert outside, (
        f"{relative} is exempted on the grounds that it {UNBOUNDED_SCHEMAS[relative]}, "
        "but every integer field in it is now inside the safe-integer domain. Move it "
        "to BOUNDED_SCHEMAS."
    )


@pytest.mark.parametrize("relative", BOUNDED_SCHEMAS)
def test_no_schema_field_is_typed_number(relative: str) -> None:
    """No declared field is typed ``number``.

    This is half a guard on its own, and was the whole of the old one. A record
    also carries members no field declares, and until they were constrained a
    float could enter through one of those with every declared field still typed
    correctly. ``test_no_object_leaves_an_additional_member_unconstrained`` is the
    other half. The day a ``number`` field is wanted, this test is the place to
    argue for it: the divergence there is about the shortest round-tripping form
    rather than about domain, and no bound fixes it.
    """
    schema = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))

    def types(node: Any) -> set[str]:
        found: set[str] = set()
        if isinstance(node, dict):
            declared = node.get("type")
            if isinstance(declared, str):
                found.add(declared)
            elif isinstance(declared, list):
                found.update(t for t in declared if isinstance(t, str))
            for value in node.values():
                found |= types(value)
        elif isinstance(node, list):
            for item in node:
                found |= types(item)
        return found

    assert "number" not in types(schema), f"{relative} types a field as number"


@pytest.mark.parametrize("relative", BOUNDED_SCHEMAS)
def test_every_integer_field_is_inside_the_safe_integer_domain(relative: str) -> None:
    """Section 3.2.2 serializes numbers as IEEE 754 doubles, so the schema must not
    admit an integer that has no double.

    An unbounded integer field admits a record no canonicalizer can turn into one
    unambiguous pre-image. Measured on two independent RFC 8785 implementations:
    `rfc8785` 0.1.4 refuses the value, and `canonicalize` 4.0.0 emits the same
    bytes for it as for the integer next to it, which is where two distinct records
    acquire one signature.
    """
    schema = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
    fields = _integer_nodes(schema)
    assert fields, f"{relative}: no integer fields found, so this test proves nothing"

    unbounded = [
        f"{path} {{{', '.join(f'{k}: {v}' for k, v in node.items() if 'imum' in k)}}}"
        for path, node in fields
        if not _within_domain(node)
    ]
    assert not unbounded, (
        f"{relative}: integer fields outside the safe-integer domain: {unbounded}. "
        "A record using one is schema-valid and has no canonical form."
    )


def _object_nodes(node: Any, path: str = "") -> list[tuple[str, dict[str, Any]]]:
    """Every subschema that declares ``"type": "object"``.

    Declaring the type is what separates an object in the record from an
    applicator subschema: the ``if`` and ``then`` branches under ``cnf.jwk``'s
    ``allOf`` carry ``properties`` but describe a condition, not a container, and
    ``additionalProperties`` on them would constrain nothing.
    """
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(node, dict):
        if node.get("type") == "object":
            found.append((path, node))
        for key, value in node.items():
            found += _object_nodes(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found += _object_nodes(value, f"{path}/{index}")
    return found


@pytest.mark.parametrize("relative", BOUNDED_SCHEMAS)
def test_no_object_leaves_an_additional_member_unconstrained(relative: str) -> None:
    """Bounding the declared fields is not bounding the record.

    The signature covers every member of the object, declared or not. `cnf.jwk`
    is open on purpose, because RFC 7517 permits members this schema does not
    name and vectors 03 and 04 are built out of exactly that, but open and
    unconstrained are different things. While it was unconstrained, two records
    identical except for `cnf.jwk` carrying 9007199254740992 and 9007199254740993
    produced one canonical form, with every declared field inside its bound.

    An object either closes to `additionalProperties: false` or holds its
    undeclared members to `#/$defs/canonicalizableValue`. Absent is neither, and
    absent means true.
    """
    schema = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
    objects = _object_nodes(schema)
    assert objects, f"{relative}: no object nodes found, so this test proves nothing"

    permitted = ({"$ref": "#/$defs/canonicalizableValue"}, False)
    loose = [
        f"{path or '/'}: additionalProperties={node.get('additionalProperties', 'absent')}"
        for path, node in objects
        if node.get("additionalProperties", "absent") not in permitted
    ]
    assert not loose, (
        f"{relative}: objects accepting an unconstrained member: {loose}. A member "
        "no field declares is still covered by the signature and still has to be "
        "canonicalizable."
    )


@pytest.mark.parametrize(
    "value, accepted",
    [
        (SAFE_INTEGER, True),
        (2**53, False),
        (2**53 + 1, False),
        (-(2**53), False),
        (1.5, False),
        ("kid-1", True),
        (["MIIB", "MIIC"], True),
        ([2**53 + 1], False),
        ({"nested": {"deeper": "still a string"}}, True),
        ({"nested": {"deeper": 2**53 + 1}}, False),
        (True, True),
        (None, True),
    ],
)
def test_an_undeclared_jwk_member_is_held_to_the_same_rule(
    value: Any, accepted: bool
) -> None:
    """The constraint on undeclared members, measured rather than read.

    The structural test above says `cnf.jwk` names a `$ref`. This says what the
    `$ref` does, including through an array and through a nested object, which is
    where a recursive definition is easy to get wrong and impossible to see wrong.
    The two cases that must pass are the shapes a real JWK uses: a string member,
    and an `x5c`-style array of them.
    """
    record = json.loads(json.dumps(_load(BASE_RECORD)["record"]))
    record["cnf"]["jwk"]["ext"] = value
    if accepted:
        validate_json(record)
    else:
        with pytest.raises(jsonschema.ValidationError):
            validate_json(record)


def _maximal_record() -> dict[str, Any]:
    """A schema-valid record that reaches every property the schema declares.

    The fixtures in this directory omit `origin`, `delegation`, `references`,
    `tool_transcript` and `appraisal.timestamp` between them, and a sweep over
    fixtures alone therefore never touches `origin.ingested_at`, which is one of
    the fields the bound is on. Building the record here is what makes the sweep
    below mean what it says.
    """
    record = json.loads(json.dumps(_load(BASE_RECORD)["record"]))
    record["origin"] = {
        "kind": "log-import",
        "producer": "example-producer",
        "source_event_id": "evt-1",
        "ingested_at": 1785000000,
    }
    record["delegation"] = {
        "parent_record_hash": "sha256:" + "a" * 64,
        "credential_id": "cred-1",
    }
    record["references"] = [{
        "rel": "behavior-trace",
        "id": "ref-1",
        "resolver": "https://example.test/resolver",
        "retention": "P30D",
        "digest": "sha256:" + "b" * 64,
    }]
    record["tool_transcript"] = {
        "hash": "sha256:" + "c" * 64,
        "call_count": 3,
        "transcript_uri": "https://example.test/transcript",
    }
    record["appraisal"]["timestamp"] = 1785000000
    return record


def test_the_maximal_record_reaches_every_declared_property() -> None:
    """The sweep's reach, asserted rather than assumed.

    A sweep that silently stops covering a field is the failure this whole change
    is about. If a property is added to the schema, this fails until the record
    above carries it, and only then does the sweep speak for it.
    """
    record = _maximal_record()
    validate_json(record)
    schema = json.loads(
        (REPO_ROOT / "schema" / "trace-claim.json").read_text(encoding="utf-8")
    )
    assert not set(schema["properties"]) - set(record)


def _positions(node: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[tuple[Any, ...], Any]]:
    found: list[tuple[tuple[Any, ...], Any]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.append((prefix + (key,), value))
            found += _positions(value, prefix + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.append((prefix + (index,), value))
            found += _positions(value, prefix + (index,))
    return found


# One schema-valid exemplar per signed artifact, for the sweep below. The record
# has its own builder because it has to reach every declared property; these three
# are small enough to write out. Without them the bundle's and the bridge's bounds
# are each separated by a single test, which is the margin rule of
# agentrust-io/trace-spec#124 not being met.
OTHER_ARTIFACTS: dict[str, dict[str, Any]] = {
    "schema/trace-revocation.json": {
        "type": "TraceRevocation/1.0",
        "compromised_key_id": "key-1",
        "last_valid_entry_id": "41",
        "revoked_after_entry": "42",
        "log_id": "log-1",
        "revoked_at": 1785000000,
        "revocation_key_id": "revoker-1",
        "sig": {"alg": "ed25519", "value": "AAAA"},
    },
    "schema/trace-revocation-bundle.json": {
        "type": "TraceRevocationBundle/1.0",
        "log_id": "log-1",
        "issued_at": 1785000000,
        "valid_until": 1785900000,
        "statements": [],
        "bundle_key_id": "bundle-key-1",
        "sig": {"alg": "ed25519", "value": "AAAA"},
    },
    "schema/pic-trace-bridge-v1.json": {
        "profile": "tag:agentrust-io.com,2026:pic-trace-bridge-v1",
        "authorization": {
            "authorization_id": "auth-1",
            "decision": "allow",
            "authorizer": "https://authorizer.example/a",
            "authorizer_key_id": "kid-1",
            "authorized_at": 1785000000,
            "expires_at": 1785900000,
            "scope": {"tools": ["transfer"], "impacts": ["funds"]},
            "pic": {
                "profile": "PIC-CJSON/1.0",
                "intent_digest": "sha256:" + "a" * 64,
                "args_digest": "sha256:" + "b" * 64,
            },
            "declaration_digest": "sha256:" + "c" * 64,
            "tool_call_digest": "sha256:" + "d" * 64,
            "transcript_required": True,
        },
        "signature": "x" * 86,
    },
}


@pytest.mark.parametrize("relative", sorted(OTHER_ARTIFACTS))
@pytest.mark.parametrize("bad", [2**53, -(2**53), 1.5], ids=["above", "below", "float"])
def test_no_position_in_another_signed_artifact_accepts_one_either(
    bad: Any, relative: str
) -> None:
    """The same sweep, on the artifacts that are not Trust Records.

    Their signatures are over an RFC 8785 canonical form too, stated in their own
    `sig` descriptions and in the bridge's signing code, so the same rule applies
    and the same sweep should find the same nothing.
    """
    schema = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    exemplar = OTHER_ARTIFACTS[relative]
    assert not list(validator.iter_errors(exemplar)), (
        f"{relative}: the exemplar is not schema-valid, so the sweep proves nothing"
    )

    accepted = []
    for path, value in _positions(exemplar):
        candidate = json.loads(json.dumps(exemplar))
        target = candidate
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = bad
        if not list(validator.iter_errors(candidate)):
            accepted.append("replace " + "/".join(str(s) for s in path))

        if not isinstance(value, dict):
            continue
        candidate = json.loads(json.dumps(exemplar))
        target = candidate
        for step in path:
            target = target[step]
        target["undeclared"] = bad
        if not list(validator.iter_errors(candidate)):
            accepted.append("inject " + "/".join(str(s) for s in path))

    candidate = json.loads(json.dumps(exemplar))
    candidate["undeclared"] = bad
    if not list(validator.iter_errors(candidate)):
        accepted.append("inject <root>")

    assert not accepted, f"{relative}: {bad!r} accepted at: {accepted}"


@pytest.mark.parametrize("bad", [2**53, -(2**53), 1.5], ids=["above", "below", "float"])
def test_no_position_in_a_record_accepts_an_uncanonicalizable_value(bad: Any) -> None:
    """Every position, both ways in, rather than the ones anyone thought of.

    Two holes in this change were found by looking, not by reasoning: `cnf.jwk`
    accepted an undeclared member with no constraint, and the bridge schema was
    exempted on a reason its own signing code contradicted. This sweep is the
    version that does not depend on someone thinking of the position first. It
    replaces the value at every position in a maximal record, and separately adds
    an undeclared member at every object in it, and asserts the schema refuses.
    """
    record = _maximal_record()
    accepted = []

    for path, value in _positions(record):
        candidate = json.loads(json.dumps(record))
        target = candidate
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = bad
        try:
            validate_json(candidate)
            accepted.append("replace " + "/".join(str(s) for s in path))
        except jsonschema.ValidationError:
            pass

        if not isinstance(value, dict):
            continue
        candidate = json.loads(json.dumps(record))
        target = candidate
        for step in path:
            target = target[step]
        target["undeclared"] = bad
        try:
            validate_json(candidate)
            accepted.append("inject " + "/".join(str(s) for s in path))
        except jsonschema.ValidationError:
            pass

    candidate = json.loads(json.dumps(record))
    candidate["undeclared"] = bad
    try:
        validate_json(candidate)
        accepted.append("inject <root>")
    except jsonschema.ValidationError:
        pass

    assert not accepted, f"{bad!r} accepted at: {accepted}"


def test_a_digest_over_an_unschema_d_object_fails_closed() -> None:
    """The surface a schema bound cannot reach, and what actually holds it.

    `digest_jcs` takes the digest of a caller-supplied object. Nothing validates
    that object, so no `maximum` anywhere protects it. Measured: two declarations
    differing only in an integer above the range, 9007199254740992 against
    9007199254740993, produce one digest under canonicalize 4.0.0, and the bridge's
    binding between an authorization and what actually ran is defeated silently.

    What stops it here is that `rfc8785` refuses the value, which section 3.2.2 now
    states as a requirement rather than leaving to a library's discretion. This test
    pins the failing-closed behaviour: if a future `rfc8785` starts rounding instead,
    this goes red, and the right response is a check in `digest_jcs`, not a looser
    test.
    """
    from agentrust_trace.intent_bridge import digest_jcs

    assert digest_jcs({"tool": "wire", "amount": SAFE_INTEGER}).startswith("sha256:")
    for out_of_range in (2**53, -(2**53)):
        with pytest.raises(Exception) as caught:
            digest_jcs({"tool": "wire", "amount": out_of_range})
        assert isinstance(caught.value, (rfc8785.IntegerDomainError, ValueError))


@pytest.mark.parametrize(
    "path",
    [("iat",), ("tool_transcript", "call_count"), ("origin", "ingested_at"),
     ("appraisal", "timestamp")],
    ids=lambda p: "/".join(p),
)
def test_the_model_and_the_schema_agree_at_the_bound(path: tuple[str, ...]) -> None:
    """A producer builds against one of two artifacts, and they have to say the same.

    `TrustRecord` mirrors every schema constraint: `ge=0` for `call_count`,
    `ge=1700000000` for `iat`, `ge=0, le=3` for `slsa_level`. When the bound went
    into the schema alone the two disagreed, and a producer using the model got a
    record the schema rejects and a canonicalizer refuses, with the failure landing
    somewhere downstream instead of at construction.

    Checked as behaviour on both artifacts rather than by comparing declarations,
    because the declarations are written in different languages.
    """
    import pydantic

    from agentrust_trace.models import TrustRecord

    def place(value: int) -> dict[str, Any]:
        record = _maximal_record()
        target = record
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = value
        return record

    at_bound = place(SAFE_INTEGER)
    validate_json(at_bound)
    TrustRecord.model_validate(at_bound)

    past_bound = place(SAFE_INTEGER + 1)
    with pytest.raises(jsonschema.ValidationError):
        validate_json(past_bound)
    with pytest.raises(pydantic.ValidationError):
        TrustRecord.model_validate(past_bound)


def test_the_bound_reaches_a_statement_nested_in_a_bundle() -> None:
    """The one field the schema files cannot test on their own.

    `trace-revocation-bundle.json` refers to the statement schema by absolute URL.
    A validator built from the bundle file alone resolves that by fetching the
    published schema over the network, so it checks a nested statement against
    whatever is deployed rather than against the file next to it, and with no
    network it is unresolvable. Either way the bound in the working tree is not
    what gets applied, and `tests/test_revocation_schema.py` compares the `$ref`
    and the `$id` as strings without ever validating an instance.

    This wires the two local files together and validates through the seam, so
    the nested `revoked_at` is covered by the repository rather than by a
    deployment. It touches no network: the registry is built from the files.
    """
    import referencing
    import referencing.jsonschema

    statement_schema = json.loads(
        (REPO_ROOT / "schema" / "trace-revocation.json").read_text(encoding="utf-8")
    )
    bundle_schema = json.loads(
        (REPO_ROOT / "schema" / "trace-revocation-bundle.json").read_text(encoding="utf-8")
    )
    resource = referencing.Resource.from_contents(
        statement_schema, default_specification=referencing.jsonschema.DRAFT202012
    )
    validator = jsonschema.Draft202012Validator(
        bundle_schema, registry=resource @ referencing.Registry()
    )

    def bundle(revoked_at: int) -> dict[str, Any]:
        return {
            "type": "TraceRevocationBundle/1.0",
            "log_id": "log-1",
            "issued_at": 1785000000,
            "valid_until": 1785900000,
            "statements": [{
                "type": "TraceRevocation/1.0",
                "compromised_key_id": "key-1",
                "last_valid_entry_id": "41",
                "revoked_after_entry": "42",
                "log_id": "log-1",
                "revoked_at": revoked_at,
                "revocation_key_id": "revoker-1",
                "sig": {"alg": "ed25519", "value": "AAAA"},
            }],
            "bundle_key_id": "bundle-key-1",
            "sig": {"alg": "ed25519", "value": "AAAA"},
        }

    assert not list(validator.iter_errors(bundle(SAFE_INTEGER)))
    errors = list(validator.iter_errors(bundle(SAFE_INTEGER + 1)))
    assert errors, "a nested statement above the bound was accepted through the $ref"
    assert list(errors[0].absolute_path) == ["statements", 0, "revoked_at"]


def test_the_anchor_profile_excludes_the_range_it_diverges_on() -> None:
    """The second canonicalization in this repository had the same gap.

    `spec/registry-anchor-v1.md` §0 exists to warn that the anchoring layer is not
    JCS, and it listed the ways the two diverge. It said they agree on records
    "whose numbers are integers", which is true only inside the safe-integer range:
    JCS goes through a double and §1 writes the digits, so the two part company
    above it. Worse for the anchor profile itself, two implementations of §1
    disagree with each other, because a language whose only number type is the
    double emits one value for both integers, and `tool_catalog_hash` runs exactly
    those rules over a tool's `input_schema`, where a `maximum` is ordinary content.

    Measured rather than asserted: the divergence the section now claims is the
    divergence Python actually shows.
    """
    doc = (REPO_ROOT / "spec" / "registry-anchor-v1.md").read_text(encoding="utf-8")
    trap = doc.split("## 0.")[1].split("## 1.")[0]

    assert "integers inside the safe-integer range" in trap, (
        "section 0 claims the two canonicalizations agree on integers without qualification"
    )
    assert "diverge in four ways" in trap
    assert trap.count("\n- **") == 4, "the count and the list have drifted apart"
    assert "Integers outside the safe-integer range" in trap

    reference = (REPO_ROOT / "docs" / "schema.md").read_text(encoding="utf-8")
    assert f"-{SAFE_INTEGER} through {SAFE_INTEGER}" in reference, (
        "docs/schema.md is the field reference a producer reads, and it lists every "
        "integer field without saying they are bounded"
    )

    profile = doc.split("## 1.")[1].split("## 2.")[0]
    assert f"-{SAFE_INTEGER} to {SAFE_INTEGER}" in profile, (
        "section 1 names no range, so section 0 points at an exclusion that is not there"
    )

    # The divergence itself: sorted-key JSON keeps the digits, JCS does not.
    pair = (2**53, 2**53 + 1)
    written = {json.dumps(n) for n in pair}
    assert len(written) == 2, "sorted-key JSON does not distinguish the pair after all"
    assert len({float(n) for n in pair}) == 1, "JCS would not merge the pair after all"


@pytest.mark.parametrize(
    "iat",
    [2**53 - 2, 2**53 - 1, 2**53, 2**53 + 1, 2**53 + 2, 2**60],
    ids=lambda n: str(n),
)
def test_all_three_layers_draw_the_line_in_the_same_place(iat: int) -> None:
    """Schema, model and canonicalizer either all take a value or all refuse it.

    Three artifacts decide whether a record is usable, and a producer meets them
    in an order nobody controls. Before this change the schema and the
    canonicalizer disagreed, which is the whole defect; while it was half made,
    the model and the schema disagreed. Checking each against the others at the
    boundary is what says the change is coherent rather than merely applied.
    """
    import pydantic

    from agentrust_trace.models import TrustRecord

    record = json.loads(json.dumps(_load(BASE_RECORD)["record"]))
    record["iat"] = iat

    def accepts(call: Callable[[], Any], expected: type[Exception]) -> bool:
        try:
            call()
        except expected:
            return False
        return True

    schema_ok = accepts(lambda: validate_json(record), jsonschema.ValidationError)
    model_ok = accepts(lambda: TrustRecord.model_validate(record), pydantic.ValidationError)
    canon_ok = accepts(
        lambda: rfc8785.dumps(_signing_input(record)), rfc8785.IntegerDomainError
    )

    assert schema_ok == model_ok == canon_ok, (
        f"iat={iat}: schema={schema_ok} model={model_ok} canonicalizer={canon_ok}. "
        "A producer meets these in an order nobody controls, so a value any one of "
        "them takes and another refuses fails somewhere unpredictable."
    )
    assert schema_ok == (abs(iat) <= SAFE_INTEGER)


def test_the_anchor_layer_refuses_what_its_profile_excludes() -> None:
    """The section 1 exclusion, as behaviour rather than as prose.

    Two functions in this repository implement the anchor format:
    `tool_catalog_hash` over a tool's `name`, `description` and `input_schema`,
    and the AGT adapter's transcript hash over audit entries. Neither checked
    anything, and an `input_schema` is JSON Schema, where a `maximum` is ordinary
    content rather than something odd a caller had to go out of their way to
    write. Python emitted a digest, a JavaScript implementation of the same four
    rules emitted a different one, and section 0 says exactly what that looks like
    from the outside: a proof that does not verify, with no useful diagnostic.

    `anchor_bytes` refuses by name instead, which is the diagnostic.
    """
    from agentrust_trace.provenance import tool_catalog_hash
    from agentrust_trace.sign import UnanchorableValue, anchor_bytes

    def tools(maximum: int) -> list[dict[str, Any]]:
        return [{
            "name": "transfer",
            "description": "move funds",
            "input_schema": {
                "type": "object",
                "properties": {"amount": {"type": "integer", "maximum": maximum}},
            },
        }]

    assert tool_catalog_hash(tools(SAFE_INTEGER)).startswith("sha256:")
    with pytest.raises(UnanchorableValue):
        tool_catalog_hash(tools(SAFE_INTEGER + 1))

    # The shapes the profile keeps, and the ones it does not. A bool is not a
    # number here even though Python makes it an int subclass, and a float is out
    # whether or not its value happens to be integral: `1.0` and `1` are one value
    # to a JavaScript writer and two to Python's.
    for kept in ({"a": "s"}, {"a": True}, {"a": None}, {"a": [1, 2, SAFE_INTEGER]}):
        assert anchor_bytes(kept)
    for excluded in ({"a": 1.5}, {"a": 1.0}, {"a": [{"b": 2**53}]}, {"a": -(2**53)}):
        with pytest.raises(UnanchorableValue):
            anchor_bytes(excluded)


def test_the_two_transcript_hashes_now_agree_on_the_same_input() -> None:
    """The adapters disagreed with each other, and now they don't.

    Both hash a caller-supplied decision log into the same record field,
    `tool_transcript.hash`. The sandbox adapter canonicalizes with `rfc8785`
    (JCS), matching what docs/schema.md and docs/integration/agt.md both call
    "canonical JSON" for this field. The AGT adapter used the registry-anchor
    sorted-key format instead -- a different, narrower profile reserved for the
    `transparency` anchor leaf (spec/registry-anchor-v1.md §0) -- which produced
    a different digest for the same entries *and* rejected ordinary floats
    (a timestamp, a latency, a risk score) that JCS handles without complaint.
    Governance-framework audit entries carry both floats and 64-bit integers
    routinely, so this was not a constructed edge case.

    The AGT adapter now uses the same `rfc8785` canonicalization as its
    sibling, so the two genuinely agree: same bytes hashed, same digest, same
    exception on the same out-of-range input -- not just "both happen to
    refuse."
    """
    import agentrust_trace.adapters.agt as agt_module
    import agentrust_trace.adapters.sandbox as sandbox_module

    entries = [{
        "tool": "transfer",
        "decision": "allow",
        "ts_ns": 1785000000123456789,
        "request_id": 2**63 - 1,
    }]
    agt_adapter = next(
        v for v in vars(agt_module).values()
        if isinstance(v, type) and hasattr(v, "_transcript_hash")
    )
    sandbox_adapter = next(
        v for v in vars(sandbox_module).values()
        if isinstance(v, type) and hasattr(v, "transcript_hash")
    )

    with pytest.raises(rfc8785.IntegerDomainError):
        agt_adapter._transcript_hash(entries)

    with pytest.raises(rfc8785.IntegerDomainError):
        sandbox_adapter.transcript_hash(entries)

    # In range, the two now produce the identical digest for identical input.
    in_range = [{**entries[0], "ts_ns": 1785000000, "request_id": SAFE_INTEGER}]
    assert agt_adapter._transcript_hash(in_range) == sandbox_adapter.transcript_hash(in_range)

    # And a float -- routine in a real audit entry, out of scope for this test's
    # integer focus but the other half of why anchor_bytes was wrong here --
    # no longer breaks the AGT adapter either.
    with_float = [{**entries[0], "ts_ns": 1785000000, "request_id": SAFE_INTEGER, "risk": 0.5}]
    assert agt_adapter._transcript_hash(with_float).startswith("sha256:")


def test_the_reproduction_script_runs_and_reproduces() -> None:
    """The evidence has to be re-runnable by whoever is reading it.

    The measurements behind this change were taken against V8, npm's
    `canonicalize` and `ajv`. A reviewer has none of those, so on its own that is
    a set of claims rather than a set of results. The script runs on the standard
    library and this package, and this runs the script: a reproduction that has
    quietly stopped reproducing is worse than none, because its presence is the
    argument.
    """
    script = FIXTURE_DIR / "number_divergence_repro.py"
    completed = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, cwd=REPO_ROOT
    )
    assert completed.returncode == 0, (
        f"the reproduction script failed:\n{completed.stdout}\n{completed.stderr}"
    )
    assert "every step reproduced" in completed.stdout
    # Its own self-check, which is what makes the rest of its output mean anything.
    assert "byte-for-byte agreement with rfc8785: True" in completed.stdout


def test_the_bound_is_the_one_rfc_8785_names_and_the_only_enforceable_one() -> None:
    """Where the bound comes from, and why no wider bound would work.

    RFC 8785 Appendix B note 1 names this range: values interpreted as true
    integers SHOULD be in -9007199254740991 to 9007199254740991. That is where
    the number comes from, and it is not derived from the first collision, which
    is one higher: 2**53 and 2**53 + 1 are the first adjacent pair to share a
    double, so a range ending at 2**53 is still injective on its own members.

    That is as far as reasoning about Python gets, and it is not far enough. A
    validator whose only number type is the IEEE 754 double never sees the
    instance value; it sees whatever the value parsed to. With the bound at
    2**53 it reads 2**53 + 1 as 2**53, finds it within the maximum, and accepts
    the one value the range exists to exclude. With the bound at 2**53 - 1 every
    out-of-range integer parses to something at or above 2**53, which is over
    the maximum, so the bound holds. 2**53 - 1 is therefore not merely the
    conventional number: it is the largest maximum a double-only validator can
    enforce at all.

    Asserted here through `float`, which is the same rounding, and confirmed
    separately against ajv 8.20.0 on node: with maximum 9007199254740991 it
    rejects 9007199254740993, and with maximum 9007199254740992 it accepts it.
    """
    assert float(SAFE_INTEGER) == SAFE_INTEGER, "the bound itself must be exact"
    assert float(SAFE_INTEGER - 1) != float(SAFE_INTEGER), "below the bound, distinct"
    assert float(-SAFE_INTEGER) == -SAFE_INTEGER, "the floor must be exact too"

    # The first adjacent pair to share a double sits above the bound.
    assert float(2**53) == float(2**53 + 1)
    assert 2**53 > SAFE_INTEGER

    # What a double-only validator does with values it cannot represent. Every
    # integer above this bound survives rounding as something still above it.
    for out_of_range in (2**53, 2**53 + 1, 2**53 + 2, 2**60, 2**70 + 1):
        assert float(out_of_range) > SAFE_INTEGER, (
            f"{out_of_range} rounds to {float(out_of_range)!r}, at or under the "
            "bound, so a double-only validator would accept it"
        )
        assert float(-out_of_range) < -SAFE_INTEGER

    # And what it does with the wider bound that reasoning about Python alone
    # would have allowed. This is the assertion that rules 2**53 out.
    too_wide = 2**53
    assert float(2**53 + 1) <= too_wide, (
        "a maximum of 2**53 would be enforceable after all, and the argument "
        "above for preferring 2**53 - 1 does not hold"
    )


def test_the_spec_states_the_rule_the_schema_enforces() -> None:
    """Section 3.2.2 and the schema have to say the same thing.

    The bound is only discoverable from the schema by reading its `maximum` keys
    and knowing why that number. An implementer works from the spec, so the rule
    has to be written there, and once written it can drift. This pins the sentence
    to the fact: the two integers it names must be the ones that actually collide,
    and the bound it describes must be the bound the schema carries.
    """
    spec = (REPO_ROOT / "spec" / "trace-v0.2.md").read_text(encoding="utf-8")
    assert spec.count("#### 3.2.2") == 1 and spec.count("#### 3.2.3") == 1, (
        "section 3.2.2 is no longer delimited by a single pair of headings, so the "
        "slice below is not the section this test believes it is reading"
    )
    section = spec.split("#### 3.2.2")[1].split("#### 3.2.3")[0]

    # The rule has to be in the bullet that defines number serialization, not merely
    # somewhere in the section. Section 3.2.2 says "MUST be rejected" about freshness
    # and "safe-integer domain" in the paragraph about libraries, so a section-wide
    # substring check passes even when the bullet no longer states the rule.
    bullets = [
        line for line in section.splitlines() if "Numbers are serialized" in line
    ]
    assert len(bullets) == 1, "section 3.2.2 no longer has exactly one number bullet"
    bullet = bullets[0]

    # The range and where it comes from, in the bullet that defines the rule.
    # Without the citation a reader has no way to tell a specification decision
    # from an arbitrary number, and the range is the half a schema edit can
    # silently contradict.
    assert "RFC 8785 Appendix B note 1" in bullet
    assert f"-{SAFE_INTEGER} to {SAFE_INTEGER}" in bullet
    assert "No object canonicalized under this section may carry" in bullet
    assert "MUST be rejected" in bullet

    # The two paragraphs the bullet leans on. Each is checked by a phrase long
    # enough to be the claim itself: "digest" alone appears throughout the section
    # and passes with the paragraph gutted.
    assert "why a profile MUST NOT widen it" in section, (
        "nothing tells an implementer that 2**53 is unenforceable, which is the "
        "bound they would otherwise pick"
    )
    assert "never sees the instance value" in section
    assert "whose digest is taken over its canonical form" in section, (
        "the rule no longer reaches the objects no schema describes"
    )

    first, second = 2**53, 2**53 + 1
    assert str(first) in bullet and str(second) in bullet, (
        "the bullet names no example pair, so nothing here can check it is the right one"
    )
    assert float(first) == float(second), (
        "the bullet names a pair that does not collide, so its example is wrong"
    )

    # Section 3.2.2 names the same pair a second time, in the paragraph about
    # libraries, and that sentence makes a factual claim about what canonicalize
    # 4.0.0 emits. Changing either number there leaves the bullet above intact and
    # the claim false, so the pair is checked wherever the section states it.
    libraries = next(
        para for para in section.split("\n\n")
        if "Implementations MUST use an RFC 8785-conformant library" in para
    )
    named = sorted({int(n) for n in re.findall(r"\b(\d{16,})\b", libraries)})
    assert len(named) == 2, f"the libraries paragraph names {named}, expected one pair"
    assert float(named[0]) == float(named[1]), (
        f"the libraries paragraph says {named} share their bytes, and they do not"
    )

    schema = json.loads(
        (REPO_ROOT / "schema" / "trace-claim.json").read_text(encoding="utf-8")
    )
    bounds = {node.get("maximum") for _, node in _integer_nodes(schema)}
    assert SAFE_INTEGER in bounds, (
        "the bullet describes a safe-integer bound the schema does not carry"
    )
    assert SAFE_INTEGER == first - 1, "the bound and the example pair have drifted apart"


def test_the_carrier_no_other_rule_inspects_is_rejected_too() -> None:
    """`iat` is the obvious carrier and the weakest one.

    A verifier enforcing section 3.2.2's own freshness rules rejects an `iat` at
    2**53 as a record dated in the year 285 million, before canonicalization is
    reached. That makes it a poor demonstration and a poor attack: the collision
    is real but something else catches it. `tool_transcript.call_count` has no
    such rule. A record carrying it, with an ordinary `iat`, passed schema
    validation on main and took the signature issued for the record one greater.

    Both are bounded now, and this asserts the one that nothing else was watching.
    """
    record = _maximal_record()
    record["tool_transcript"]["call_count"] = SAFE_INTEGER
    validate_json(record)

    for out_of_range in (2**53, 2**53 + 1):
        record["tool_transcript"]["call_count"] = out_of_range
        with pytest.raises(jsonschema.ValidationError):
            validate_json(record)


def test_a_record_above_the_bound_is_rejected_before_it_is_signed() -> None:
    """Schema and canonicalizer now agree, which is the point of the change.

    Before the bound, `iat` accepted this value and `rfc8785.dumps` raised on it:
    a record could pass validation and then have no canonical form at all. The
    test asserts both halves, so removing the bound fails here and not only in the
    per-schema test above.
    """
    fixture = _load(BASE_RECORD)
    record = json.loads(json.dumps(fixture["record"]))
    record["iat"] = 2**53

    with pytest.raises(jsonschema.ValidationError):
        validate_json(record)

    # `rfc8785` refuses rather than rounding. If a future release starts rounding
    # instead, this line fails, and that failure is worth reading: the record would
    # then be canonicalized into bytes it shares with a different record, silently.
    with pytest.raises(rfc8785.IntegerDomainError):
        rfc8785.dumps(_signing_input(record))

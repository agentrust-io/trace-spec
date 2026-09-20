"""The citation-resolution consumer: vectors, invariants, and the network sweep.

`examples/citation-resolution/` carries sixteen signed vectors. The runner maps each
vector's `context` onto `verify_record`, builds the harness resolver from
`context.resolutions` (bytes in hand, base64-decoded here and nowhere in `src/`), and
compares the `citations` mapping alone: revocation, thumbprint and the raise/no-raise
behaviour of `verify_record` are held unchanged by the invariants below rather than
re-asserted per vector.

The invariants are numbered I1 to I11 as the change that introduced them names them.
Diagnostic-message tests sit in their own section at the end, so a wording change in a
`ValueError` never reads as a conformance failure.

This file carries its own copy of the network import sweep in
`tests/test_revocation_bundle.py`, because that sweep walks `src/agentrust_trace/*.py`
and itself, not this file. `socket` is reached here only through a dotted-string
monkeypatch and `sys.modules`, never an import, so the sweep stays clean.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from collections.abc import Callable
from typing import Any, get_args

import pytest

from agentrust_trace.citation import SURFACES, Cause, CitationCheck, check_citations
from agentrust_trace.revocation import NO_CHECK, VerificationResult
from agentrust_trace.sign import generate_key, key_to_jwk, sign_record, verify_record

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples" / "citation-resolution"
FILES = sorted(VECTORS.glob("*.json"))
assert FILES, "no citation-resolution vectors on disk; the runner would measure nothing"

REVOCATION_VECTORS = sorted((ROOT / "examples" / "revocation-bundle").glob("*.json"))

CONSUMED = tuple(path for path, deferred in SURFACES if deferred is None)
DEFERRED = {path: reason for path, reason in SURFACES if reason is not None}

#: What `verify_record` reports when no resolver is supplied: the same four rows for
#: every record, whatever it cites.
DEFAULT_ROWS: dict[str, dict[str, Any]] = {
    **{
        path: {"outcome": "not_attempted", "cause": "no_resolver", "evidence": {}}
        for path in CONSUMED
    },
    **{
        path: {
            "outcome": "not_attempted",
            "cause": "surface_deferred",
            "evidence": {"reason": reason},
        }
        for path, reason in DEFERRED.items()
    },
}


def _load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolver(ctx: dict[str, Any]) -> Callable[[str], bytes] | None:
    """The harness resolver. Absent `resolutions` means no resolver; a present table
    that lacks the URI raises `KeyError`, which is the vectors' `resolver_raised`."""
    if "resolutions" not in ctx:
        return None
    table = ctx["resolutions"]

    def resolve(uri: str) -> bytes:
        return base64.b64decode(table[uri]["bytes_base64"])

    return resolve


def _run(doc: dict[str, Any], **overrides: Any) -> VerificationResult:
    ctx = doc["context"]
    kwargs: dict[str, Any] = {
        "now": ctx["now"],
        "max_age_seconds": ctx["max_age_seconds"],
        "max_future_skew_seconds": ctx["max_future_skew_seconds"],
        "citation_resolver": _resolver(ctx),
    }
    kwargs.update(overrides)
    return verify_record(doc["records"][0], ctx["trusted_key"], **kwargs)


def _rows(citations: dict[str, CitationCheck]) -> dict[str, dict[str, Any]]:
    return {surface: dataclasses.asdict(check) for surface, check in citations.items()}


def _assert_rows_match(
    got: dict[str, CitationCheck], expected: dict[str, dict[str, Any]], name: str
) -> None:
    """The vector comparison: same surfaces in the same order, same outcome and cause,
    and every expected evidence key present with the expected value. Evidence is
    compared as a subset, as the revocation runner compares it."""
    assert list(got) == list(expected), f"{name}: surfaces or their order"
    for surface, row in expected.items():
        check = got[surface]
        assert check.outcome == row["outcome"], f"{name}: {surface} outcome"
        assert check.cause == row["cause"], f"{name}: {surface} cause"
        for key, value in row["evidence"].items():
            assert check.evidence.get(key) == value, f"{name}: {surface} evidence[{key!r}]"


def _fresh() -> dict[str, Any]:
    return _load(VECTORS / "16-all-three-resolved.json")


def _signed(body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """A record signed under a key this test holds, and the trusted JWK for it."""
    key = generate_key()
    return sign_record(body, key), key_to_jwk(key)


def _unsigned_body(doc: dict[str, Any]) -> dict[str, Any]:
    body = dict(doc["records"][0])
    del body["signature"]
    del body["cnf"]
    return body


# ---- the vectors ---------------------------------------------------------------------


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_vector(path: pathlib.Path) -> None:
    doc = _load(path)
    expected = doc["expected"]
    assert expected["rejected"] is False and expected["codes"] == [], path.name
    result = _run(doc)
    _assert_rows_match(result.citations, expected["citations"], path.name)


def test_the_set_carries_every_cause_on_every_consumed_surface() -> None:
    """A surface dropped from `SURFACES`, or a cause the set never reaches, shows here
    rather than as sixteen identical passes."""
    seen: set[tuple[str, str, str | None]] = set()
    for path in FILES:
        for surface, row in _load(path)["expected"]["citations"].items():
            seen.add((surface, row["outcome"], row["cause"]))
    for surface in CONSUMED:
        assert (surface, "not_attempted", "no_resolver") in seen, surface
        assert (surface, "not_attempted", "field_absent") in seen, surface
        assert (surface, "unresolvable", "resolver_raised") in seen, surface
        assert (surface, "resolved", None) in seen, surface
    for surface in DEFERRED:
        assert all(
            _load(path)["expected"]["citations"][surface]["cause"] == "surface_deferred"
            for path in FILES
        ), f"{surface} is deferred in every vector"


# ---- invariants ----------------------------------------------------------------------


def test_I1_every_record_that_verified_before_still_verifies_with_the_same_result() -> None:
    """The revocation vectors are the records `verify_record` accepted before citations
    existed. Each still returns, its revocation check is what its vector expects, and
    its citations are the four default rows."""
    for path in REVOCATION_VECTORS:
        doc = _load(path)
        if doc["expected"]["rejected"]:
            continue
        ctx = doc["context"]
        result = verify_record(
            doc["records"][0],
            ctx["trusted_key"],
            now=ctx["now"],
            max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
            max_future_skew_seconds=ctx["max_future_skew_seconds"],
            revocation_bundle=ctx["bundle"],
            trusted_bundle_keys=ctx["trusted_bundle_keys"],
        )
        assert result.revocation.outcome == doc["expected"]["outcome"], path.name
        assert result.revocation.cause == doc["expected"]["cause"], path.name
        assert _rows(result.citations) == DEFAULT_ROWS, path.name
    for path in FILES:
        assert _rows(_run(_load(path), citation_resolver=None).citations) == DEFAULT_ROWS


def test_I1_a_result_built_by_hand_defaults_to_no_citations() -> None:
    by_hand = VerificationResult(revocation=NO_CHECK, trusted_key_thumbprint="thumb")
    assert by_hand.citations == {}


def test_I2_no_citation_outcome_moves_revocation_or_the_thumbprint() -> None:
    for path in FILES:
        doc = _load(path)
        with_resolver = _run(doc)
        without = _run(doc, citation_resolver=None)
        assert with_resolver.revocation == NO_CHECK, path.name
        assert with_resolver.revocation == without.revocation, path.name
        assert with_resolver.trusted_key_thumbprint == without.trusted_key_thumbprint
    doc = _fresh()
    store = _run(doc, revocation=set())
    assert store.revocation.outcome == "verified"
    assert store.revocation.evidence == {"source": "store"}
    assert all(check.outcome == "resolved" for s, check in store.citations.items() if s in CONSUMED)


def test_I3a_a_resolver_named_by_the_record_is_ignored() -> None:
    """Section 3.1.2: a record that names its own checker can name one that agrees
    with it. `check_citations` reads the dict, so the hint can sit where the schema
    would refuse it; the outcome is the same with and without."""
    doc = _fresh()
    plain = json.loads(json.dumps(doc["records"][0]))
    hinted = json.loads(json.dumps(plain))
    hinted["appraisal"]["resolver"] = "https://resolver.example/that-agrees"
    calls: list[str] = []

    def resolver(uri: str) -> bytes:
        calls.append(uri)
        return b"object"

    assert _rows(check_citations(hinted, resolver)) == _rows(check_citations(plain, resolver))
    assert "https://resolver.example/that-agrees" not in calls
    assert _rows(check_citations(hinted, None)) == DEFAULT_ROWS


def test_I3b_I4_a_references_entry_naming_a_resolver_changes_nothing() -> None:
    """The schema's own home for a record-named resolver is `references[].resolver`.
    A signed record carrying one, whose `id` the harness cannot resolve, verifies
    with citations byte-identical to the same record without the entry. The resolver
    is never asked for the entry's id: `references[]` is not read."""
    doc = _fresh()
    body = _unsigned_body(doc)
    with_ref = json.loads(json.dumps(body))
    with_ref["references"] = [{
        "rel": "behavior-trace",
        "id": "urn:example:trace:not-resolvable-anywhere",
        "resolver": "https://resolver.example/that-agrees",
    }]
    asked: list[str] = []
    table = doc["context"]["resolutions"]

    def resolver(uri: str) -> bytes:
        asked.append(uri)
        return base64.b64decode(table[uri]["bytes_base64"])

    ctx = doc["context"]
    results = []
    for candidate in (body, with_ref):
        record, trusted = _signed(candidate)
        results.append(verify_record(
            record, trusted, now=ctx["now"], max_age_seconds=ctx["max_age_seconds"],
            max_future_skew_seconds=ctx["max_future_skew_seconds"],
            citation_resolver=resolver,
        ))
    plain, referenced = (json.dumps(_rows(r.citations), sort_keys=True) for r in results)
    assert plain == referenced
    assert "urn:example:trace:not-resolvable-anywhere" not in asked
    assert set(asked) <= set(table)


def test_I5_every_outcome_other_than_resolved_names_a_cause() -> None:
    causes = set(get_args(Cause))

    def boom(uri: str) -> bytes:
        raise LookupError(uri)

    def wrong(uri: str) -> Any:
        return "not bytes"

    rows: list[CitationCheck] = []
    for path in FILES:
        rows.extend(_run(_load(path)).citations.values())
    doc = _fresh()
    for resolver in (None, boom, wrong):
        rows.extend(check_citations(doc["records"][0], resolver).values())
    assert rows
    for check in rows:
        if check.outcome == "resolved":
            assert check.cause is None
        else:
            assert check.cause in causes, check


def test_I6_every_evidence_dict_serialises_as_json() -> None:
    def boom(uri: str) -> bytes:
        raise RuntimeError("the text of this exception is never evidence")

    def wrong(uri: str) -> Any:
        return object()

    doc = _fresh()
    cases: list[dict[str, CitationCheck]] = [
        _run(_load(path)).citations for path in FILES
    ] + [check_citations(doc["records"][0], r) for r in (None, boom, wrong)]
    for citations in cases:
        for check in citations.values():
            json.dumps(check.evidence)
        json.dumps(_rows(citations))


# ---- I7: nothing here or under src/ reaches the network ------------------------------


def test_I7_nothing_under_src_or_this_test_reaches_the_network() -> None:
    """A copy of the sweep in `tests/test_revocation_bundle.py`, over this file: that
    one walks itself, not this file. `citation.py` is inside both."""
    pattern = re.compile(
        r"^\s*(import|from)\s+(socket|urllib|http\.client|httpx|requests|aiohttp)\b"
    )
    files = sorted((ROOT / "src" / "agentrust_trace").glob("*.py")) + [pathlib.Path(__file__)]
    assert ROOT / "src" / "agentrust_trace" / "citation.py" in files
    offenders = [
        f"{path.name}:{number}: {line.strip()}"
        for path in files
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.match(line)
    ]
    assert not offenders, offenders
    assert pattern.match("import socket") and pattern.match("from urllib import request")


def _refuse_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace `socket.socket` with a class whose construction fails. A class, not a
    function, because `ssl` subclasses it at import; a dotted string, because this
    file must not import `socket`."""

    class RefusingSocket:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("citation resolution opened a socket")

    monkeypatch.setattr("socket.socket", RefusingSocket)


def test_I7_a_plain_function_resolver_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    _refuse_sockets(monkeypatch)
    for path in FILES:
        doc = _load(path)
        _assert_rows_match(_run(doc).citations, doc["expected"]["citations"], path.name)


def test_I7_the_socket_block_is_live(monkeypatch: pytest.MonkeyPatch) -> None:
    _refuse_sockets(monkeypatch)
    socket_module = sys.modules["socket"]
    with pytest.raises(AssertionError, match="opened a socket"):
        socket_module.create_connection(("127.0.0.1", 9), timeout=0.2)


# ---- I8 to I10 -----------------------------------------------------------------------


def test_I8_a_raising_resolver_is_reported_not_propagated() -> None:
    def boom(uri: str) -> bytes:
        raise RuntimeError("secret operational detail")

    doc = _fresh()
    result = _run(doc, citation_resolver=boom)
    for surface in CONSUMED:
        check = result.citations[surface]
        assert (check.outcome, check.cause) == ("unresolvable", "resolver_raised"), surface
        assert check.evidence["exception"] == "RuntimeError"
        head, leaf = surface.split(".")
        assert check.evidence["uri"] == doc["records"][0][head][leaf]
    assert "secret operational detail" not in json.dumps(_rows(result.citations))
    assert result.revocation == NO_CHECK


def test_I9_the_digest_is_sha256_over_exactly_the_returned_bytes() -> None:
    doc = _fresh()
    for row in doc["expected"]["citations"].values():
        if row["outcome"] == "resolved":
            entry = doc["context"]["resolutions"][row["evidence"]["uri"]]
            raw = base64.b64decode(entry["bytes_base64"])
            assert row["evidence"]["sha256"] == hashlib.sha256(raw).hexdigest()
            assert row["evidence"]["bytes"] == len(raw)
    payload = bytes(range(256)) * 3

    def exact(uri: str) -> bytes:
        return payload

    def empty(uri: str) -> bytes:
        return b""

    for check in check_citations(doc["records"][0], exact).values():
        if check.outcome == "resolved":
            assert check.evidence["sha256"] == hashlib.sha256(payload).hexdigest()
            assert check.evidence["bytes"] == 768
    for surface, check in check_citations(doc["records"][0], empty).items():
        if surface in CONSUMED:
            assert check.outcome == "resolved", surface
            assert check.evidence["sha256"] == (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            assert check.evidence["bytes"] == 0


NOT_CALLABLE: tuple[Any, ...] = (True, 1, "x", b"x", object())


@pytest.mark.parametrize("junk", NOT_CALLABLE, ids=[type(j).__name__ for j in NOT_CALLABLE])
def test_I10_a_non_callable_resolver_is_refused_at_entry(junk: Any) -> None:
    """At entry: before the record is read. `{}` is not a valid record, and the error
    still names the resolver, so the check runs ahead of every record check."""
    doc = _fresh()
    with pytest.raises(ValueError, match="citation_resolver"):
        verify_record({}, doc["context"]["trusted_key"], citation_resolver=junk)
    with pytest.raises(ValueError, match="resolver"):
        check_citations(doc["records"][0], junk)


@pytest.mark.parametrize("returned", ["text", 7, None], ids=["str", "int", "None"])
def test_I10_a_resolver_returning_non_bytes_is_an_outcome_not_a_crash(returned: Any) -> None:
    doc = _fresh()
    result = _run(doc, citation_resolver=lambda uri: returned)
    for surface in CONSUMED:
        check = result.citations[surface]
        assert (check.outcome, check.cause) == ("unresolvable", "resolver_returned_non_bytes")
        assert check.evidence["returned"] == type(returned).__name__


def test_I10_a_non_object_record_is_refused_by_check_citations() -> None:
    for junk in ("a-string", 1, None, [1], b"x"):
        with pytest.raises(ValueError, match="JSON object"):
            check_citations(junk, None)  # type: ignore[arg-type]


def test_I11_a_record_that_fails_verification_drives_no_resolution() -> None:
    """The resolver is called last. A record whose signature does not verify, whose
    signer is not the trusted key, or whose `iat` is stale raises before the resolver
    is asked for anything; a valid record asks for exactly its three URIs, in order."""
    from cryptography.exceptions import InvalidSignature

    doc = _fresh()
    ctx = doc["context"]
    record = doc["records"][0]
    calls: list[str] = []

    def resolver(uri: str) -> bytes:
        calls.append(uri)
        return b"object"

    tampered = json.loads(json.dumps(record))
    first = tampered["signature"][0]
    tampered["signature"] = ("A" if first != "A" else "B") + tampered["signature"][1:]
    with pytest.raises((ValueError, InvalidSignature)):
        verify_record(tampered, ctx["trusted_key"], now=ctx["now"], citation_resolver=resolver)
    assert calls == []
    with pytest.raises(ValueError):
        verify_record(
            record, key_to_jwk(generate_key()), now=ctx["now"], citation_resolver=resolver,
        )
    assert calls == []
    with pytest.raises(ValueError):
        verify_record(
            record, ctx["trusted_key"], now=ctx["now"] + 10 * 86400, max_age_seconds=86400,
            citation_resolver=resolver,
        )
    assert calls == []
    result = _run(doc, citation_resolver=resolver)
    assert all(result.citations[s].outcome == "resolved" for s in CONSUMED)
    expected_calls = []
    for surface in CONSUMED:
        head, leaf = surface.split(".")
        expected_calls.append(record[head][leaf])
    assert calls == expected_calls


# ---- the generator -------------------------------------------------------------------


def test_the_generator_reproduces_the_committed_vectors_byte_for_byte(
    tmp_path: pathlib.Path,
) -> None:
    """LF bytes on every platform. `test_generators_reproduce_fixtures` also covers
    this; it is repeated here so a failure in this set is reported beside the set."""
    import os
    import shutil

    target = tmp_path / "examples" / "citation-resolution"
    shutil.copytree(VECTORS, target)
    subprocess.run(
        [sys.executable, "examples/citation-resolution/gen_citation_vectors.py"],
        cwd=tmp_path, check=True, capture_output=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    for path in FILES:
        assert (target / path.name).read_bytes() == path.read_bytes(), path.name


# ---- diagnostics: message text, kept apart from the vectors --------------------------


def test_diagnostic_verify_record_names_the_argument_it_refuses() -> None:
    doc = _fresh()
    with pytest.raises(ValueError) as caught:
        verify_record(doc["records"][0], doc["context"]["trusted_key"], citation_resolver=1)
    assert str(caught.value) == "citation_resolver must be callable or None"


def test_diagnostic_check_citations_names_what_it_refuses() -> None:
    doc = _fresh()
    with pytest.raises(ValueError) as caught:
        check_citations(doc["records"][0], 1)  # type: ignore[arg-type]
    assert str(caught.value) == "resolver must be callable or None"
    with pytest.raises(ValueError) as caught:
        check_citations("record", None)  # type: ignore[arg-type]
    assert str(caught.value) == "record must be a JSON object, got str"

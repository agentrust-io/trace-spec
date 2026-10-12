"""The published error codes and record samples must agree with the modules.

Every check here comes from drift that was live in `main`, not from first principles.
`TR-SIG-005` was carried by every signature finding and documented nowhere. `TR-ANC-002`
was documented in three files and named by no module, with two descriptions that
disagreed. `docs/levels.md` showed an `anchor` object the closed schema does not define,
and a `runtime.platform` of `sev-snp`, which is not in the enum.

Documentation that disagrees with the code is worse than absent documentation: it reads
as verified. Nothing checked it, which is why all of it survived.
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
from typing import Any

import jsonschema

from trace_tests.modules.unverified import UNVERIFIED_FAILS_FROM_LEVEL
from trace_tests.runner import _LEVEL_MODULES

REPO = pathlib.Path(__file__).resolve().parents[1]
MODULES = REPO / "src" / "trace_tests" / "modules"
ERROR_CODES = REPO / "docs" / "error-codes.md"
LEVELS = REPO / "docs" / "levels.md"
SCHEMA = REPO / "schemas" / "trace-claim.json"
DOCS = REPO / "docs"

_CODE = re.compile(r"TR-[A-Z]{3}-\d{3}")
_DOCUMENTED_ROW = re.compile(r"^\| (TR-[A-Z]{3}-\d{3}) ", re.M)
_JSON_BLOCK = re.compile(r"```json\n(.*?)```", re.S)
#: A row of the unverified-level table in docs/levels.md: code, then a level.
_UNVERIFIED_ROW = re.compile(r"^\| (TR-[A-Z]{3}-\d{3}) \| (\d+) \|", re.M)


def test_published_module_counts_match_the_runner() -> None:
    """Keep total counts on reader entry pages aligned with the active modules."""
    expected = len(set().union(*_LEVEL_MODULES.values()))
    words = ["zero", "one", "two", "three", "four", "five", "six",
             "seven", "eight", "nine", "ten", "eleven", "twelve"]
    pattern = re.compile(r"\b(" + "|".join(words) + r"|\d+) (?:test )?modules\b", re.I)
    for relative in ("README.md", "index.md", "docs/modules.md",
                     "docs/tutorials/writing-conformance-tests.md"):
        text = (REPO / relative).read_text(encoding="utf-8")
        counts = pattern.findall(text)
        assert counts, f"No published total found in {relative}"
        for count in counts:
            actual = int(count) if count.isdigit() else words.index(count.lower())
            assert actual == expected, f"{relative}: says {count} modules; runner has {expected}"
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    badge = re.search(r"Conformance_Tests-(\d+)_modules-", readme)
    assert badge is not None
    assert int(badge.group(1)) == expected


def _codes(text: str) -> set[str]:
    return set(_CODE.findall(text))


def _codes_in_code(source: str) -> set[str]:
    """Codes that appear in a module's string literals, ignoring prose about them.

    Comments and docstrings are not the module naming a code, they are the module
    talking about one. Counting them let a code stay "named" after its last real use
    was removed: a docstring in ``tr_sig`` explaining why ``TR-SIG-003`` must not
    appear in a message was, on its own, enough to keep the deleted code looking
    alive. ``ast`` drops comments, and module, class and function docstrings are
    skipped explicitly.
    """
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))

    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in docstrings:
            continue
        found |= _codes(node.value)
    return found


def test_the_code_set_named_by_the_modules_matches_the_code_set_documented() -> None:
    """Matched on codes *named in* module source, not on what a ``Finding`` carries.

    Those two sets are the same today, measured, and were not: ``TR-SIG-003`` used to
    appear only inside a message string that a ``TR-SIG-005`` finding carried, so it
    was never a ``Finding.code``, and matching on ``Finding.code`` would have demanded
    deleting a row that documented a real condition. The branch that removed that
    prefix closed the gap. The match stays on literals anyway: this reads source text
    and cannot tell which literal reaches a ``Finding``, and a message naming its own
    code is the convention here rather than a defect.

    Codes are read from string literals via ``ast``, not from the file text, so a
    comment or docstring about a code does not count as naming it.

    This is set membership in both directions and nothing more. It cannot tell whether
    a row describes what its code reports, which was a second kind of drift and was
    live here too: the ``TR-SIG-004`` row described private key material in ``cnf.jwk``,
    a condition the module never reports under that code. Catching that would mean
    comparing prose to behaviour, so the rows are checked by reading them.
    """
    named = set()
    for path in sorted(MODULES.glob("*.py")):
        named |= _codes_in_code(path.read_text(encoding="utf-8"))
    # A row, not a mention. A code named in passing somewhere on the page is not
    # documented, and treating it as documented would let the check be satisfied
    # by prose that tells a reader nothing.
    documented = set(_DOCUMENTED_ROW.findall(ERROR_CODES.read_text(encoding="utf-8")))

    assert named == documented, (
        f"named by a module, undocumented: {sorted(named - documented)}\n"
        f"documented, named by no module:  {sorted(documented - named)}\n"
        f"Add the row to {ERROR_CODES.relative_to(REPO)}, or delete it. A code in one "
        "place and not the other is a claim nobody checked."
    )


def _without_required(node: Any) -> Any:
    """The schema with every ``required`` list dropped, except inside ``if`` and ``not``.

    The documented samples are fragments: "changes from Level 1", not whole records.
    Validating them as published fails on absent fields and says nothing about the
    fields that are present. Dropping ``required`` leaves every statement about a value
    that *is* there: ``additionalProperties``, ``enum``, ``pattern``, ``type``.

    ``if`` and ``not`` are left intact deliberately. Stripping ``required`` from an
    ``if`` makes it vacuously true, which fires the matching ``then`` against records
    the condition was never meant to reach. The schema's ``origin`` rule does exactly
    that: strip its ``if`` and every sample is required to be ``software-only``.
    """
    if isinstance(node, dict):
        return {
            key: value if key in ("if", "not") else _without_required(value)
            for key, value in node.items()
            if key != "required"
        }
    if isinstance(node, list):
        return [_without_required(item) for item in node]
    return node


def _drop_elisions(node: Any) -> Any:
    """Remove string values that are visibly abbreviated for the page.

    A documented sample writes a signature as ``eyJhbGciOiJFZERTQSJ9...``. That is a
    reader's placeholder, not a claim about the format, and holding it to the schema's
    base64url pattern would report the page style as a defect.
    """
    if isinstance(node, dict):
        return {k: _drop_elisions(v) for k, v in node.items()
                if not (isinstance(v, str) and "..." in v)}
    if isinstance(node, list):
        return [_drop_elisions(v) for v in node]
    return node


def test_every_json_sample_in_the_docs_agrees_with_the_packaged_schema() -> None:
    """Two drifts lived here: an ``anchor`` object the closed schema does not define,
    and a ``runtime.platform`` of ``sev-snp``, which is not in the enum. A reader
    copying either sample produced a record this suite rejects.

    Every ``.md`` under ``docs/`` is scanned rather than a list of pages kept by hand,
    because a hand-maintained list of what gets checked is the same defect this exists
    to catch, in the one place it would not show.

    Prose lists of valid values are not checked, because checking them means reading
    them. ``docs/error-codes.md``, ``docs/levels.md`` and ``docs/modules/tr-rte.md`` all
    listed platform values that do not exist; only the sample was mechanically catchable.
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema.get("additionalProperties") is False, (
        "This test assumes the packaged schema is closed. If that changed, an unknown "
        "field in a sample is no longer necessarily an error and this needs rewriting."
    )
    validator = jsonschema.Draft202012Validator(_without_required(schema))

    failures: dict[str, list[str]] = {}
    validated = 0
    unparsed = 0
    for page in sorted(DOCS.rglob("*.md")):
        for block in _JSON_BLOCK.findall(page.read_text(encoding="utf-8")):
            try:
                sample = json.loads(block)
            except json.JSONDecodeError:
                unparsed += 1
                continue  # prose-annotated fragment, not a record
            if not isinstance(sample, dict):
                continue
            validated += 1
            errors = [e.message for e in validator.iter_errors(_drop_elisions(sample))]
            if errors:
                failures.setdefault(str(page.relative_to(REPO)), []).extend(errors)

    assert not failures, (
        f"JSON samples in the documentation disagree with {SCHEMA.name}, so a reader "
        f"copying one gets a record this suite rejects: {failures}"
    )
    # Without this the check degrades to nothing the moment the samples stop parsing
    # or the fences change, and it degrades silently, reporting a pass over no work.
    assert validated, (
        f"no JSON object sample under {DOCS.relative_to(REPO)} was validated "
        f"({unparsed} block(s) did not parse). Either the samples are gone or the fence "
        "this reads has changed; a check over nothing must not report a pass."
    )


def _unverified_emitters(source: str) -> set[str]:
    """Codes this module constructs a ``Finding`` for with ``Status.UNVERIFIED``.

    Matched on the construction rather than on the string, because a code named
    in a message, a comment or a table is not the module *emitting* it. The
    registration table names every code it governs; without this the two sets
    could agree while nothing actually produced one of them.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name != "Finding":
            continue
        args = list(node.args)
        by_kw = {k.arg: k.value for k in node.keywords}
        code_node = args[0] if args else by_kw.get("code")
        status_node = args[1] if len(args) > 1 else by_kw.get("status")
        if not isinstance(code_node, ast.Constant) or not isinstance(code_node.value, str):
            continue
        if not (isinstance(status_node, ast.Attribute) and status_node.attr == "UNVERIFIED"):
            continue
        found |= _codes(code_node.value)
    return found


def _emitted_unverified_codes() -> set[str]:
    emitted: set[str] = set()
    for path in sorted(MODULES.glob("*.py")):
        emitted |= _unverified_emitters(path.read_text(encoding="utf-8"))
    return emitted


def test_every_code_that_can_be_unverified_is_registered() -> None:
    """A module emitting UNVERIFIED under an unregistered code fails from level 1.

    That default is fail-closed and therefore safe, but it is also silent: the
    code would be governed by a rule nobody chose. Registering it is a
    decision, so it has to be made rather than defaulted into.
    """
    emitted = _emitted_unverified_codes()
    registered = set(UNVERIFIED_FAILS_FROM_LEVEL)
    assert emitted <= registered, (
        f"emitted as UNVERIFIED and not registered: {sorted(emitted - registered)}\n"
        "Add the code to UNVERIFIED_FAILS_FROM_LEVEL with the level it fails from, "
        "or stop emitting UNVERIFIED under it. Falling through to the default means "
        "a level nobody picked."
    )


def test_every_registered_code_is_actually_emitted() -> None:
    """The other direction: a row for a code nothing produces documents a fiction.

    This is the half that catches a table outliving its module. A registered
    code with no emitter reads as a check the suite performs, and it does not.
    """
    emitted = _emitted_unverified_codes()
    registered = set(UNVERIFIED_FAILS_FROM_LEVEL)
    assert registered <= emitted, (
        f"registered and emitted by no module: {sorted(registered - emitted)}\n"
        "Delete the row, or emit the finding. A level for a status nothing "
        "produces is a claim nobody checked."
    )


def test_the_registration_table_and_the_published_table_agree() -> None:
    """``docs/levels.md`` publishes the levels; the module decides them.

    Two copies of one fact, which is the shape everything else in this file
    exists to catch. Compared by row rather than by prose, because a reader
    acting on the published table needs the number to be the one the code uses.
    """
    published = {code: int(level) for code, level in _UNVERIFIED_ROW.findall(
        LEVELS.read_text(encoding="utf-8"))}
    assert published == UNVERIFIED_FAILS_FROM_LEVEL, (
        f"published in {LEVELS.relative_to(REPO)}: {published}\n"
        f"registered in the module:      {UNVERIFIED_FAILS_FROM_LEVEL}\n"
        "A reader following the page must get the level the code applies."
    )
    assert published, (
        "no unverified-level row was parsed, so this check would pass over no "
        "work; the table in docs/levels.md is gone or its shape changed"
    )

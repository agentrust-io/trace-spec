"""Every API call the README names has to exist in the package.

`pyproject.toml` sets `readme = "README.md"`, so this file is the PyPI long
description: a call written here is the first instruction a new user reads, and
it is the text an answer engine quotes back when asked how to use TRACE. Through
0.10.0 the README told them to call `TrustRecord.sign(claims, signing_key)`,
`record.anchor()` and `record.verify(verifying_key)`. None of the three has ever
existed. The package signs with `sign_record`, checks with `verify_record`, and
does not anchor anything.

Nothing caught it. `tests/test_docs_quickstart.py` executes the fenced blocks in
`docs/`, and the README states its API in inline spans inside prose, which no
instrument read. That is the gap this file closes, and it closes it for the file
that travels furthest.

Two instruments, for the two ways the README states an API. The fenced block is
executed. The inline spans are resolved, by a rule kept deliberately narrow so it
stays a fact check rather than a style check. A call-shaped inline span is
resolved one of two ways:

* a qualified name (`agentrust_trace.sign_record(...)`, `TrustRecord.sign(...)`)
  is walked attribute by attribute from the exported symbol it starts at;
* an unqualified receiver (`record.anchor()`) cannot be resolved, so the method
  name has to exist on some exported class instead, and not be one of the names
  every object inherits, which would resolve for any receiver at all.

A call that is deliberately not package API (`json.dumps(...)`, say) fails here
by design. Qualify it, or write it without the parentheses, rather than loosening
the rule: the point is that a reader cannot tell prose from instructions, so
neither does this test.
"""
from __future__ import annotations

import inspect
import pathlib
import re
import subprocess
import sys

import agentrust_trace

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"

#: A call inside an inline code span: the dotted name in front of the paren.
CALL = re.compile(r"`([A-Za-z_][A-Za-z0-9_.]*)\s*\(")


#: Attributes every object or class carries. A README that told a reader to call
#: `record.mro()` would otherwise resolve, since the name exists on every class,
#: and the check would be agreeing with itself rather than with the package.
UNIVERSAL_ATTRIBUTES = set(dir(object)) | set(dir(type))


def _exported_classes() -> list[type]:
    return [
        value
        for name in agentrust_trace.__all__
        if inspect.isclass(value := getattr(agentrust_trace, name, None))
    ]


def unresolvable(text: str) -> list[str]:
    """Return the call-shaped names in `text` that do not exist in the package."""
    missing = []
    for name in dict.fromkeys(CALL.findall(text)):
        head, *rest = name.split(".")
        if head == agentrust_trace.__name__:
            # Fully qualified, which is the clearest form to write and would
            # otherwise look like an unresolvable receiver.
            head, *rest = rest or [head]
        target = getattr(agentrust_trace, head, None)
        if target is None:
            # An unqualified receiver. The method has to exist on some exported
            # class, or the sentence is telling a reader to call nothing.
            method = rest[-1] if rest else head
            on_a_class = any(hasattr(cls, method) for cls in _exported_classes())
            if method in UNIVERSAL_ATTRIBUTES or not on_a_class:
                missing.append(name)
            continue
        for attribute in rest:
            target = getattr(target, attribute, None)
            if target is None:
                missing.append(name)
                break
    return missing


def test_every_api_call_in_the_readme_exists() -> None:
    missing = unresolvable(README.read_text(encoding="utf-8"))
    assert missing == [], (
        f"README.md tells a reader to call {missing}, which this package does not have. "
        "That file is the PyPI long description, so a call written there is what someone "
        "runs after `pip install agentrust-trace`. Name the function the package exports, "
        "or, if the call is deliberately not package API, qualify it or write it without "
        "the parentheses."
    )


def test_a_qualified_call_resolves() -> None:
    """The other direction: the clearest way to write a call must not be refused."""
    assert unresolvable("`agentrust_trace.verify_record(record)` and `sign_record(r, k)`") == []


def test_the_readme_example_runs(tmp_path: pathlib.Path) -> None:
    """The README's one fenced block, executed rather than read.

    `tests/test_docs_quickstart.py` runs the fenced blocks in `docs/` this way.
    The README had no instrument at all, and it is the file that travels to PyPI,
    so its example is executed here too. The count is pinned: a second block is a
    deliberate act, not something that arrives unmeasured.
    """
    blocks = re.findall(r"^```python\n(.*?)^```", README.read_text(encoding="utf-8"), re.S | re.M)
    assert len(blocks) == 1, (
        f"README.md has {len(blocks)} fenced python blocks and this test runs one. Extend "
        "it to run the others, or the new block is an example nothing executes."
    )
    result = subprocess.run(
        [sys.executable, "-c", blocks[0]],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_check_catches_the_calls_that_shipped_through_0_10_0() -> None:
    """The negative control is the defect itself, kept so the check cannot rot.

    If this ever passes, `unresolvable` has stopped resolving anything and the
    test above is measuring nothing.
    """
    shipped = (
        "sign a record with `TrustRecord.sign(claims, signing_key)`, anchor it to a "
        "SCITT ledger with `record.anchor()`, and check it with "
        "`record.verify(verifying_key)`."
    )
    assert unresolvable(shipped) == [
        "TrustRecord.sign",
        "record.anchor",
        "record.verify",
    ]


def test_a_name_every_object_carries_does_not_count_as_an_api() -> None:
    """`record.mro()` names nothing a reader can act on, and must not resolve.

    The unqualified branch asks whether some exported class has the method. Every
    class has `mro`, `__init__` and the rest of the object surface, so without
    this the check would pass on a receiver that does not exist either.
    """
    assert unresolvable("`record.mro()` and `record.__init__()`") == [
        "record.mro",
        "record.__init__",
    ]
    # Real methods of exported classes still resolve, which is the other half.
    assert unresolvable("`record.model_dump()`") == []

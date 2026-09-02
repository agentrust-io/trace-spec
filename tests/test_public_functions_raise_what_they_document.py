"""Every public function in the package, swept, against the error its module documents.

This test exists because the claim it makes was made once before without it. The change
that closed the last three record-argument leaks said "every public entry point in the
package now reports zero leaks under the same sweep", and the sweep was never committed.
Nobody could re-run it, including its author, and it was wrong in a way that is invisible
from the sentence: it fed record-shaped values, so it never reached the functions whose
argument is a key, and ``key_to_jwk`` leaked ``AttributeError`` on every input including
the public key that is the plausible mistake for a function with that name.

A claim about a surface has to be checked by something that finds the surface. So the
functions here are discovered by walking the package, and ``DOCUMENTED`` has to name every
module they live in or the first test fails. Adding a module without deciding what it
refuses with is the failure this catches; adding one and quietly not sweeping it is the
failure that produced this file.

What it does not do: sweep every argument of every function. It sweeps the first
positional argument, holding the rest valid, which is where externally-supplied data
arrives. ``CALLS`` is written out per function rather than generated, because a generated
call passes ``None`` for the arguments it does not vary, and a ``TypeError`` from the
second argument then reads exactly like a leak in the first. That happened while this file
was being written, and produced a finding against ``verify_bridge`` that did not exist.
"""
from __future__ import annotations

import importlib
import inspect
import json
import pkgutil
import time
from collections.abc import Callable
from typing import Any

import pytest

import agentrust_trace as at
from agentrust_trace import (content_marking, generate_key, intent_bridge, key_to_jwk,
                             provenance, revocation, sign, validate)

#: Values a caller can supply where an object, a string, a key or bytes is expected.
#: The last five are the ones that separate a strict canonicalizer from a permissive
#: one: JSON carries them, and RFC 8785 has no form for four of them.
JUNK: tuple[Any, ...] = (
    "a-string", 123, None, [1, 2], True, False, 0, {}, "", b"bytes",
    10**20, float("nan"), float("inf"), "\ud800", {"a": 1}, [{}], 1.5,
)

#: The exceptions each module documents as its refusal. Anything else escaping a
#: public function in that module is a leak: a caller written against the documented
#: contract does not catch it.
DOCUMENTED: dict[str, tuple[str, ...]] = {
    "content_marking": ("ContentMarkingError", "RecordMismatch"),
    "intent_bridge": ("IntentBridgeError", "AuthorizationDenied", "AuthorizationMismatch"),
    "provenance": ("ProvenanceError", "ToolCatalogMismatch"),
    "revocation": ("ValueError", "UnanchorableValue"),
    "sign": ("ValueError", "UnanchorableValue", "InvalidSignature"),
    "validate": ("ValueError", "ValidationError"),
    "models": ("ValidationError",),
    "adapters": ("ValueError", "ValidationError"),
}

_KEY = generate_key()
_JWK = key_to_jwk(_KEY)
_RECORD_BYTES = json.dumps(
    {"eat_profile": "x", "subject": "spiffe://e.example/agent/a"}
).encode()
_AUTHORIZATION = {"iss": "https://a.example", "sub": "urn:agent:x", "iat": int(time.time())}

#: name -> a call varying only the first positional argument.
CALLS: dict[str, Callable[[Any], Any]] = {
    "content_marking.build_assertion":
        lambda v: content_marking.build_assertion(v, url="https://e.example/r.json"),
    "content_marking.verify_assertion":
        lambda v: content_marking.verify_assertion(v, _RECORD_BYTES),
    "intent_bridge.digest_jcs": intent_bridge.digest_jcs,
    "intent_bridge.sign_bridge": lambda v: intent_bridge.sign_bridge(v, _KEY),
    "provenance.check_tool_catalog": lambda v: provenance.check_tool_catalog(v, []),
    "provenance.sign_record": lambda v: provenance.sign_record(v, _KEY),
    "provenance.tool_catalog_hash": provenance.tool_catalog_hash,
    "provenance.verify_record": lambda v: provenance.verify_record(v, _JWK),
    "revocation.bundle_digest": revocation.bundle_digest,
    "revocation.check_bundle": lambda v: revocation.check_bundle(
        v, trusted_key_identifiers=[], trusted_bundle_keys=[_JWK], now=1785000000,
        max_bundle_age_seconds=86400, max_future_skew_seconds=300,
    ),
    "sign.anchor_bytes": sign.anchor_bytes,
    "sign.jwk_thumbprint": sign.jwk_thumbprint,
    "sign.key_to_jwk": sign.key_to_jwk,
    "sign.load_key": sign.load_key,
    "sign.sign_record": lambda v: sign.sign_record(v, _KEY),
    "sign.verify_record": lambda v: sign.verify_record(v, _JWK),
    "validate.iter_errors": validate.iter_errors,
    "validate.validate_json": validate.validate_json,
}

#: Functions with no externally-supplied positional argument to sweep. Listed so that
#: the coverage test below can account for the whole surface rather than for the part
#: somebody remembered.
NO_ARGUMENT_TO_SWEEP = {
    "sign.generate_key", "sign.load_signing_key",
    "provenance.build_record",
    "intent_bridge.verify_bridge",  # every argument is keyword-only and required
}


def _public_functions() -> dict[str, Any]:
    """Walk the package. Discovered rather than listed: a hardcoded roster is how the
    previous sweep missed a whole class of argument."""
    modules = [at]
    for info in pkgutil.walk_packages(at.__path__, at.__name__ + "."):
        if "__" not in info.name:
            modules.append(importlib.import_module(info.name))
    found: dict[str, Any] = {}
    for module in modules:
        for name, obj in vars(module).items():
            if name.startswith("_") or inspect.isclass(obj) or not callable(obj):
                continue
            origin = getattr(obj, "__module__", "")
            if origin.startswith("agentrust_trace"):
                found[f"{origin.split('.')[-1]}.{name}"] = obj
    return found


def test_the_walk_finds_something_to_sweep() -> None:
    """An empty walk would make every test below vacuous and green."""
    found = _public_functions()
    assert len(found) >= 20, f"only found {sorted(found)}"


def test_every_public_function_is_either_swept_or_declared_unsweepable() -> None:
    """The coverage test. A new public function fails here until somebody decides
    which it is, which is the step that was skipped last time."""
    found = set(_public_functions())
    accounted = set(CALLS) | NO_ARGUMENT_TO_SWEEP
    assert found == accounted, (
        f"not swept and not declared unsweepable: {sorted(found - accounted)}\n"
        f"declared but no longer present: {sorted(accounted - found)}"
    )


def test_every_swept_module_declares_what_it_refuses_with() -> None:
    modules = {name.split(".")[0] for name in CALLS}
    assert modules <= set(DOCUMENTED), f"undeclared: {sorted(modules - set(DOCUMENTED))}"


@pytest.mark.parametrize("name", sorted(CALLS))
def test_no_public_function_raises_an_undocumented_exception(name: str) -> None:
    allowed = DOCUMENTED[name.split(".")[0]]
    call = CALLS[name]

    leaked: dict[str, Any] = {}
    for value in JUNK:
        try:
            call(value)
        except Exception as exc:  # noqa: BLE001 - the whole point is what escapes
            if type(exc).__name__ not in allowed:
                leaked.setdefault(type(exc).__name__, repr(value)[:20])

    assert not leaked, (
        f"{name} raised {leaked}, which its module does not document as its refusal. "
        f"Documented: {allowed}. A caller written against that contract does not catch "
        f"these."
    )


#: One value per function that must produce a named outcome, and the outcome it must
#: produce. A ratio over the junk matrix cannot serve here: `anchor_bytes` and
#: `sign_bridge` legitimately accept most of it, so "most inputs raised" is a property
#: of the function rather than evidence the call is wired up. An explicit witness is.
REACHES: dict[str, tuple[Any, str]] = {
    "content_marking.build_assertion": (None, "ContentMarkingError"),
    "content_marking.verify_assertion": (None, "ContentMarkingError"),
    "intent_bridge.digest_jcs": ("a-string", "IntentBridgeError"),
    "intent_bridge.sign_bridge": ({"k": float("nan")}, "IntentBridgeError"),
    "provenance.check_tool_catalog": (None, "ProvenanceError"),
    "provenance.sign_record": (None, "ProvenanceError"),
    "provenance.tool_catalog_hash": (None, "ProvenanceError"),
    "provenance.verify_record": (None, "ProvenanceError"),
    "revocation.bundle_digest": (None, "ValueError"),
    "sign.anchor_bytes": (b"bytes", "UnanchorableValue"),
    "sign.jwk_thumbprint": (None, "ValueError"),
    "sign.key_to_jwk": (None, "ValueError"),
    "sign.load_key": (None, "ValueError"),
    "sign.sign_record": (None, "ValueError"),
    "sign.verify_record": (None, "ValueError"),
    "validate.validate_json": (None, "ValidationError"),
}


def test_every_swept_function_has_a_witness() -> None:
    """Two are excluded on purpose and named, rather than silently absent. `iter_errors`
    returns findings instead of raising, and its witness is the next test.
    `check_bundle` reports a bundle it cannot use as an outcome rather than raising,
    by design (spec 3.2.3: inability to check is not evidence of a defect), and its
    witness is `test_check_bundle_reports_junk_as_an_outcome` below."""
    assert set(REACHES) == set(CALLS) - {"validate.iter_errors", "revocation.check_bundle"}


@pytest.mark.parametrize("value", JUNK, ids=[repr(v)[:12] for v in JUNK])
def test_check_bundle_reports_junk_as_an_outcome(value: Any) -> None:
    """The sweep reaches `check_bundle`, and what comes back is a result, not a raise."""
    result = CALLS["revocation.check_bundle"](value)
    assert result.outcome == "unverified_for_revocation"
    assert result.cause == "bundle_malformed"


@pytest.mark.parametrize("name", sorted(REACHES))
def test_the_sweep_actually_reaches_each_function(name: str) -> None:
    """A `CALLS` entry can be wrong in a way that never reaches its function, and a
    sweep that never arrives reports clean. This is what makes the clean reading mean
    something."""
    value, expected = REACHES[name]
    with pytest.raises(Exception) as caught:  # noqa: PT011 - the type is the assertion
        CALLS[name](value)
    assert type(caught.value).__name__ == expected, (
        f"{name}({value!r}) raised {type(caught.value).__name__}, expected {expected}"
    )


def test_iter_errors_reports_rather_than_raising() -> None:
    """Its contract is a list of findings, so silence is its failure mode, not an
    exception. A non-record returning no findings would be a caller accepting junk."""
    assert validate.iter_errors("a-string"), "iter_errors reported nothing for a string"
    assert validate.iter_errors({}), "iter_errors reported nothing for an empty object"

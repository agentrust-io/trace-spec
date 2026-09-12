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

``CALLS`` sweeps the first positional argument, holding the rest valid, which is where
externally-supplied data arrives. It is written out per function rather than generated,
because a generated call passes ``None`` for the arguments it does not vary, and a
``TypeError`` from the second argument then reads exactly like a leak in the first. That
happened while this file was being written, and produced a finding against
``verify_bridge`` that did not exist.

``KEYWORD_CALLS`` sweeps every other parameter, one at a time, from a call that is valid
in full. It exists because the first version of this file said "what it does not do:
sweep every argument", listed ``build_record`` and ``verify_bridge`` as having no
positional argument to sweep, and #320 then arrived on ``build_record``'s ``issued_at``,
a keyword argument that ``int()`` coerced before the guard saw it. An exemption with a
true reason is still an exemption: "no positional argument" was correct and the leaks
were on the other kind. Every parameter of every public function is now either swept
here or named in ``UNSWEPT_PARAMETERS`` with the reason, and the coverage test holds the
three sets equal to the signatures, so a new parameter fails until somebody decides.

The assertions decide what must be refused. What each parameter *accepts* is a judgment,
so ``tools/sweep_public_surface.py`` prints it from these same tables as a report for a
reader; the last two tests hold that the report still runs over every function here and
that its ``--strict`` exit goes red the moment a leak is not filed.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import json
import pathlib
import pkgutil
import sys
import time
from collections.abc import Callable
from typing import Any

import pytest

import agentrust_trace as at
from agentrust_trace import (content_marking, generate_key, intent_bridge, key_to_jwk,
                             provenance, revocation, sign, successor_observation, validate)

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
    "successor_observation": ("SuccessorObservationError",),
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
    # #320: every argument is keyword-only, which is why this was listed as
    # unsweepable and why a coercion in front of the validator went unnoticed.
    # Only issued_at varies; the rest are valid so a refusal can only come from it.
    #
    # `KEYWORD_CALLS` below also sweeps this function, and over every parameter rather
    # than this one. The overlap is deliberate and is left for the maintainer to
    # collapse or keep: this entry arrived with #334 and deleting a test that landed
    # hours ago, inside a pull request about something else, is not this branch's call.
    # Keeping both costs one duplicated `issued_at` sweep and no coverage.
    "provenance.build_record": lambda v: provenance.build_record(
        kind="publisher-asserted", publisher="did:web:example.com", tools=[],
        artifact={"package": "x", "digest": "sha256:" + "a" * 64}, issued_at=v,
    ),
    "provenance.check_tool_catalog": lambda v: provenance.check_tool_catalog(v, []),
    "provenance.sign_record": lambda v: provenance.sign_record(v, _KEY),
    "provenance.tool_catalog_hash": provenance.tool_catalog_hash,
    "provenance.verify_record": lambda v: provenance.verify_record(v, _JWK),
    "successor_observation.evaluate_successor_observation": lambda v: (
        successor_observation.evaluate_successor_observation(
            v,
            expected_successor_digest="sha256:" + "0" * 64,
            trusted_observers={"observer-1"},
            executor_id="executor-1",
            independence_required=True,
            now=160,
            max_age_seconds=30,
            predicate=lambda obs: obs.get("reachable") is True,
        )
    ),
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
#: somebody remembered. `build_record` and `verify_bridge` were here until #320; their
#: arguments are keyword arguments and are swept below.
NO_ARGUMENT_TO_SWEEP = {
    "sign.generate_key", "sign.load_signing_key",
}

_RECORD_JSON = json.dumps({
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2", "iat": 1760000000,
    "subject": "spiffe://example.org/agent/image-bot", "data_class": "public",
}).encode()
_ASSERTION = content_marking.build_assertion(_RECORD_JSON, url="https://r.example/r.json")
_DECLARATION = {"impact": "external-side-effect", "purpose": "send invoice"}
_TOOL_CALL = {"name": "send_invoice", "arguments": {"approved": 1}}
_BRIDGE_AUTH = {
    "authorization_id": "auth-1", "decision": "allow", "authorizer": "finance-policy",
    "authorizer_key_id": "key-1", "authorized_at": 100, "expires_at": 200,
    "scope": {"tools": ["send_invoice"], "impacts": ["external-side-effect"]},
    "pic": {"profile": "PIC-CJSON/1.0", "intent_digest": "sha256:" + "1" * 64,
            "args_digest": "sha256:" + "2" * 64},
    "declaration_digest": intent_bridge.digest_jcs(_DECLARATION),
    "tool_call_digest": intent_bridge.digest_jcs(_TOOL_CALL),
    "transcript_required": True,
}
_BRIDGE = intent_bridge.sign_bridge(_BRIDGE_AUTH, _KEY)
_TRANSCRIPT = {"before": {"tool_call": dict(_TOOL_CALL)}, "after": {"status": "accepted"}}
_SUCCESSOR_AFTER = {
    "observation": {"commit": "abc123", "reachable": True},
    "observer": "observer-1",
    "observed_at": 150,
}
_SUCCESSOR_DIGEST = intent_bridge.digest_jcs(_SUCCESSOR_AFTER)
_TOOLS = [{"name": "search", "description": "search", "input_schema": {"type": "object"}}]
_ARTIFACT = {"package": "pkg:npm/%40acme/mcp-search@2.1.0", "digest": "sha256:" + "0" * 64}
_PROVENANCE = provenance.build_record(
    kind="publisher-asserted", publisher="did:web:acme.example", tools=_TOOLS,
    artifact=_ARTIFACT, issued_at=1760000000,
)
_PROVENANCE_SIGNED = provenance.sign_record(_PROVENANCE, _KEY)
_VECTOR = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "examples" / "revocation-bundle"
     / "01-fresh-well-inside-both-bounds.json").read_text(encoding="utf-8")
)
_CTX = _VECTOR["context"]
_TRUST_RECORD = _VECTOR["records"][0]

#: name -> (a complete valid call as keyword arguments, the parameters to vary). Each
#: baseline is asserted to succeed before anything is varied, so a leak reported here
#: is from the varied parameter and not from a baseline that was already broken.
KEYWORD_CALLS: dict[str, tuple[Callable[[], dict[str, Any]], tuple[str, ...]]] = {
    "content_marking.build_assertion": (
        lambda: {"record_bytes": _RECORD_JSON, "url": "https://r.example/r.json",
                     "alg": "sha256", "anchor": None},
        ("url", "alg", "anchor"),
    ),
    "content_marking.verify_assertion": (
        lambda: {"assertion": _ASSERTION, "record_bytes": _RECORD_JSON}, ("record_bytes",),
    ),
    "intent_bridge.sign_bridge": (
        lambda: {"authorization": _BRIDGE_AUTH, "key": _KEY}, ("key",),
    ),
    "intent_bridge.verify_bridge": (
        lambda: {"bridge": _BRIDGE, "trusted_authorizer_jwk": {**_JWK, "kid": "key-1"},
                     "declaration": _DECLARATION,
                     "pic_intent_digest": _BRIDGE_AUTH["pic"]["intent_digest"],
                     "pic_args_digest": _BRIDGE_AUTH["pic"]["args_digest"],
                     "tool_call": _TOOL_CALL, "transcript": _TRANSCRIPT, "now": 150},
        ("bridge", "trusted_authorizer_jwk", "declaration", "pic_intent_digest",
         "pic_args_digest", "tool_call", "transcript", "now"),
    ),
    "successor_observation.evaluate_successor_observation": (
        lambda: {
            "after": _SUCCESSOR_AFTER,
            "expected_successor_digest": _SUCCESSOR_DIGEST,
            "trusted_observers": {"observer-1"},
            "executor_id": "executor-1",
            "independence_required": True,
            "now": 160,
            "max_age_seconds": 30,
            "predicate": lambda obs: obs.get("reachable") is True,
        },
        ("expected_successor_digest", "trusted_observers", "executor_id",
         "independence_required", "now", "max_age_seconds", "predicate"),
    ),
    "provenance.build_record": (
        lambda: {"kind": "publisher-asserted", "publisher": "did:web:acme.example",
                     "tools": _TOOLS, "artifact": _ARTIFACT, "endpoint": None, "attestation": None,
                     "issued_at": 1760000000},
        ("kind", "publisher", "tools", "artifact", "endpoint", "attestation", "issued_at"),
    ),
    "provenance.check_tool_catalog": (
        lambda: {"record": _PROVENANCE, "tools": _TOOLS}, ("tools",),
    ),
    "provenance.sign_record": (lambda: {"record": _PROVENANCE, "key": _KEY}, ("key",)),
    "provenance.verify_record": (
        lambda: {"record": _PROVENANCE_SIGNED, "trusted_jwk": _JWK, "revocation": None,
                     "max_age_seconds": None, "max_future_skew_seconds": 300},
        ("trusted_jwk", "revocation", "max_age_seconds", "max_future_skew_seconds"),
    ),
    "revocation.check_bundle": (
        lambda: {"bundle": _CTX["bundle"],
                     "trusted_key_identifiers": [sign.jwk_thumbprint(_CTX["trusted_key"])],
                     "trusted_bundle_keys": _CTX["trusted_bundle_keys"], "now": _CTX["now"],
                     "max_bundle_age_seconds": _CTX["max_bundle_age_seconds"],
                     "max_future_skew_seconds": _CTX["max_future_skew_seconds"]},
        ("trusted_key_identifiers", "trusted_bundle_keys", "now",
         "max_bundle_age_seconds", "max_future_skew_seconds"),
    ),
    "sign.sign_record": (
        lambda: {"record": {k: v for k, v in _TRUST_RECORD.items() if k != "signature"},
                     "key": _KEY},
        ("key",),
    ),
    "sign.verify_record": (
        lambda: {"record": _TRUST_RECORD, "public_key_or_jwk": _CTX["trusted_key"],
                     "allow_embedded_key": False, "max_age_seconds": None,
                     "max_future_skew_seconds": 300, "expected_nonce": None, "revocation": None,
                     "revocation_bundle": _CTX["bundle"],
                     "trusted_bundle_keys": _CTX["trusted_bundle_keys"],
                     "max_bundle_age_seconds": _CTX["max_bundle_age_seconds"],
                     "now": _CTX["now"]},
        ("public_key_or_jwk", "allow_embedded_key", "max_age_seconds",
         "max_future_skew_seconds", "expected_nonce", "revocation", "revocation_bundle",
         "trusted_bundle_keys", "max_bundle_age_seconds", "now"),
    ),
}

#: Parameters swept by neither table, each with the reason. Empty is the goal; a
#: reason that stops being true is what the coverage test is for.
UNSWEPT_PARAMETERS: dict[str, str] = {}

#: (function, parameter) pairs whose leaks are known, filed, and owned by someone
#: else's fix. Strict: the day the fix lands, the entry has to go, or this fails.
#: It held `("provenance.build_record", "issued_at"): "#320"` until 2026-09-12, and the
#: marker did its job twice. #334 landed the reordering half and the leak case went
#: `XPASS(strict)` on the rebase, which is what took the entry off the exception class.
#: The producer-and-verifier case did not flip, because the other half of #320 is the
#: safe-integer bound and #334 did not carry it; the one value that case still reported
#: was `10000000000000000000`. That bound is now in `_check_structure`, so both cases
#: pass and nothing is filed.
LEAKS_FILED: dict[tuple[str, str], str] = {}


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
    accounted = set(CALLS) | set(KEYWORD_CALLS) | NO_ARGUMENT_TO_SWEEP
    assert found == accounted, (
        f"not swept and not declared unsweepable: {sorted(found - accounted)}\n"
        f"declared but no longer present: {sorted(accounted - found)}"
    )


def _module_of(name: str) -> Any:
    return {"content_marking": content_marking, "intent_bridge": intent_bridge,
            "provenance": provenance, "revocation": revocation, "sign": sign,
            "successor_observation": successor_observation,
            "validate": validate}[name.split(".")[0]]


def test_every_parameter_of_every_public_function_is_swept_or_named() -> None:
    """The coverage test for the other kind of argument. #320 sat on a keyword argument of
    a function this file had declared unsweepable, with a true reason. So the accounting
    is now per parameter: the first positional through `CALLS`, the rest through
    `KEYWORD_CALLS`, and anything else named in `UNSWEPT_PARAMETERS` with why."""
    missing: dict[str, list[str]] = {}
    stale: list[str] = []
    for name, func in _public_functions().items():
        if name in NO_ARGUMENT_TO_SWEEP:
            continue
        params = list(inspect.signature(func).parameters)
        covered = set(params[:1]) if name in CALLS else set()
        covered |= set(KEYWORD_CALLS.get(name, (None, ()))[1])
        covered |= {p.split(".")[-1] for p in UNSWEPT_PARAMETERS if p.startswith(name + ".")}
        left = [p for p in params if p not in covered]
        if left:
            missing[name] = left
        for p in KEYWORD_CALLS.get(name, (None, ()))[1]:
            if p not in params:
                stale.append(f"{name}.{p}")
    assert not missing, f"parameters swept by nothing and named by nobody: {missing}"
    assert not stale, f"KEYWORD_CALLS names parameters that no longer exist: {stale}"


@pytest.mark.parametrize("name", sorted(KEYWORD_CALLS))
def test_every_keyword_baseline_succeeds_before_anything_is_varied(name: str) -> None:
    base, _ = KEYWORD_CALLS[name]
    func = getattr(_module_of(name), name.split(".")[1])
    func(**base())


def _keyword_cases() -> list[Any]:
    cases = []
    for name, (_, params) in sorted(KEYWORD_CALLS.items()):
        for param in params:
            marks = []
            if (name, param) in LEAKS_FILED:
                marks.append(pytest.mark.xfail(
                    strict=True, reason=f"filed as {LEAKS_FILED[(name, param)]}"))
            cases.append(pytest.param(name, param, id=f"{name}.{param}", marks=marks))
    return cases


@pytest.mark.parametrize(("name", "param"), _keyword_cases())
def test_no_keyword_argument_leaks_an_undocumented_exception(name: str, param: str) -> None:
    allowed = DOCUMENTED[name.split(".")[0]]
    base, _ = KEYWORD_CALLS[name]
    func = getattr(_module_of(name), name.split(".")[1])
    leaked: dict[str, Any] = {}
    for value in JUNK:
        kwargs = base()
        kwargs[param] = value
        try:
            func(**kwargs)
        except Exception as exc:  # noqa: BLE001 - the whole point is what escapes
            if type(exc).__name__ not in allowed:
                leaked.setdefault(type(exc).__name__, repr(value)[:20])
    assert not leaked, (
        f"{name}({param}=...) raised {leaked}, which its module does not document as its "
        f"refusal. Documented: {allowed}."
    )


#: One (parameter, value) per keyword-swept function that must reach the function and
#: come back as the documented refusal, so a clean sweep above means the call arrived.
KEYWORD_REACHES: dict[str, tuple[str, Any, str]] = {
    "content_marking.build_assertion": ("alg", 123, "ContentMarkingError"),
    "content_marking.verify_assertion": ("record_bytes", None, "ContentMarkingError"),
    "intent_bridge.sign_bridge": ("key", None, "IntentBridgeError"),
    "intent_bridge.verify_bridge": ("now", "a-string", "IntentBridgeError"),
    "successor_observation.evaluate_successor_observation":
        ("expected_successor_digest", None, "SuccessorObservationError"),
    "provenance.build_record": ("publisher", 123, "ProvenanceError"),
    "provenance.check_tool_catalog": ("tools", None, "ProvenanceError"),
    "provenance.sign_record": ("key", None, "ProvenanceError"),
    "provenance.verify_record": ("max_age_seconds", "a-string", "ProvenanceError"),
    "revocation.check_bundle": ("now", "a-string", "ValueError"),
    "sign.sign_record": ("key", None, "ValueError"),
    "sign.verify_record": ("max_age_seconds", "a-string", "ValueError"),
}


def test_every_keyword_swept_function_has_a_witness() -> None:
    assert set(KEYWORD_REACHES) == set(KEYWORD_CALLS)


@pytest.mark.parametrize("name", sorted(KEYWORD_REACHES))
def test_the_keyword_sweep_actually_reaches_each_function(name: str) -> None:
    param, value, expected = KEYWORD_REACHES[name]
    base, _ = KEYWORD_CALLS[name]
    kwargs = base()
    kwargs[param] = value
    func = getattr(_module_of(name), name.split(".")[1])
    with pytest.raises(Exception) as caught:  # noqa: PT011 - the type is the assertion
        func(**kwargs)
    assert type(caught.value).__name__ == expected


#: A producer that accepts a value has to emit something its own verifier accepts. This
#: is the half of #320 the leak test cannot see: `build_record(issued_at=10**20)` raised
#: nothing, and `sign_record` then refused the record it built.
PRODUCERS: dict[str, tuple[str, Callable[[dict[str, Any]], Any]]] = {
    "provenance.build_record": (
        "provenance.build_record",
        lambda built: provenance.verify_record(
            provenance.sign_record(built, _KEY), _JWK, max_age_seconds=None),
    ),
    "content_marking.build_assertion": (
        "content_marking.build_assertion",
        lambda built: content_marking.verify_assertion(built, _RECORD_JSON),
    ),
}


def _producer_cases() -> list[Any]:
    cases = []
    for name in sorted(PRODUCERS):
        for param in KEYWORD_CALLS[name][1]:
            marks = []
            if (name, param) in LEAKS_FILED:
                marks.append(pytest.mark.xfail(
                    strict=True, reason=f"filed as {LEAKS_FILED[(name, param)]}"))
            cases.append(pytest.param(name, param, id=f"{name}.{param}", marks=marks))
    return cases


@pytest.mark.parametrize(("name", "param"), _producer_cases())
def test_what_a_producer_accepts_its_own_verifier_accepts(name: str, param: str) -> None:
    base, _ = KEYWORD_CALLS[name]
    func = getattr(_module_of(name), name.split(".")[1])
    _, verify = PRODUCERS[name]
    orphaned: dict[str, str] = {}
    for value in JUNK:
        kwargs = base()
        kwargs[param] = value
        try:
            built = func(**kwargs)
        except Exception:  # noqa: BLE001 - refusing is the leak test's business
            continue
        try:
            verify(built)
        except Exception as exc:  # noqa: BLE001
            orphaned[repr(value)[:20]] = type(exc).__name__
    assert not orphaned, (
        f"{name}({param}=...) accepted values whose output its own verifier refuses: "
        f"{orphaned}. A producer emitting what its signer or verifier will not take is "
        f"the producer reporting success for a record nobody can use."
    )


@pytest.mark.parametrize("anchor", ["", 123, [1, 2]], ids=["empty", "int", "list"])
def test_a_wrong_anchor_is_refused_rather_than_dropped(anchor: Any) -> None:
    """`if anchor:` used to be the only gate, so a non-string was written out as-is and an
    empty string was dropped on the floor: the caller got an assertion with no anchor and
    no error. None of these is a registry entry URI and each is refused, with the error
    naming the parameter. The empty string matters separately because it passes an
    `isinstance` check and would still fall to `if anchor:` without its own clause."""
    with pytest.raises(content_marking.ContentMarkingError, match="anchor"):
        content_marking.build_assertion(_RECORD_JSON, url="https://r.example/r.json", anchor=anchor)


@pytest.mark.parametrize("attestation", [False, 0, ""], ids=["False", "0", "empty"])
def test_a_falsy_attestation_is_refused_rather_than_emitted(attestation: Any) -> None:
    """`kind != "tee-attested" and attestation` is a truthiness test, so on `main` a
    falsy non-`None` value passed it and `build_record` emitted `"attestation": false`
    where spec/server-provenance-v1.md gives `null`. The guard is `is not None` plus the
    type, and it raises the module's own error."""
    kwargs = KEYWORD_CALLS["provenance.build_record"][0]()
    kwargs["attestation"] = attestation
    with pytest.raises(provenance.ProvenanceError, match="attestation"):
        provenance.build_record(**kwargs)


def test_a_record_carrying_attestation_false_is_refused_by_the_verifier() -> None:
    """The one verification-side change in the sweep. The same shape check runs on both
    sides, so a record already carrying `"attestation": false`, which `main`'s
    `build_record` could emit and `main`'s `verify_record` accepted, is refused now. The
    control is the same record with `null`, which verifies."""
    record = dict(_PROVENANCE)
    record["attestation"] = False
    with pytest.raises(provenance.ProvenanceError, match="attestation"):
        provenance.verify_record(provenance.sign_record(record, _KEY), _JWK, max_age_seconds=None)
    record["attestation"] = None
    provenance.verify_record(provenance.sign_record(record, _KEY), _JWK, max_age_seconds=None)


def test_sign_record_refuses_a_record_it_cannot_canonicalise_with_its_own_error() -> None:
    """`_canonical_bytes` is `rfc8785.dumps`, whose errors are its own `ValueError`s. An
    integer past the safe domain reached it through a record `build_record` had accepted,
    and left `sign_record` as `IntegerDomainError`. Same wrap `intent_bridge._jcs` has."""
    with pytest.raises(provenance.ProvenanceError, match="canonical form"):
        provenance.sign_record({**_PROVENANCE, "issued_at": 10**20}, _KEY)


def test_verify_record_refuses_a_record_it_cannot_canonicalise_with_its_own_error() -> None:
    """The verifier half of the same wrap. `sign_record` is a producer and can refuse
    early, but the record reaching `verify_record` is the untrusted document, so a value
    JCS has no form for arrives wherever the structural checks do not type the field.
    An out-of-range integer under `tools` left this function as `rfc8785`'s own
    `IntegerDomainError`. The control is the same edit with a safe integer: it reaches
    the signature check and is refused there, which is what says the first refusal came
    from canonicalisation rather than from the edit itself."""
    signed = provenance.sign_record(_PROVENANCE, _KEY)
    unsignable = {**signed, "tools": [{"name": "t", "version": 10**20}]}
    with pytest.raises(provenance.ProvenanceError, match="canonical form"):
        provenance.verify_record(unsignable, _JWK, max_age_seconds=None)
    safe = {**signed, "tools": [{"name": "t", "version": 1}]}
    with pytest.raises(provenance.ProvenanceError, match="signature does not verify"):
        provenance.verify_record(safe, _JWK, max_age_seconds=None)


@pytest.mark.parametrize("bare", ["sha256:" + "a" * 64, b"bytes", {"kty": "OKP"}],
                         ids=["str", "bytes", "dict"])
def test_a_bare_value_where_an_iterable_is_expected_is_refused(bare: Any) -> None:
    """A `str` iterates as characters and a `dict` as its keys. `check_bundle` with
    `trusted_key_identifiers="sha256:..."` used to look up one-character identifiers,
    match nothing, and report `verified`. That is a result, and it is the wrong one."""
    base, _ = KEYWORD_CALLS["revocation.check_bundle"]
    for param in ("trusted_key_identifiers", "trusted_bundle_keys"):
        kwargs = base()
        kwargs[param] = bare
        with pytest.raises(ValueError, match=param):
            revocation.check_bundle(**kwargs)
    kwargs = KEYWORD_CALLS["sign.verify_record"][0]()
    kwargs["trusted_bundle_keys"] = bare
    with pytest.raises(ValueError, match="trusted_bundle_keys"):
        sign.verify_record(**kwargs)


@pytest.mark.parametrize("falsy", ["", {}, False, 0], ids=["str", "dict", "False", "0"])
def test_a_falsy_non_none_trusted_bundle_keys_is_not_read_as_no_keys(falsy: Any) -> None:
    """`verify_record` used to pass `trusted_bundle_keys or ()` down, so an empty string,
    an empty object or `False` became "no trusted keys" and the bundle check reported
    the bundle key untrusted. Only `None` means no keys; the rest reach the check and
    are refused as the wrong shape."""
    kwargs = KEYWORD_CALLS["sign.verify_record"][0]()
    kwargs["trusted_bundle_keys"] = falsy
    with pytest.raises(ValueError, match="trusted_bundle_keys"):
        sign.verify_record(**kwargs)


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
    "provenance.build_record": (True, "ProvenanceError"),
    "provenance.check_tool_catalog": (None, "ProvenanceError"),
    "provenance.sign_record": (None, "ProvenanceError"),
    "provenance.tool_catalog_hash": (None, "ProvenanceError"),
    "provenance.verify_record": (None, "ProvenanceError"),
    "successor_observation.evaluate_successor_observation":
        ("a-string", "SuccessorObservationError"),
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


# --- The report tool -----------------------------------------------------------------

_TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "sweep_public_surface.py"


def _load_tool() -> Any:
    spec = importlib.util.spec_from_file_location("sweep_public_surface", _TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_report_tool_runs_over_the_same_tables(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tool reads this file's tables rather than keeping its own, so it cannot drift
    from the assertions. This holds that it still loads them, reaches every function in
    both tables, and exits 0 while every known leak is filed."""
    tool = _load_tool()
    monkeypatch.setattr(tool, "_load_tables", lambda: sys.modules[__name__])
    assert tool.main(["--strict"]) == 0
    out = capsys.readouterr().out
    for name in list(CALLS) + list(KEYWORD_CALLS):
        assert name in out, f"{name} is missing from the report"
    assert ", 0 unfiled leak(s)" in out


def test_the_report_tool_goes_red_when_a_leak_is_not_filed(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the exit code. Plant a function that raises what its module does
    not document, with nothing filed for it, and ``--strict`` has to fail, or a green run
    says nothing. The leak is planted rather than borrowed from ``LEAKS_FILED``, so this
    control still fires on the day the last real leak is fixed and that table is empty.
    Without ``--strict`` the report stays informational."""

    def leaks(value: Any) -> None:
        raise RuntimeError("planted: not a ProvenanceError")

    tool = _load_tool()
    monkeypatch.setattr(tool, "_load_tables", lambda: sys.modules[__name__])
    monkeypatch.setitem(CALLS, "provenance.planted_control", leaks)
    assert tool.main(["--strict"]) == 1
    out = capsys.readouterr().out
    assert "provenance.planted_control" in out
    assert "RuntimeError" in out
    assert ", 0 unfiled leak(s)" not in out
    assert tool.main([]) == 0

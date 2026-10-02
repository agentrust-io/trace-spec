"""A malformed record must produce a finding, never an exception.

``runner.run`` calls every module directly, with no ``try``. A module that raises on
a record it does not understand ends the whole run: the caller gets a traceback where
a verdict belongs, and the record is neither passed nor failed.

The original regression covered malformed top-level fields but not nested discriminator
fields. Four modules then performed set membership directly on values from the record:
an array or object at ``policy.enforcement_mode``, ``runtime.platform``,
``build_provenance.slsa_level`` or ``cnf.jwk.kty`` raised ``TypeError`` instead of
returning a finding. This matrix pins both levels of the record shape.

Scope: the record is a dict throughout and its *fields* are malformed. The cmcp case
below hands ``check`` an envelope whose ``trace`` is junk, but it does so directly.
``loader.extract_trace`` does return ``record["trace"]`` unchecked, so reading it in
isolation suggests a hole; there is not one on the path the tool takes, because
``load_record`` refuses a cmcp envelope whose ``trace`` is not a dict before that runs,
and ``extract_trace`` is unexported with ``runner.run`` as its only caller. A library
caller that assembles a record by hand and calls ``runner.run`` without the loader can
still reach it.
"""
from __future__ import annotations

import copy
import inspect
import json
import pathlib
from typing import Any

import pytest

from trace_tests.modules import tr_anc, tr_env, tr_pol, tr_rte, tr_sca, tr_sig, tr_txn
from trace_tests.result import Finding, Status
from trace_tests.runner import run

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors"

MODULES = {
    "tr_env": tr_env, "tr_sig": tr_sig, "tr_pol": tr_pol, "tr_rte": tr_rte,
    "tr_txn": tr_txn, "tr_anc": tr_anc, "tr_sca": tr_sca,
}

#: Values a record can carry where an object or a string is expected. `True` is here
#: because `isinstance(True, int)`; `False` and `0` because a bare truthiness test
#: reads them as absent, which is a different branch from a wrong type.
#:
#: The last three are a different axis and were added after the first nine reported this
#: file clean over a class they cannot represent. Every one of the nine serializes through
#: ``rfc8785`` without complaint, so no number of runs could reach a module that raises
#: while canonicalizing. These three are the ones JCS has no form for: an integer outside
#: the safe range, a non-finite float, and a lone surrogate. All three are ordinary JSON
#: that ``json.loads`` accepts and ``load_record`` has no reason to refuse.
JUNK: tuple[Any, ...] = (
    "a-string", 123, None, [1, 2], True, False, 0, {}, "",
    10**20, float("inf"), "\ud800",
)

TOP_LEVEL = (
    "cnf", "runtime", "policy", "tool_transcript", "build_provenance",
    "transparency", "appraisal", "signature", "model", "subject", "iat",
)

NESTED_DISCRIMINANTS = (
    (("policy", "enforcement_mode"), "TR-POL-002"),
    (("runtime", "platform"), "TR-RTE-001"),
    (("build_provenance", "slsa_level"), "TR-SCA-001"),
    (("cnf", "jwk", "kty"), "TR-SIG-004"),
)


def _record() -> dict[str, Any]:
    raw = json.loads((VECTORS / "signed_root.json").read_text(encoding="utf-8"))
    return dict(raw.get("record", raw))


def _replace(record: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    """Replace the value at *path* in a copied fixture."""
    node = record
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def _call(module: Any, record: dict[str, Any]) -> list[Finding]:
    """Invoke a module's ``check`` whatever its parameter list happens to be.

    Read from the signature rather than written down here, so a module that gains a
    parameter is still exercised instead of quietly dropping out of this test.
    """
    params = list(inspect.signature(module.check).parameters)
    if params[:3] == ["trace", "record", "fmt"]:
        return list(module.check(record, record, "trace", 0))
    if "level" in params:
        return list(module.check(record, 0))
    return list(module.check(record))


def _mutations() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []
    for field in TOP_LEVEL:
        for junk in JUNK:
            record = _record()
            record[field] = junk
            cases.append((f"{field}={junk!r}", record))
    for junk in JUNK:
        record = _record()
        if isinstance(record.get("cnf"), dict):
            record["cnf"]["jwk"] = junk
            cases.append((f"cnf.jwk={junk!r}", record))
    for path, _ in NESTED_DISCRIMINANTS:
        for junk in JUNK:
            record = _record()
            _replace(record, path, junk)
            cases.append((f"{'.'.join(path)}={junk!r}", record))
    record = _record()
    record["cnf"]["jwk"]["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    cases.append(("cnf.jwk carries d", record))
    # Absence is its own class. Replacing a field with junk never exercises the branch
    # a module takes when the key is not there at all.
    for field in TOP_LEVEL:
        record = _record()
        record.pop(field, None)
        cases.append((f"{field} removed", record))
    record = _record()
    if isinstance(record.get("cnf"), dict):
        record["cnf"].pop("jwk", None)
        cases.append(("cnf.jwk removed", record))
    return cases


@pytest.mark.parametrize("name", sorted(MODULES))
def test_no_module_raises_on_a_record_whose_fields_are_malformed(name: str) -> None:
    module = MODULES[name]
    raised: list[str] = []
    for label, record in _mutations():
        try:
            findings = _call(module, copy.deepcopy(record))
        except Exception as exc:  # noqa: BLE001 - the point is that nothing escapes
            raised.append(f"{label} -> {type(exc).__name__}: {exc}")
            continue
        if not findings:
            raised.append(f"{label} -> returned no findings at all")

    assert not raised, (
        f"{name}.check raised or returned nothing on {len(raised)} malformed record(s). "
        f"runner.run has no try, so each of these ends the run instead of failing the "
        f"record:\n  " + "\n  ".join(raised)
    )


@pytest.mark.parametrize(
    ("path", "expected_code"),
    NESTED_DISCRIMINANTS,
    ids=["policy", "runtime", "provenance", "signing-key"],
)
@pytest.mark.parametrize("junk", (["unexpected"], {"unexpected": True}), ids=("array", "object"))
def test_runner_fails_nested_discriminators_instead_of_raising(
    path: tuple[str, ...], expected_code: str, junk: Any
) -> None:
    record = _record()
    _replace(record, path, junk)

    results = run(record, "trace", level=2)

    findings = [finding for module in results.values() for finding in module]
    assert any(finding.code == expected_code and finding.failed() for finding in findings), (
        f"{'.'.join(path)}={junk!r} produced no {expected_code} failure: {findings}"
    )


@pytest.mark.parametrize("slsa_level", [True, False])
def test_runner_rejects_boolean_slsa_levels(slsa_level: bool) -> None:
    """JSON booleans must not inherit Python's integer membership semantics."""
    record = _record()
    record["build_provenance"]["slsa_level"] = slsa_level

    results = run(record, "trace", level=1)

    assert any(
        finding.code == "TR-SCA-001" and finding.failed()
        for finding in results["TR-SCA"]
    ), results["TR-SCA"]


def test_a_record_embedding_its_own_private_key_fails_rather_than_raising() -> None:
    """The condition the check exists for, named as its own case.

    The generic test above would pass if this raised in a module that had no such
    check at all. This one asserts the verdict, so removing the check fails here
    rather than going unnoticed.
    """
    record = _record()
    record["cnf"]["jwk"]["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    findings = tr_sig.check(record, record, "trace", 0)

    leak = [f for f in findings if f.status is Status.FAIL and "private key" in f.message]
    assert leak, f"no finding reports the embedded private key: {findings}"
    assert leak[0].code == "TR-SIG-004", (
        f"the leak is reported under {leak[0].code!r}; docs/error-codes.md documents "
        "this condition under TR-SIG-004"
    )


def test_a_leaked_key_still_reports_whether_the_signature_was_checked() -> None:
    """The leak check returns early, so nothing else in the module runs.

    Before this branch that path raised, so the state was unreachable and no consumer
    had met it. Making it reachable without a TR-SIG-005 would publish a record with no
    signature verdict of any kind: not pass, not fail, not unverified. One consumer in
    this suite already reads that finding with a bare ``next``.
    """
    record = _record()
    record["cnf"]["jwk"]["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    findings = tr_sig.check(record, record, "trace", 0)
    by_code = {f.code: f for f in findings}

    assert "TR-SIG-005" in by_code, (
        f"a leaked-key record reports no signature verdict at all: {findings}"
    )
    assert by_code["TR-SIG-005"].status is Status.UNVERIFIED, (
        "the signature was not checked, so it is unverified rather than passed or failed"
    )
    assert by_code["TR-SIG-004"].status is Status.FAIL


@pytest.mark.parametrize("level", [0, 1, 2])
def test_the_runner_completes_on_a_record_that_embeds_its_own_private_key(level: int) -> None:
    """The regression as it was actually met, one layer above the module.

    The traceback came out of ``runner.run``, which calls each module with no ``try``.
    Testing ``tr_sig.check`` alone would still pass if some later change moved the same
    failure into the runner, so the path that broke is exercised here as well.
    """
    record = _record()
    record["cnf"]["jwk"]["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    results = run(record, "trace", level)

    sig = results["TR-SIG"]
    assert sig, "the runner produced no TR-SIG findings for a record it should reject"
    assert any(f.code == "TR-SIG-004" and f.status is Status.FAIL for f in sig), sig
    assert any(f.code == "TR-SIG-005" and f.status is Status.UNVERIFIED for f in sig), sig


def test_no_finding_from_any_module_repeats_the_key_it_found() -> None:
    """A finding about a leaked private key must not carry the key.

    Findings travel: ``report.py`` publishes every message into a JSON and an HTML
    artifact meant to be forwarded. A message that quoted the offending value to be
    helpful would copy the private key into the thing the reader sends on. The report
    itself carries only the record's digest, so a message is the only place this can
    go wrong, and it can go wrong in any module rather than only the one that reports
    the leak.
    """
    secret = "Zm9yYmlkZGVuLXByaXZhdGUta2V5LW1hdGVyaWFs"
    record = _record()
    record["cnf"]["jwk"]["d"] = secret

    offenders = []
    for name, module in sorted(MODULES.items()):
        for finding in _call(module, copy.deepcopy(record)):
            if secret in finding.message:
                offenders.append(f"{name} {finding.code}: {finding.message}")

    assert not offenders, (
        "a finding repeats the private key it is reporting:\n  " + "\n  ".join(offenders)
    )


def _cmcp_record() -> dict[str, Any]:
    return json.loads((VECTORS / "valid_cmcp_runtime.json").read_text(encoding="utf-8"))


def test_the_cmcp_path_does_not_raise_on_a_malformed_envelope() -> None:
    """The other entry point, which the parametrised test above never reaches.

    ``check`` dispatches to ``check_cmcp_runtime`` on ``fmt == "cmcp-runtime"`` and
    every case above passes ``"trace"``, so the branch that reads ``record["trace"]``
    three levels deep was hardened without being exercised. It reads a value the caller
    supplies rather than the extracted trace, so it can be handed anything.
    """
    raised: list[str] = []
    for junk in JUNK:
        for path in (("trace",), ("trace", "cnf"), ("trace", "cnf", "jwk"), ("signature",)):
            record = _cmcp_record()
            node: Any = record
            for key in path[:-1]:
                if not isinstance(node, dict) or not isinstance(node.get(key), dict):
                    node = None
                    break
                node = node[key]
            if node is None:
                continue
            node[path[-1]] = junk
            label = ".".join(path) + f"={junk!r}"
            try:
                findings = tr_sig.check(record.get("trace", {}), record, "cmcp-runtime", 0)
            except Exception as exc:  # noqa: BLE001 - the point is that nothing escapes
                raised.append(f"{label} -> {type(exc).__name__}: {exc}")
                continue
            if not findings:
                raised.append(f"{label} -> returned no findings at all")

    assert not raised, (
        "tr_sig.check on a cmcp envelope raised or returned nothing:\n  " + "\n  ".join(raised)
    )

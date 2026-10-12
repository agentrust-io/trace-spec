"""Run conformance modules for a given level against a trust record."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType
from typing import Any

from trace_tests import accounting
from trace_tests.loader import extract_trace
from trace_tests.modules import tr_anc, tr_apr, tr_env, tr_pol, tr_rte, tr_sca, tr_sig, tr_txn
from trace_tests.result import Finding

# Modules that run at each level (cumulative).
_LEVEL_MODULES: Mapping[int, tuple[str, ...]] = MappingProxyType(
    {
        0: ("TR-ENV", "TR-SIG", "TR-POL", "TR-APR"),
        1: ("TR-ENV", "TR-SIG", "TR-POL", "TR-APR", "TR-RTE", "TR-SCA"),
        2: (
            "TR-ENV",
            "TR-SIG",
            "TR-POL",
            "TR-APR",
            "TR-RTE",
            "TR-SCA",
            "TR-TXN",
            "TR-ANC",
        ),
    }
)

_Checker = Callable[..., list[Finding]]
_Checkers = tuple[
    _Checker, _Checker, _Checker, _Checker, _Checker, _Checker, _Checker, _Checker
]
_Invoke = Callable[[str, Callable[[], list[Finding]]], list[Finding]]


def _live_checkers() -> _Checkers:
    return (
        tr_env.check,
        tr_sig.check,
        tr_pol.check,
        tr_apr.check,
        tr_rte.check,
        tr_sca.check,
        tr_txn.check,
        tr_anc.check,
    )


def _run_core(
    trace: dict[str, Any],
    record: dict[str, Any],
    fmt: str,
    level: int,
    modules: tuple[str, ...],
    checkers: _Checkers,
    invoke: _Invoke,
    *,
    max_age_seconds: int,
    expected_nonce: str | None,
    receipt: dict[str, Any] | None,
    policy_resolver: Callable[[str], bytes] | None,
) -> dict[str, list[Finding]]:
    """Run one predecoded level through the shared public/accounting path."""
    env, sig, pol, apr, rte, sca, txn, anc = checkers
    results: dict[str, list[Finding]] = {}
    active = set(modules)

    if "TR-ENV" in active:
        results["TR-ENV"] = invoke(
            "TR-ENV", lambda: env(trace, max_age_seconds=max_age_seconds)
        )

    if "TR-SIG" in active:
        results["TR-SIG"] = invoke(
            "TR-SIG", lambda: sig(trace, record, fmt, level)
        )

    if "TR-POL" in active:
        results["TR-POL"] = invoke(
            "TR-POL", lambda: pol(trace, policy_resolver=policy_resolver)
        )

    if "TR-APR" in active:
        results["TR-APR"] = invoke("TR-APR", lambda: apr(trace, level))

    if "TR-RTE" in active:
        results["TR-RTE"] = invoke(
            "TR-RTE", lambda: rte(trace, level, expected_nonce=expected_nonce)
        )

    if "TR-SCA" in active:
        results["TR-SCA"] = invoke("TR-SCA", lambda: sca(trace))

    if "TR-TXN" in active:
        results["TR-TXN"] = invoke("TR-TXN", lambda: txn(trace))

    if "TR-ANC" in active:
        results["TR-ANC"] = invoke(
            "TR-ANC", lambda: anc(trace, receipt=receipt)
        )

    return results


def run(
    record: dict[str, Any],
    fmt: str,
    level: int,
    max_age_seconds: int = tr_env.DEFAULT_MAX_AGE_SECONDS,
    expected_nonce: str | None = None,
    receipt: dict[str, Any] | None = None,
    policy_resolver: Callable[[str], bytes] | None = None,
) -> dict[str, list[Finding]]:
    """Run all modules required for *level* and return findings keyed by module ID."""
    if level not in _LEVEL_MODULES:
        raise ValueError(f"Unknown conformance level {level!r}; valid: 0, 1, 2")
    with accounting._without_capture():
        trace = extract_trace(record, fmt)
        return _run_core(
            trace,
            record,
            fmt,
            level,
            _LEVEL_MODULES[level],
            _live_checkers(),
            accounting._invoke,
            max_age_seconds=max_age_seconds,
            expected_nonce=expected_nonce,
            receipt=receipt,
            policy_resolver=policy_resolver,
        )


def _run_levels(
    record: dict[str, Any],
    fmt: str,
    levels: Iterable[int],
    max_age_seconds: int = tr_env.DEFAULT_MAX_AGE_SECONDS,
    expected_nonce: str | None = None,
    receipt: dict[str, Any] | None = None,
    policy_resolver: Callable[[str], bytes] | None = None,
) -> accounting._Execution:
    """Run one exact contiguous level set and return its atomic accounting value."""
    attempted = tuple(levels)
    if (
        attempted not in ((0,), (0, 1), (0, 1, 2))
        or any(type(level) is not int for level in attempted)
    ):
        raise ValueError("attempted levels must be exactly (0,), (0, 1), or (0, 1, 2)")

    planned = tuple(
        (level, module) for level in attempted for module in _LEVEL_MODULES[level]
    )
    modules = tuple(_LEVEL_MODULES[level] for level in attempted)
    core = _run_core
    checkers = _live_checkers()
    decode = extract_trace
    execute = accounting._execution
    begin = accounting._begin_level
    end = accounting._end_level
    complete = accounting._complete_execution
    invoke = accounting._invoke
    results: dict[int, dict[str, list[Finding]]] = {}
    with execute(record, fmt, attempted, planned) as capture:
        # Decode every level input before the first caller callback runs.
        prepared = tuple(
            (level_record, decode(level_record, fmt))
            for level_record in (
                json.loads(capture.record_bytes) for _level in attempted
            )
        )
        for level, level_modules, (level_record, trace) in zip(
            attempted, modules, prepared, strict=True
        ):
            begin(level)
            results[level] = core(
                trace,
                level_record,
                fmt,
                level,
                level_modules,
                checkers,
                invoke,
                max_age_seconds=max_age_seconds,
                expected_nonce=expected_nonce,
                receipt=receipt,
                policy_resolver=policy_resolver,
            )
            end(level)
        return complete(capture, results)

#!/usr/bin/env python3
"""Report what every public function does with junk, one parameter at a time.

    python tools/sweep_public_surface.py            # the report
    python tools/sweep_public_surface.py --strict   # exit 1 on any unfiled leak

The assertions live in ``tests/test_public_functions_raise_what_they_document.py`` and
run in CI: no undocumented exception from any parameter, what a producer accepts its own
verifier accepts, no bare value where an iterable is expected. This script reuses that
file's tables (``JUNK``, ``CALLS``, ``KEYWORD_CALLS``, ``LEAKS_FILED``) and prints the
part the assertions cannot decide for you: which junk each parameter *accepts*. A
``now`` of ``0`` or a ``max_age_seconds`` of ``10**20`` is accepted on purpose; an
``issued_at`` of ``True`` is accepted by accident, and that is #320. The list is for a
reader to look down, not for CI to pass, which is why it is a script and not a test.

Run it from a checkout with ``requirements/dev.txt`` installed before a release, or when
a public function gains a parameter, and read the ACCEPTED column with the function's
contract open.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
from collections import defaultdict
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEST_FILE = ROOT / "tests" / "test_public_functions_raise_what_they_document.py"
# The tree first, so the report is about this checkout and not an installed release.
sys.path.insert(0, str(ROOT / "src"))


def _load_tables() -> Any:
    spec = importlib.util.spec_from_file_location("sweep_tables", TEST_FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sweep_tables"] = module
    spec.loader.exec_module(module)
    return module


def _outcome(call: Any, allowed: tuple[str, ...]) -> tuple[str, str]:
    try:
        call()
    except Exception as exc:  # noqa: BLE001 - classifying what escapes is the job
        kind = type(exc).__name__
        return ("documented" if kind in allowed else "LEAK", kind)
    return ("accepted", "")


def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    t = _load_tables()
    rows: list[tuple[str, str, str, list[str], dict[str, str]]] = []
    unfiled_leaks = 0
    for name in sorted(t.CALLS):
        allowed = t.DOCUMENTED[name.split(".")[0]]
        accepted: list[str] = []
        leaks: dict[str, str] = {}
        for value in t.JUNK:
            call = t.CALLS[name]
            state, kind = _outcome(lambda v=value, c=call: c(v), allowed)
            if state == "accepted":
                accepted.append(repr(value)[:14])
            elif state == "LEAK":
                leaks.setdefault(kind, repr(value)[:14])
        rows.append((name, "<first positional>", "", accepted, leaks))
    for name, (base, params) in sorted(t.KEYWORD_CALLS.items()):
        allowed = t.DOCUMENTED[name.split(".")[0]]
        func = getattr(t._module_of(name), name.split(".")[1])
        for param in params:
            accepted = []
            leaks = {}
            for value in t.JUNK:
                kwargs = base()
                kwargs[param] = value
                state, kind = _outcome(lambda k=kwargs, f=func: f(**k), allowed)
                if state == "accepted":
                    accepted.append(repr(value)[:14])
                elif state == "LEAK":
                    leaks.setdefault(kind, repr(value)[:14])
            filed = t.LEAKS_FILED.get((name, param), "")
            rows.append((name, param, filed, accepted, leaks))
    width = max(len(r[0]) + len(r[1]) + 1 for r in rows)
    print(f"{'function.parameter':<{width}}  {'LEAKS':<28}  ACCEPTED")
    print("-" * (width + 40))
    by_function: dict[str, int] = defaultdict(int)
    for name, param, filed, accepted, leaks in rows:
        label = f"{name}.{param}" if param != "<first positional>" else f"{name} {param}"
        leak_text = ", ".join(f"{k} on {v}" for k, v in leaks.items()) or "none"
        if leaks and filed:
            leak_text += f" (filed {filed})"
        elif leaks:
            unfiled_leaks += len(leaks)
        by_function[name] += len(accepted)
        print(f"{label:<{width}}  {leak_text:<28}  {', '.join(accepted) or 'none'}")
    print()
    print(f"{len(rows)} parameters swept, {sum(len(r[3]) for r in rows)} accepted junk values, "
          f"{unfiled_leaks} unfiled leak(s)")
    return 1 if strict and unfiled_leaks else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

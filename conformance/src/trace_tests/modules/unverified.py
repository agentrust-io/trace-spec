"""Which unverified findings fail a run, and from which conformance level.

An unverified finding means the check could not be executed against the
evidence the record cites. That is a statement about reachability, not about
the record being wrong: the evidence may be perfectly good and simply out of
reach. It is held apart from a skip so that a consumer can never read it as a
benign omission.

Whether such a finding fails the run is **per code**, read from the table
below, rather than one rule applied to every unverified finding at once.
Different checks lose their evidence for different reasons and at different
levels. A record with no signature cannot be called conformant anywhere that
requires one. A policy bundle that did not resolve is a weaker statement, and
the level at which it stops being tolerable is a property of that check rather
than of the status.

A code absent from the table fails from level 1, which is what the blanket
rule did for every code before this table existed. That default is deliberate:
a new code that nobody remembered to register still fails closed, and the
registration guard turns red rather than the run turning quietly permissive.
"""

from __future__ import annotations

from collections.abc import Callable

from trace_tests.result import Finding

#: Lowest conformance level at which an unverified finding under this code
#: counts as a failure. Registered here and in ``docs/levels.md``; the two are
#: held equal by ``tests/test_docs_match_the_modules.py``.
UNVERIFIED_FAILS_FROM_LEVEL: dict[str, int] = {
    "TR-SIG-005": 1,
    "TR-POL-003": 2,
}

#: Applied to any code the table does not name. Fail-closed on purpose; see
#: the module docstring.
DEFAULT_FAILS_FROM_LEVEL = 1


def unverified_fails(code: str, level: int) -> bool:
    """Return True when an unverified finding under *code* must fail at *level*."""
    return level >= UNVERIFIED_FAILS_FROM_LEVEL.get(code, DEFAULT_FAILS_FROM_LEVEL)


def finding_counts_as_level_failure(
    finding: Finding,
    level: int,
) -> bool:
    """Return whether one finding contributes failure at one level."""
    return _finding_counts_as_level_failure(finding, level, unverified_fails)


def _finding_counts_as_level_failure(
    finding: Finding,
    level: int,
    unverified_rule: Callable[[str, int], bool],
) -> bool:
    """Private policy primitive used with either the live or a frozen threshold rule."""
    if finding.failed():
        return True
    if finding.unverified():
        return unverified_rule(finding.code, level)
    return False

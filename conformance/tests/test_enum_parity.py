"""Every hand-written copy of a schema enum, compared against the schema.

A set literal restating a schema enum accepts what it always accepted. The
specification moving is exactly the case it cannot see, and the failure is
silent: the copy keeps passing its own tests while rejecting a value the schema
now permits. Both drifts these tests were written for had that shape.

`measurement/scripts/enum_drift.py` finds these by walking the AST, which is the
right tool for discovering an unknown copy. This file is the other half: the
copies that are already known, asserted on every run, so the next drift fails in
CI rather than waiting to be looked for.
"""

from __future__ import annotations

import pytest

from tests.test_level0 import VALID_APPRAISAL, VALID_ENFORCEMENT, VALID_PLATFORMS
from trace_tests.modules.tr_apr import _VALID_STATUS
from trace_tests.modules.tr_pol import _VALID_ENFORCEMENT
from trace_tests.modules.tr_rte import _VALID_PLATFORMS


def _schema_enum(schema: dict, *path: str) -> set[str]:
    node = schema
    for key in path:
        node = node["properties"][key]
    return set(node["enum"])


# (label, the hand-written set, the path to its schema enum)
COPIES = [
    ("tr_rte._VALID_PLATFORMS", lambda: _VALID_PLATFORMS, ("runtime", "platform")),
    ("tr_pol._VALID_ENFORCEMENT", lambda: _VALID_ENFORCEMENT, ("policy", "enforcement_mode")),
    ("tr_apr._VALID_STATUS", lambda: _VALID_STATUS, ("appraisal", "status")),
    ("test_level0.VALID_PLATFORMS", lambda: VALID_PLATFORMS, ("runtime", "platform")),
    ("test_level0.VALID_ENFORCEMENT", lambda: VALID_ENFORCEMENT, ("policy", "enforcement_mode")),
    ("test_level0.VALID_APPRAISAL", lambda: VALID_APPRAISAL, ("appraisal", "status")),
]


@pytest.mark.parametrize("label,get_copy,path", COPIES, ids=[c[0] for c in COPIES])
def test_a_hand_written_enum_matches_the_schema(label, get_copy, path, schema) -> None:
    """Equality, not containment.

    A superset is as wrong as a subset here: it means the copy accepts a value
    the schema does not define, which is the same drift pointing the other way.
    """
    declared = set(get_copy())
    expected = _schema_enum(schema, *path)
    assert declared == expected, (
        f"{label} has drifted from schema {'.'.join(path)}\n"
        f"  missing from the copy: {sorted(expected - declared) or 'none'}\n"
        f"  not in the schema:     {sorted(declared - expected) or 'none'}"
    )


def test_every_known_copy_is_listed() -> None:
    """A guard on the guard: six copies exist, and all six are asserted above.

    Adding a seventh without adding it here would leave it unguarded, which is the
    state this file exists to end. `enum_drift.py` is what finds a new one.
    """
    assert len(COPIES) == 6

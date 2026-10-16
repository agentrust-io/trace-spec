"""Every copy of the digest-format pattern, compared against the schema.

The string `^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$` exists in eighteen places:
thirteen `pattern` values in `schemas/trace-claim.json` and five compiled constants
in the modules and the tests. Eighteen copies of one rule, and changing any one of
them is a silent change to what the suite accepts.

`test_enum_parity.py` is the same guard for the hand-written enums.
`measurement/scripts/enum_drift.py` is what discovers an unknown copy, but it
finds them by walking the AST for a set of string constants, so a compiled regex
is invisible to it by construction. That is why these eighteen were unguarded
while the five enum copies were not.

The schema sites are named here rather than discovered, and a walk checks the
list against the schema: a fourteenth digest field appearing in the schema fails
`test_no_digest_site_in_the_schema_is_missing_from_the_list` instead of joining
silently. The list stays named, so adding a site is still a decision; it just
cannot be skipped, and a listed entry naming no schema site fails from the
other side.

The compiled copies get no such walk. `enum_drift.py` cannot see a compiled
regex and neither can a walk of the schema, so nothing discovers a sixth
compiled copy; `assert len(COMPILED_COPIES) == 5` marks that boundary rather
than closing it. That gap is stated here because the schema half no longer
shares it.

Near misses, deliberately not listed: src/trace_tests/inclusion.py
and tests/test_report.py each pin a sha256-only pattern. That is a
narrower rule than this one, not an additional copy of it.
"""

from __future__ import annotations

import pytest

from tests.test_level0 import DIGEST_RE
from trace_tests.modules.tr_pol import _DIGEST_RE as TR_POL_DIGEST_RE
from trace_tests.modules.tr_rte import _DIGEST_RE as TR_RTE_DIGEST_RE
from trace_tests.modules.tr_sca import _DIGEST_RE as TR_SCA_DIGEST_RE
from trace_tests.modules.tr_txn import _DIGEST_RE as TR_TXN_DIGEST_RE

# The schema properties whose `pattern` is the digest format, enumerated rather
# than searched for. A new digest-shaped field is a decision about what this
# suite pins, so it joins this list deliberately or fails
# `test_every_known_site_is_listed`.
SCHEMA_SITES: list[tuple[str, ...]] = [
    ("model", "weights_digest"),
    ("runtime", "measurement"),
    ("policy", "bundle_hash"),
    ("tool_transcript", "hash"),
    ("delegation", "parent_record_hash"),
    ("references", "items", "digest"),
    ("reproducibility", "code_identity"),
    ("reproducibility", "input_closure", "items", "digest"),
    ("reproducibility", "transcript_digest"),
    ("build_provenance", "digest"),
    ("appraisal", "re_execution", "observed_digest"),
    ("appraisal", "re_execution", "verifier_code_identity"),
    ("appraisal", "platform_measurement", "measurement"),
]

# (label, the compiled copy). Lambdas for the same reason `test_enum_parity.py`
# uses them: the value is read when the case runs, not when this module loads.
COMPILED_COPIES = [
    ("tr_pol._DIGEST_RE", lambda: TR_POL_DIGEST_RE),
    ("tr_rte._DIGEST_RE", lambda: TR_RTE_DIGEST_RE),
    ("tr_sca._DIGEST_RE", lambda: TR_SCA_DIGEST_RE),
    ("tr_txn._DIGEST_RE", lambda: TR_TXN_DIGEST_RE),
    ("test_level0.DIGEST_RE", lambda: DIGEST_RE),
]


def _schema_pattern(schema: dict, *path: str) -> str:
    node = schema
    for step in path:
        node = node["items"] if step == "items" else node["properties"][step]
    return str(node["pattern"])


def _reference(schema: dict) -> str:
    """The pattern the compiled copies are held to.

    Any of the thirteen would serve; `test_every_schema_digest_site_holds_one_pattern`
    is what makes the choice arbitrary rather than load-bearing. Drift in this
    particular site therefore reds the copy cases too, which is true rather than
    noisy: the string they are all held to is the one that moved.
    """
    return _schema_pattern(schema, *SCHEMA_SITES[0])


def test_every_schema_digest_site_holds_one_pattern(schema) -> None:
    """The thirteen schema copies, against each other.

    Grouped rather than compared pairwise so the failure says which sites hold
    which string, instead of naming one site and leaving the reader to find its
    partner.
    """
    by_pattern: dict[str, list[str]] = {}
    for path in SCHEMA_SITES:
        site = ".".join(path)
        by_pattern.setdefault(_schema_pattern(schema, *path), []).append(site)

    assert len(by_pattern) == 1, "the schema's digest patterns have drifted apart\n" + "\n".join(
        f"  {pattern!r}\n    {', '.join(sites)}" for pattern, sites in sorted(by_pattern.items())
    )


@pytest.mark.parametrize(
    "label,get_copy", COMPILED_COPIES, ids=[c[0] for c in COMPILED_COPIES]
)
def test_a_compiled_digest_copy_matches_the_schema(label, get_copy, schema) -> None:
    """Byte equality against the schema string, not equivalence.

    Two patterns can accept the same inputs and still be different rules to the
    next person who edits one of them. The schema is the source; a copy that has
    been improved locally is still a copy that no longer says what the schema
    says.
    """
    declared = get_copy().pattern
    expected = _reference(schema)
    assert declared == expected, (
        f"{label} has drifted from the schema's digest pattern\n"
        f"  the copy:   {declared!r}\n"
        f"  the schema: {expected!r}"
    )


def test_no_digest_site_in_the_schema_is_missing_from_the_list(schema) -> None:
    walked: set[tuple[str, ...]] = set()

    def visit(node: object, path: tuple[str, ...]) -> None:
        if isinstance(node, dict):
            pattern = node.get("pattern")
            if isinstance(pattern, str) and pattern.startswith("^sha") and path:
                walked.add(path)
            for name, value in node.items():
                if name == "properties" and isinstance(value, dict):
                    for child, sub in value.items():
                        visit(sub, (*path, child))
                elif name == "items":
                    visit(value, (*path, "items"))
                else:
                    visit(value, path)
        elif isinstance(node, list):
            for item in node:
                visit(item, path)

    visit(schema, ())
    assert walked == set(SCHEMA_SITES), (
        "the schema's digest-shaped fields and SCHEMA_SITES disagree\n"
        f"  in the schema, not listed: {sorted(walked - set(SCHEMA_SITES))}\n"
        f"  listed, not in the schema: {sorted(set(SCHEMA_SITES) - walked)}"
    )


def test_every_known_site_is_listed() -> None:
    """The compiled half of the guard, which no walk can supply.

    The schema half is now checked against the schema itself by
    `test_no_digest_site_in_the_schema_is_missing_from_the_list`, so the count
    that stood in for it here is removed rather than kept alongside. A compiled
    copy is a compiled regex: `enum_drift.py` walks the AST for set literals and
    cannot see one, and a walk of the schema cannot see one either. This count is
    all that marks a twelfth compiled copy going unlisted.
    """
    assert len(COMPILED_COPIES) == 5

"""Regenerate schema/trace-claim-v0.3-draft.json from schema/trace-claim.json.

The draft declares that, outside the profile identifier and ``runtime.evidence``,
its members are byte-identical to the canonical schema. Nothing enforced that,
so it was forked once and drifted: it never received the private-key refusal in
``cnf.jwk`` or the RSA branch (#368). This script is now the only way the draft
changes outside its own members, and tests/test_v03_draft_schema.py fails when
the committed file is not what it produces.

The draft's own members, taken from the committed draft:
``$id``, ``title``, ``description``, ``properties.eat_profile`` and
``properties.runtime.properties.evidence``. Everything else comes from canonical.

Usage: python scripts/gen_v03_draft_schema.py [--check]
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = REPO_ROOT / "schema" / "trace-claim.json"
DRAFT = REPO_ROOT / "schema" / "trace-claim-v0.3-draft.json"

DRAFT_OWN_TOP_LEVEL = ("$id", "title", "description")


def _insert_after(
    mapping: dict[str, Any], key: str, value: Any, after: str | None
) -> dict[str, Any]:
    """Return a copy of ``mapping`` with ``key`` placed after ``after`` (first if None)."""
    out: dict[str, Any] = {}
    if after is None:
        out[key] = value
    for k, v in mapping.items():
        if k == key:
            continue
        out[k] = v
        if k == after:
            out[key] = value
    if key not in out:
        out[key] = value
    return out


def build(canonical: dict[str, Any], draft: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(canonical)
    for key in DRAFT_OWN_TOP_LEVEL:
        result[key] = draft[key]
    result["properties"]["eat_profile"] = copy.deepcopy(draft["properties"]["eat_profile"])

    draft_runtime = draft["properties"]["runtime"]["properties"]
    keys = list(draft_runtime)
    position = keys.index("evidence")
    after = keys[position - 1] if position > 0 else None
    runtime = result["properties"]["runtime"]
    runtime["properties"] = _insert_after(
        runtime["properties"], "evidence", copy.deepcopy(draft_runtime["evidence"]), after
    )
    return result


def render(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def generate() -> str:
    canonical = json.loads(CANONICAL.read_text(encoding="utf-8"))
    draft = json.loads(DRAFT.read_text(encoding="utf-8"))
    return render(build(canonical, draft))


def main(argv: list[str]) -> int:
    text = generate()
    if "--check" in argv:
        current = DRAFT.read_text(encoding="utf-8")
        if current != text:
            print(f"{DRAFT.relative_to(REPO_ROOT)} is out of date; run {Path(__file__).name}")
            return 1
        return 0
    DRAFT.write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

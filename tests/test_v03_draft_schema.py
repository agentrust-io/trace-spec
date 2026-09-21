"""The v0.3 draft schema is canonical plus its own declared members, and nothing else (#368).

The draft states that outside the profile identifier and ``runtime.evidence`` it
is byte-identical to schema/trace-claim.json. It was forked once and drifted,
missing the ``cnf.jwk`` private-key refusal (#296) and the RSA branch (#311), so a
v0.3 record carrying the private half of its confirmation key validated against it.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "gen_v03_draft_schema.py"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_v03_draft_schema", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(name: str) -> dict:
    return json.loads((REPO_ROOT / "schema" / name).read_text(encoding="utf-8"))


def test_committed_draft_is_what_the_generator_produces():
    committed = (REPO_ROOT / "schema" / "trace-claim-v0.3-draft.json").read_text(encoding="utf-8")
    assert committed.replace("\r\n", "\n") == _generator().generate(), (
        "schema/trace-claim-v0.3-draft.json has drifted from schema/trace-claim.json; "
        "run scripts/gen_v03_draft_schema.py"
    )


def test_draft_differs_from_canonical_only_in_its_declared_members():
    canonical, draft = _load("trace-claim.json"), _load("trace-claim-v0.3-draft.json")
    stripped = copy.deepcopy(draft)
    for key in ("$id", "title", "description"):
        stripped[key] = canonical[key]
    stripped["properties"]["eat_profile"] = canonical["properties"]["eat_profile"]
    del stripped["properties"]["runtime"]["properties"]["evidence"]
    assert stripped == canonical


@pytest.mark.parametrize("member", ["d", "p", "q"])
def test_draft_refuses_a_private_key_member_as_canonical_does(member):
    record = _load_example()
    record["cnf"]["jwk"][member] = "AAAA"
    v02, v03 = copy.deepcopy(record), copy.deepcopy(record)
    v03["eat_profile"] = "tag:agentrust-io.com,2026:trace-v0.3"
    canonical = jsonschema.Draft202012Validator(_load("trace-claim.json"))
    draft = jsonschema.Draft202012Validator(_load("trace-claim-v0.3-draft.json"))
    assert list(canonical.iter_errors(v02))
    assert list(draft.iter_errors(v03))


def _load_example() -> dict:
    return json.loads((REPO_ROOT / "examples" / "amd-sev-snp.json").read_text(encoding="utf-8"))

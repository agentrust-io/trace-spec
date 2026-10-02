"""The tool-catalog observed digest recomputes from the pinned tools/list bytes.

docs/rfcs/tool-catalog-observed-digest.md states the derivation in prose.
examples/verifier-token-conformance/catalog/ carries the pinned tools/list files
and, in digests.json, the values recorded for them. gen_corpus.py recomputes the
same values when it builds COMP-MCP-004 to 006. The functions below are written
from the prose and import nothing from the generator, so the three agree only if
the prose is complete enough to implement. A disagreement anywhere fails here by
name.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import cbor2
import pytest
import rfc8785

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "examples" / "verifier-token-conformance"
CATALOG = CORPUS / "catalog"
RECORDED = json.loads((CATALOG / "digests.json").read_text(encoding="utf-8"))

FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
UNSAFE = re.compile(r"[^\x21-\x7e]|[%=]")


def tool_digest(definition: dict) -> str:
    body = {f: definition[f] for f in FIELDS if definition.get(f) is not None}
    preimage = rfc8785.dumps({"profile": RECORDED["label"], "tool": body})
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def tool_key(name: str) -> str:
    raw = name.encode("utf-8", "surrogatepass")
    encoded = UNSAFE.sub(
        lambda m: "".join(f"%{b:02X}" for b in m.group().encode("utf-8", "surrogatepass")), name
    )
    if len(encoded) > 128:
        encoded = encoded[:96] + "~" + hashlib.sha256(raw).hexdigest()[:16]
    return "tool:" + encoded


def catalog_digests(tools: list[dict]) -> tuple[dict[str, str], str]:
    per_tool = {tool_key(str(t.get("name", "") or "unnamed")): tool_digest(t) for t in tools}
    assert len(per_tool) == len(tools), "the pinned catalogs carry no duplicate names"
    lines = "\n".join(f"{key}={per_tool[key]}" for key in sorted(per_tool))
    return per_tool, "sha256:" + hashlib.sha256(lines.encode("utf-8")).hexdigest()


def pinned(name: str) -> list[dict]:
    path = CATALOG / RECORDED["catalogs"][name]["file"]
    return json.loads(path.read_text(encoding="utf-8"))["tools"]


def vector_and_payload(vector_id: str) -> tuple[dict, dict]:
    vector = json.loads((CORPUS / "vectors" / f"{vector_id}.json").read_text(encoding="utf-8"))
    envelope = cbor2.loads(base64.b64decode(vector["envelope_b64"]))
    return vector, json.loads(envelope.value[2])


@pytest.mark.parametrize("name", sorted(RECORDED["catalogs"]))
def test_pinned_catalog_recomputes_to_its_recorded_digests(name):
    per_tool, manifest = catalog_digests(pinned(name))
    assert per_tool == RECORDED["catalogs"][name]["tools"]
    assert manifest == RECORDED["catalogs"][name]["manifest"]


@pytest.mark.parametrize("pair", RECORDED["key_encoding"], ids=lambda p: p["key"][:40])
def test_key_encoding(pair):
    assert tool_key(pair["name"]) == pair["key"]


def test_meta_and_unknown_members_are_not_hashed():
    tools = pinned("deepwiki")
    assert all("_meta" in t for t in tools)
    stripped = [{k: v for k, v in t.items() if k != "_meta"} for t in tools]
    extended = [dict(t, vendorExtension={"x": 1}) for t in tools]
    assert catalog_digests(stripped) == catalog_digests(tools) == catalog_digests(extended)


def test_null_and_absent_are_the_same_and_empty_is_not():
    tool = pinned("deepwiki")[0]
    assert "title" not in tool
    assert tool_digest(dict(tool, title=None)) == tool_digest(tool)
    assert tool_digest(dict(tool, title="")) != tool_digest(tool)


def test_reordering_the_catalog_is_not_drift():
    tools = pinned("deepwiki")
    assert catalog_digests(list(reversed(tools))) == catalog_digests(tools)


def test_drift_is_localized_to_the_changed_tool():
    before, _ = catalog_digests(pinned("deepwiki"))
    after, _ = catalog_digests(pinned("deepwiki-drifted"))
    assert set(before) == set(after)
    assert [k for k in before if before[k] != after[k]] == ["tool:ask_wiki_question"]


def test_wrong_subject_shares_no_tool_with_the_pinned_catalog():
    deepwiki, _ = catalog_digests(pinned("deepwiki"))
    other, _ = catalog_digests(pinned("cloudflare-docs"))
    assert not set(deepwiki) & set(other)


@pytest.mark.parametrize("vector_id", sorted(RECORDED["vectors"]))
def test_vector_pins_and_presents_the_recorded_digests(vector_id):
    role = RECORDED["vectors"][vector_id]
    vector, payload = vector_and_payload(vector_id)
    requirement = next(
        r
        for r in vector["context"]["requirements"]["components"]
        if r["component_id"] == "tools.catalog"
    )
    component = next(c for c in payload["components"] if c["component_id"] == "tools.catalog")
    catalogs = RECORDED["catalogs"]
    assert requirement["expected_observed_digest"] == catalogs[role["pinned"]]["manifest"]
    assert component["observed_digest"] == catalogs[role["presented"]]["manifest"]
    assert vector["expected"]["token"] == role["expected"]["token"]
    assert vector["expected"]["composite_status"] == role["expected"]["composite_status"]

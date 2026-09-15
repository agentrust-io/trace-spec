"""The PIC bridge document quotes a schema pattern and two refusals. Nothing read them.

`docs/integration/pic-trace-bridge-v1.md` tells an integrator what form this bridge carries
PIC's `intent_digest` and `args_digest` in, and what it says when handed the bare hexadecimal
PIC itself produces. It does that by quoting `schema/pic-trace-bridge-v1.json`'s digest pattern
and two strings `agentrust_trace.intent_bridge` raises. A quotation in prose drifts from its
source in silence: the suite is green either way, and the reader consulting the document is the
one who finds out. These pin the quotations to what they quote.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agentrust_trace import intent_bridge

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs/integration/pic-trace-bridge-v1.md").read_text(encoding="utf-8")
SCHEMA = json.loads((ROOT / "schema/pic-trace-bridge-v1.json").read_text(encoding="utf-8"))
PIC_FIELDS = ("intent_digest", "args_digest")


def test_the_document_quotes_the_schemas_digest_pattern() -> None:
    pattern = SCHEMA["$defs"]["digest"]["pattern"]
    assert f"`{pattern}`" in DOC, "the document quotes a digest pattern the schema does not have"


def test_both_pic_digests_go_through_the_definition_the_document_names() -> None:
    pic = SCHEMA["properties"]["authorization"]["properties"]["pic"]["properties"]
    for field in PIC_FIELDS:
        assert pic[field] == {"$ref": "#/$defs/digest"}, f"{field} no longer uses $defs/digest"
    assert "`$defs/digest`" in DOC


@pytest.mark.parametrize("field", ["authorization.pic.intent_digest", "intent_digest"])
def test_the_document_quotes_the_refusal_the_bridge_raises(field: str) -> None:
    """The artifact-side name and the argument-side name, which differ and are both quoted."""
    with pytest.raises(intent_bridge.IntentBridgeError) as raised:
        intent_bridge._digest("a" * 64, field)
    assert f"`{raised.value}`" in DOC, f"the document does not quote {raised.value!r}"


@pytest.mark.parametrize("field", PIC_FIELDS)
def test_the_prefixed_form_the_document_tells_integrators_to_send_is_accepted(field: str) -> None:
    value = "sha256:" + "a" * 64
    assert intent_bridge._digest(value, f"authorization.pic.{field}") == value

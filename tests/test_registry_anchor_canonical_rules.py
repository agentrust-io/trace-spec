"""Tests for Registry Anchor Format v1 §1 canonical serialization rules (#536)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from agentrust_trace.sign import UnanchorableValue, anchor_bytes

REPO_ROOT = Path(__file__).resolve().parents[1]
_INCLUSION_SPEC = importlib.util.spec_from_file_location(
    "inclusion", REPO_ROOT / "conformance" / "src" / "trace_tests" / "inclusion.py"
)
assert _INCLUSION_SPEC is not None and _INCLUSION_SPEC.loader is not None
_INCLUSION_MODULE = importlib.util.module_from_spec(_INCLUSION_SPEC)
_INCLUSION_SPEC.loader.exec_module(_INCLUSION_MODULE)
InclusionError = _INCLUSION_MODULE.InclusionError
canonical_claim_bytes = _INCLUSION_MODULE.canonical_claim_bytes

SERIALIZERS = (anchor_bytes, canonical_claim_bytes)


@pytest.mark.parametrize("serialize", SERIALIZERS)
def test_rule_1_recursive_code_point_key_sorting(serialize) -> None:
    """Object keys are sorted lexicographically by Unicode code point, recursively."""
    # U+FFFD (65533) < U+10000 (65536) by code point, whereas in UTF-16 code units
    # U+10000 (\uD800\uDC00) precedes U+FFFD (\uFFFD).
    claim = {
        "z": {"b": 1, "a": 2},
        "\U00010000": "supplementary",
        "\ufffd": "bmp",
        "a": 0,
    }
    assert serialize(claim) == (
        b'{"a":0,"z":{"a":2,"b":1},"\\ufffd":"bmp","\\ud800\\udc00":"supplementary"}'
    )


@pytest.mark.parametrize("serialize", SERIALIZERS)
def test_rule_2_separators_and_rule_5_no_trailing_newline(serialize) -> None:
    """Separators are ',' and ':', with no whitespace and no trailing newline."""
    out = serialize({"b": [1, 2, 3], "a": {"k": "v"}})
    assert out == b'{"a":{"k":"v"},"b":[1,2,3]}'
    assert not out.endswith(b"\n")
    assert b" " not in out


@pytest.mark.parametrize("serialize", SERIALIZERS)
@pytest.mark.parametrize(
    ("char", "escaped"),
    [
        ('"', b'\\"'),
        ("\\", b"\\\\"),
        ("\b", b"\\b"),
        ("\t", b"\\t"),
        ("\n", b"\\n"),
        ("\f", b"\\f"),
        ("\r", b"\\r"),
        ("/", b"/"),
    ],
)
def test_rule_3_short_escapes_and_unescaped_slash(
    serialize, char: str, escaped: bytes
) -> None:
    """Mandatory two-character escapes and unescaped '/' (U+002F)."""
    assert serialize({"s": char}) == b'{"s":"' + escaped + b'"}'


@pytest.mark.parametrize("serialize", SERIALIZERS)
def test_rule_3_remaining_control_characters_use_lowercase_hex(serialize) -> None:
    """Control characters U+0000..U+001F other than \\b, \\t, \\n, \\f, \\r use \\u00xx."""
    short = {0x08, 0x09, 0x0A, 0x0C, 0x0D}
    for cp in range(0x20):
        if cp in short:
            continue
        expected = f'\\u{cp:04x}'.encode("ascii")
        assert serialize({"s": chr(cp)}) == b'{"s":"' + expected + b'"}'


@pytest.mark.parametrize("serialize", SERIALIZERS)
def test_rule_3_del_and_bmp_above_007f_use_lowercase_hex(
    serialize,
) -> None:
    """U+007F (DELETE) and U+0080..U+FFFF use lowercase \\uXXXX escapes."""
    for cp, hex_escape in [
        (0x007F, b"\\u007f"),
        (0x0080, b"\\u0080"),
        (0x00E9, b"\\u00e9"),
        (0x20AC, b"\\u20ac"),
        (0xFFFD, b"\\ufffd"),
        (0xFFFF, b"\\uffff"),
    ]:
        assert serialize({"s": chr(cp)}) == b'{"s":"' + hex_escape + b'"}'


@pytest.mark.parametrize("serialize", SERIALIZERS)
def test_rule_3_supplementary_plane_uses_lowercase_surrogate_pairs(serialize) -> None:
    """Supplementary-plane code points U+10000..U+10FFFF use lowercase surrogate pairs."""
    assert serialize({"s": "\U0001f600"}) == b'{"s":"\\ud83d\\ude00"}'
    assert serialize({"s": "\U00010000"}) == b'{"s":"\\ud800\\udc00"}'
    assert serialize({"s": "\U0010ffff"}) == b'{"s":"\\udbff\\udfff"}'


@pytest.mark.parametrize("serialize", SERIALIZERS)
def test_rule_3_escaping_applies_to_object_keys_as_well_as_values(serialize) -> None:
    """Object member names apply the same escaping rules as string values."""
    claim = {
        'a"b\\c/d\n\x00\x7f\u00e9\U0001f600': 1,
    }
    assert (
        serialize(claim)
        == b'{"a\\"b\\\\c/d\\n\\u0000\\u007f\\u00e9\\ud83d\\ude00":1}'
    )


def test_rule_4_integer_zero_is_written_without_minus_sign() -> None:
    """Guards the spec/registry-anchor-v1.md §1 text only (for languages with signed zero).

    In Python, the integer literal ``-0`` is already the ``int`` ``0`` before it
    reaches either serializer (and ``-0.0`` is a ``float``, which §1 excludes), so
    a runtime call like ``anchor_bytes({"z": -0})`` cannot fail on `-0` handling.
    This test therefore guards only that §1 explicitly states the ``0`` (never ``-0``)
    rule for implementations in languages whose number representation has a signed zero.
    """
    doc = (REPO_ROOT / "spec" / "registry-anchor-v1.md").read_text(encoding="utf-8")
    section_1 = doc.split("## 1. Canonical claim bytes")[1].split("## 2. Leaf hash")[0]
    assert "- Integer zero is written `0` (never `-0`)." in section_1


@pytest.mark.parametrize("bad_str", ["\ud800", "\udbff", "\udc00", "\udfff", "a\ud800b"])
def test_unpaired_surrogates_in_values_and_keys_are_rejected(bad_str: str) -> None:
    """Unpaired UTF-16 surrogates (U+D800..U+DFFF) are rejected as outside the profile."""
    for claim in (
        {"s": bad_str},
        {"nested": [bad_str]},
        {bad_str: 1},
        {"nested": {bad_str: 1}},
    ):
        with pytest.raises(UnanchorableValue, match="surrogate"):
            anchor_bytes(claim)
        with pytest.raises(InclusionError, match="surrogate"):
            canonical_claim_bytes(claim)


def test_registry_anchor_spec_documents_all_five_canonical_rules() -> None:
    """spec/registry-anchor-v1.md §1 states all five language-independent rules."""
    doc = (REPO_ROOT / "spec" / "registry-anchor-v1.md").read_text(encoding="utf-8")
    section_1 = doc.split("## 1. Canonical claim bytes")[1].split("## 2. Leaf hash")[0]

    for required_fragment in (
        "Object keys sorted lexicographically by Unicode code point, recursively",
        'Separators `","` and `":"`, no whitespace.',
        r'`\"`, `\\`, `\b`, `\t`, `\n`, `\f`, and `\r`',
        "`/` (`U+002F`) is not escaped",
        "(`U+0000` to `U+001F`)",
        (
            "in `U+007F` to `U+D7FF` and `U+E000` to `U+FFFF` (including `U+007F`, "
            "which is escaped as `\\u007f`) use lowercase four-hex-digit `\\uXXXX` escapes"
        ),
        (
            "(`U+10000` to `U+10FFFF`) use lowercase UTF-16 surrogate pairs "
            "(a high surrogate in `U+D800` to `U+DBFF` followed by a low surrogate in "
            "`U+DC00` to `U+DFFF`, e.g. `\\ud8xx\\udcxx`)"
        ),
        "Integer zero is written `0` (never `-0`).",
        "No trailing newline.",
        "unpaired UTF-16 surrogate (`U+D800` to `U+DFFF`)",
    ):
        assert required_fragment in section_1, (
            f"spec/registry-anchor-v1.md §1 is missing {required_fragment!r}"
        )


def test_verifier_compatibility_readme_and_acta_crosswalk_findings_closed() -> None:
    """#448 items 3 and 16 remain closed in the documentation."""
    readme = (
        REPO_ROOT / "examples" / "verifier-compatibility" / "README.md"
    ).read_text(encoding="utf-8")
    assert "No normative text for them has been accepted" not in readme
    assert "Nothing in `docs/verification.md` currently" not in readme
    assert "`spec/trace-v0.2.md` §3.3" in readme
    assert "`docs/verification.md`" in readme

    acta = (
        REPO_ROOT / "docs" / "crosswalks" / "acta-decision-receipts.md"
    ).read_text(encoding="utf-8")
    assert "3.3.2" not in acta
    assert "3.3.3" in acta

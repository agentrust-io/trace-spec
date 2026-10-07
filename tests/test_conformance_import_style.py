"""Imported Unicode bytes retain their meaning; future edits still face house style."""

import hashlib
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "house_style", Path(__file__).resolve().parents[1] / "tools" / "check_dashes.py"
)
assert SPEC is not None and SPEC.loader is not None
style = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(style)


def test_import_exemption_requires_exact_original_bytes(tmp_path):
    source = tmp_path / "conformance" / "tests" / "vector.json"
    source.parent.mkdir(parents=True)
    original = json.dumps({"unicode": chr(0x2014)}, ensure_ascii=False).encode()
    source.write_bytes(original)
    digest = hashlib.sha1(f"blob {len(original)}\0".encode() + original).hexdigest()
    (tmp_path / "conformance" / "import-manifest.json").write_text(
        json.dumps({"files": {"tests/vector.json": digest}}), encoding="utf-8"
    )
    assert list(style.findings(tmp_path)) == []

    source.write_bytes(original + b"\n")
    assert [row[0] for row in style.findings(tmp_path)] == ["conformance/tests/vector.json"]


def test_new_conformance_file_has_no_import_exemption(tmp_path):
    source = tmp_path / "conformance" / "new.py"
    source.parent.mkdir()
    source.write_text("# " + chr(0x2014), encoding="utf-8")
    assert [row[0] for row in style.findings(tmp_path)] == ["conformance/new.py"]

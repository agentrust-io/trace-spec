"""Runs the independent JavaScript verifier over every verifier-token vector.

The verifier in tools/independent-verifier/ is a clean-room implementation
that never reads the Python prototype. Agreement with each vector's expected
outcome is the interoperability evidence; a disagreement fails the test.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "independent-verifier" / "verify.mjs"
LEGACY = sorted((ROOT / "examples" / "verifier-token-profile").glob("[0-9]*.json"))
CONFORMANCE = sorted((ROOT / "examples" / "verifier-token-conformance" / "vectors").glob("*.json"))
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def _run(paths: list[Path]) -> dict[str, dict]:
    proc = subprocess.run(
        [NODE, str(CLI), *map(str, paths)],
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == len(paths)
    return {str(p): out for p, out in zip(paths, lines, strict=True)}


@pytest.fixture(scope="module")
def results() -> dict[str, dict]:
    paths = LEGACY + CONFORMANCE
    return _run(paths) if paths else {}


def _expected(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    expected = data["expected"]
    if isinstance(expected, str):  # legacy format: token outcome only
        return {"token": expected}
    return {
        "token": expected["token"],
        "composite_status": expected.get("composite_status"),
        "proof": expected.get("proof"),
    }


@pytest.mark.parametrize("path", LEGACY + CONFORMANCE, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_vector_agrees(path: Path, results: dict[str, dict]) -> None:
    got = results[str(path)]
    expected = _expected(path)
    actual = {key: got[key] for key in expected}
    assert actual == expected, f"{path.name}: independent verifier {actual}, vector {expected}"


def test_corpus_present() -> None:
    assert LEGACY, "legacy vectors missing"

"""Run the first-record tutorial in two processes with its retained verifier key."""
from pathlib import Path
import re
import subprocess
import sys


def test_first_record_tutorial(tmp_path):
    page = Path(__file__).resolve().parents[1] / "docs/quickstart.md"
    blocks = re.findall(r"^```python\n(.*?)^```", page.read_text(), re.M | re.S)
    assert len(blocks) == 2
    first = subprocess.run(
        [sys.executable, "-c", blocks[0]], cwd=tmp_path, text=True, capture_output=True
    )
    assert first.returncode == 0, first.stdout + first.stderr
    assert "PASS: changed record rejected" in first.stdout
    assert (tmp_path / "session.trace.json").is_file()
    assert (tmp_path / "issuer-public.pem").is_file()
    second = subprocess.run(
        [sys.executable, "-c", blocks[1]], cwd=tmp_path, text=True, capture_output=True
    )
    assert second.returncode == 0, second.stdout + second.stderr
    assert "PASS: saved record verified against the retained public key" in second.stdout

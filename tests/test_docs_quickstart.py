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

    verify_page = page.parent / "tutorials/verifying-a-trust-record.md"
    verify_blocks = re.findall(
        r"^```python\n(.*?)^```", verify_page.read_text(encoding="utf-8-sig"), re.M | re.S
    )
    assert len(verify_blocks) == 2
    received = subprocess.run(
        [sys.executable, "-c", "\n".join(verify_blocks)],
        cwd=tmp_path, text=True, capture_output=True,
    )
    assert received.returncode == 0, received.stdout + received.stderr
    assert "no revocation check performed" in received.stdout
    assert "edited record rejected" in received.stdout


def test_agt_adapter_tutorial(tmp_path):
    page = Path(__file__).resolve().parents[1] / "docs/tutorials/agt-adapter.md"
    blocks = re.findall(r"^```python\n(.*?)^```", page.read_text(encoding="utf-8-sig"), re.M | re.S)
    assert len(blocks) == 1
    result = subprocess.run(
        [sys.executable, "-c", blocks[0]], cwd=tmp_path, text=True, capture_output=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: mapped and signed synthetic session" in result.stdout

    transcript_page = page.with_name("verifying-the-audit-chain.md")
    transcript_blocks = re.findall(
        r"^```python\n(.*?)^```", transcript_page.read_text(encoding="utf-8-sig"), re.M | re.S
    )
    assert len(transcript_blocks) == 1
    transcript = subprocess.run(
        [sys.executable, "-c", blocks[0] + "\n" + transcript_blocks[0]],
        cwd=tmp_path, text=True, capture_output=True,
    )
    assert transcript.returncode == 0, transcript.stdout + transcript.stderr
    assert "PASS: transcript matches the signed commitment" in transcript.stdout
    assert "PASS: changed transcript rejected" in transcript.stdout

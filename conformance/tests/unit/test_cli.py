"""End-to-end CLI tests for fail-closed behavior."""

import json
import pathlib
import time

import click
import pytest
from click.testing import CliRunner

from trace_tests.cli import main

VECTORS_DIR = pathlib.Path(__file__).parent.parent / "vectors"


@pytest.fixture
def fresh_level0_path(tmp_path):
    vector = json.loads((VECTORS_DIR / "valid_level0.json").read_text())
    vector["iat"] = int(time.time()) - 60
    p = tmp_path / "record.json"
    p.write_text(json.dumps(vector))
    return str(p)


def test_unsigned_record_fails_level_2(fresh_level0_path):
    """Regression: unsigned plain JSON must never pass `verify --level 2`."""
    result = CliRunner().invoke(main, ["verify", "--record", fresh_level0_path, "--level", "2"])
    assert result.exit_code == 1, result.output
    assert "Result: FAIL" in result.output


def test_unsigned_record_fails_level_1(fresh_level0_path):
    result = CliRunner().invoke(main, ["verify", "--record", fresh_level0_path, "--level", "1"])
    assert result.exit_code == 1, result.output


def test_level_1_requires_verifier_nonce(fresh_level0_path):
    result = CliRunner().invoke(main, ["verify", "--record", fresh_level0_path, "--level", "1"])
    assert result.exit_code == 1, result.output
    assert "requires the verifier's expected nonce" in result.output


def test_unsigned_record_level_0_reports_unverified(fresh_level0_path):
    result = CliRunner().invoke(main, ["verify", "--record", fresh_level0_path, "--level", "0"])
    assert result.exit_code == 0, result.output
    assert "UNVERIFIED" in result.output
    # The summary no longer says "cryptographically": under per-code
    # registration a policy bundle that did not resolve is unverified too, and
    # a line naming only signatures would be a published claim the code stopped
    # making the moment TR-POL-003 existed.
    assert "could not be executed against the evidence this record cites" in result.output


def test_stale_record_fails(tmp_path):
    vector = json.loads((VECTORS_DIR / "valid_level0.json").read_text())
    vector["iat"] = int(time.time()) - (25 * 3600)
    p = tmp_path / "stale.json"
    p.write_text(json.dumps(vector))
    result = CliRunner().invoke(main, ["verify", "--record", str(p), "--level", "0"])
    assert result.exit_code == 1, result.output


def test_partial_cmcp_envelope_is_rejected(tmp_path):
    vector = json.loads((VECTORS_DIR / "valid_cmcp_runtime.json").read_text())
    del vector["cmcp_version"]
    p = tmp_path / "partial.json"
    p.write_text(json.dumps(vector))
    result = CliRunner().invoke(main, ["verify", "--record", str(p), "--level", "0"])
    assert result.exit_code == 2, result.output
    assert "partial cmcp-runtime envelope" in result.output


def test_version_matches_distribution_metadata():
    """`--version` must report the installed distribution version.

    `__version__` was a second hardcoded literal alongside `pyproject.toml` and
    fell behind through two releases, so a 0.4.0 install reported 0.2.0. Since
    the v0.2 profile cutover shipped in 0.4.0, `--version` was the one command
    that could not tell you whether your suite accepts v0.2 records.
    """
    from importlib.metadata import version

    expected = version("agentrust-trace-tests")
    result = CliRunner().invoke(main, ["--version"])

    assert result.exit_code == 0, result.output
    assert expected in result.output, f"expected {expected!r} in {result.output!r}"


def test_dunder_version_is_not_a_stale_literal():
    """Guard against reverting to a hardcoded `__version__`."""
    from importlib.metadata import version

    import trace_tests

    assert trace_tests.__version__ == version("agentrust-trace-tests")


def _iter_commands(cmd: click.Command) -> list[click.Command]:
    yielded = [cmd]
    if isinstance(cmd, click.Group):
        for subcmd in cmd.commands.values():
            yielded.extend(_iter_commands(subcmd))
    return yielded


def test_all_options_have_help():
    """Every Click command option must have non-empty help text."""
    missing = []
    for cmd in _iter_commands(main):
        for param in cmd.params:
            if isinstance(param, click.Option) and not (param.help and param.help.strip()):
                missing.append((cmd.name, param.opts))
    assert not missing, f"Options missing help text: {missing}"


def test_report_help_describes_max_age():
    """`report --help` must describe `--max-age`."""
    result = CliRunner().invoke(main, ["report", "--help"])
    assert result.exit_code == 0
    assert "--max-age" in result.output
    assert "Maximum allowed record age in seconds" in result.output

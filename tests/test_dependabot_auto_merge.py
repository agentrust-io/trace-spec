"""Exercise the workflow's real shell gate without contacting GitHub."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/dependabot-auto-merge.yml"


@pytest.mark.parametrize(
    ("metadata", "allowed"),
    [
        ([{"updateType": "version-update:semver-patch"}], True),
        ([{"updateType": "version-update:semver-minor"}], True),
        ([{"updateType": "version-update:semver-major"}], False),
        (
            [
                {"updateType": "version-update:semver-minor"},
                {"updateType": "version-update:semver-patch"},
            ],
            True,
        ),
        (
            [
                {"updateType": "version-update:semver-patch"},
                {"updateType": "version-update:semver-major"},
            ],
            False,
        ),
        ([{"updateType": "version-update:semver-patch"}, {}], False),
        ([{"updateType": None}], False),
        ([{"updateType": "unknown"}], False),
        ([{"updateType": "version-update:semver-patch"}, "unknown"], False),
        ([], False),
        ({"updateType": "version-update:semver-patch"}, False),
        (None, False),
        ("not metadata", False),
    ],
)
def test_only_fully_classified_minor_patch_groups_queue(
    tmp_path: Path, metadata: object, allowed: bool
) -> None:
    _run_gate(tmp_path, json.dumps(metadata), allowed)


def test_malformed_metadata_never_queues(tmp_path: Path) -> None:
    _run_gate(tmp_path, "{invalid", False)


def _run_gate(tmp_path: Path, metadata: str, allowed: bool) -> None:
    if sys.platform != "linux":
        pytest.skip("Bash/jq execution matches the workflow's Ubuntu runner")
    # Extract this workflow's literal script without adding a YAML dependency
    # to the reference library's development environment.
    block = re.search(r"^        run: \|\n((?:          [^\n]*\n)+)", WORKFLOW.read_text(), re.M)
    assert block is not None, "auto-merge must retain its literal Bash block"
    script = textwrap.dedent(block[1])
    gh = tmp_path / "gh"
    output = tmp_path / "gh-args"
    gh.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$AUDIT_GH_ARGS"\n')
    gh.chmod(0o755)
    head = "a" * 40
    url = "https://github.com/example/repo/pull/1"
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "AUDIT_GH_ARGS": str(output),
        "UPDATED_DEPENDENCIES": metadata,
        "PR_HEAD_SHA": head,
        "PR_URL": url,
        "GH_TOKEN": "unused-local-test-token",
    }
    subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert output.exists() is allowed
    if allowed:
        assert output.read_text().splitlines() == [
            "pr",
            "merge",
            "--auto",
            "--squash",
            "--match-head-commit",
            head,
            url,
        ]


def test_workflow_keeps_event_and_permission_boundaries() -> None:
    source = WORKFLOW.read_text()
    assert re.search(
        r"^on:\n  pull_request:\n    types: \[opened, reopened, synchronize\]\n"
        r"    branches: \[main\]\n\npermissions:",
        source,
        re.M,
    )
    assert "user.login == 'dependabot[bot]'" in source
    assert "head.repo.full_name == github.repository" in source
    assert "permissions:\n  contents: read\n" in source
    assert "    permissions:\n      contents: write\n      pull-requests: write\n" in source
    assert re.search(r"uses: dependabot/fetch-metadata@[0-9a-f]{40} #", source)
    assert "skip-verification" not in source
    assert "skip-commit-verification" not in source
    assert "checkout@" not in source

"""Workflow OIDC authority stays within the four reviewed publishing allowances."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

# Reviewed under agentrust-io/.github#54; TestPyPI remains explicitly opt-in.
OIDC_JOBS = {
    ("publish.yml", "publish"),  # Main SDK trusted publishing
    ("conformance-publish.yml", "pypi"),  # Conformance trusted publishing
    ("conformance-publish.yml", "testpypi"),  # Reviewed opt-in TestPyPI
    ("scorecard.yml", "scorecard"),  # Scorecard
}


def _oidc_write(permissions: dict | str) -> bool:
    if isinstance(permissions, str):
        assert permissions in {"read-all", "write-all"}, "unsupported permission shorthand"
        return permissions == "write-all"
    assert isinstance(permissions, dict), "permissions must be a mapping or shorthand"
    return permissions.get("id-token") == "write"


def _assert_oidc_jobs(directory: Path) -> None:
    grants = set()
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    assert paths, "no workflow files found"
    for path in paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        defaults = workflow.get("permissions", {})
        assert not _oidc_write(defaults), f"{path.name}: workflow-wide OIDC grant"
        for name, job in workflow["jobs"].items():
            permissions = job.get("permissions", defaults)
            assert permissions != "write-all", f"{path.name}/{name}: write-all grant"
            if _oidc_write(permissions):
                grants.add((path.name, name))
    assert grants == OIDC_JOBS, f"OIDC job drift: {grants ^ OIDC_JOBS}"


def test_workflow_oidc_grants() -> None:
    _assert_oidc_jobs(Path(".github/workflows"))


@pytest.mark.parametrize(
    "case",
    [
        "validation-job", "sbom-job", "workflow-inheritance", "workflow-write-all",
        "allowed-job-write-all", "other-job-write-all", "new-yml", "new-yaml",
        "removed-allowance",
    ],
)
def test_oidc_guard_detects_permission_drift(tmp_path: Path, case: str) -> None:
    directory = tmp_path / "workflows"
    shutil.copytree(".github/workflows", directory)
    _assert_oidc_jobs(directory)
    if case in {"new-yml", "new-yaml"}:
        extension = case.removeprefix("new-")
        (directory / f"unexpected.{extension}").write_text(
            "permissions: {contents: read}\njobs:\n"
            "  validation:\n    permissions: {id-token: write}\n",
            encoding="utf-8",
        )
    else:
        filename = "sbom.yml" if case == "sbom-job" else "ci.yml"
        if case in {"allowed-job-write-all", "removed-allowance"}:
            filename = "publish.yml"
        path = directory / filename
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        job_name = "sbom" if case == "sbom-job" else "test"
        if case in {"allowed-job-write-all", "removed-allowance"}:
            job_name = "publish"
        job = workflow["jobs"][job_name]
        if case == "workflow-inheritance":
            workflow["permissions"]["id-token"] = "write"
            job.pop("permissions", None)
        elif case == "workflow-write-all":
            workflow["permissions"] = "write-all"
        elif case in {"allowed-job-write-all", "other-job-write-all"}:
            job["permissions"] = "write-all"
        elif case == "removed-allowance":
            job["permissions"].pop("id-token")
        else:
            job.setdefault("permissions", {})["id-token"] = "write"
        path.write_text(yaml.safe_dump(workflow), encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_oidc_jobs(directory)


def test_oidc_guard_accepts_read_only_inheritance(tmp_path: Path) -> None:
    directory = tmp_path / "workflows"
    shutil.copytree(".github/workflows", directory)
    (directory / "read-only.yaml").write_text(
        "permissions: read-all\njobs:\n  validation:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    _assert_oidc_jobs(directory)



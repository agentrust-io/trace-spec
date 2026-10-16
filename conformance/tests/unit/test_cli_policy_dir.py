"""--policy-dir: the manifest's shape-check, and what it deliberately does not check."""

from __future__ import annotations

import hashlib
import json
import pathlib
import time

import pytest
from click.testing import CliRunner

from trace_tests.cli import _is_unsafe_relative, main

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "vectors"
BUNDLE = b'{"policy_id":"appraisal/agent-v1","version":"1.0.0"}\n'
URI = "https://policy.example.org/bundles/policy-bundle-base.json"


def _record(tmp_path, **policy):
    rec = json.loads((VECTORS / "valid_level0.json").read_text(encoding="utf-8"))
    rec["iat"] = int(time.time())
    rec["policy"].update(policy)
    p = tmp_path / "record.json"
    p.write_text(json.dumps(rec), encoding="utf-8")
    return str(p)


def _policy_dir(tmp_path, manifest, *, write_bundle=True):
    d = tmp_path / "policies"
    d.mkdir(exist_ok=True)
    if write_bundle:
        (d / "policy-bundle-base.json").write_bytes(BUNDLE)
    (d / "resolutions.json").write_text(json.dumps(manifest), encoding="utf-8")
    return str(d)


def _run(record, policy_dir=None, level="0"):
    args = ["verify", "--record", record, "--level", level, "--max-age", "3153600000"]
    if policy_dir is not None:
        args += ["--policy-dir", policy_dir]
    return CliRunner().invoke(main, args)


def test_a_resolvable_bundle_passes_tr_pol_003(tmp_path):
    digest = "sha256:" + hashlib.sha256(BUNDLE).hexdigest()
    rec = _record(tmp_path, policy_uri=URI, bundle_hash=digest)
    d = _policy_dir(tmp_path, {URI: "policy-bundle-base.json"})
    result = _run(rec, d)
    assert "TR-POL-003" not in result.output or "PASS" in result.output
    assert result.exit_code == 0, result.output


def test_a_uri_the_manifest_does_not_hold_is_unverified(tmp_path):
    digest = "sha256:" + hashlib.sha256(BUNDLE).hexdigest()
    rec = _record(tmp_path, policy_uri=URI, bundle_hash=digest)
    d = _policy_dir(
        tmp_path,
        {"https://policy.example.org/bundles/other.json": "policy-bundle-base.json"},
    )
    result = _run(rec, d)
    assert "UNVERIFIED" in result.output
    assert "KeyError" in result.output


def test_a_mapped_file_that_is_not_there_is_unverified_not_a_load_error(tmp_path):
    """The manifest loads; the missing bundle surfaces per record, as weather.

    Refusing the whole manifest because one bundle had gone missing would be
    the manifest-level version of treating a lost referent as a wrong
    reference, and it would make every other record in the run unreadable too.
    """
    digest = "sha256:" + hashlib.sha256(BUNDLE).hexdigest()
    rec = _record(tmp_path, policy_uri=URI, bundle_hash=digest)
    d = _policy_dir(tmp_path, {URI: "policy-bundle-gone.json"})
    result = _run(rec, d)
    assert result.exit_code != 2, "a missing bundle must not be a manifest load error"
    assert "UNVERIFIED" in result.output
    assert "FileNotFoundError" in result.output or "Errno 2" in result.output


def test_a_missing_manifest_exits_2(tmp_path):
    rec = _record(tmp_path)
    result = _run(rec, str(tmp_path / "nowhere"))
    assert result.exit_code == 2
    assert "cannot read policy manifest" in result.output


def test_a_manifest_that_is_not_json_exits_2(tmp_path):
    rec = _record(tmp_path)
    d = tmp_path / "policies"
    d.mkdir()
    (d / "resolutions.json").write_text("{not json", encoding="utf-8")
    result = _run(rec, str(d))
    assert result.exit_code == 2
    assert "is not valid JSON" in result.output


def test_a_manifest_that_is_not_an_object_exits_2(tmp_path):
    rec = _record(tmp_path)
    d = _policy_dir(tmp_path, ["a", "list"])
    result = _run(rec, d)
    assert result.exit_code == 2
    assert "must be a JSON object" in result.output


def test_a_manifest_value_that_is_not_a_string_exits_2(tmp_path):
    rec = _record(tmp_path)
    d = _policy_dir(tmp_path, {URI: 7})
    result = _run(rec, d)
    assert result.exit_code == 2
    assert "expected a relative path string" in result.output


@pytest.mark.parametrize(
    "bad", ["/etc/passwd", "../outside.json", "a/../../outside.json", "C:/Windows/x.json", ""]
)
def test_a_manifest_entry_escaping_the_directory_exits_2(tmp_path, bad):
    rec = _record(tmp_path)
    d = _policy_dir(tmp_path, {URI: bad})
    result = _run(rec, d)
    assert result.exit_code == 2
    assert "must be relative paths inside the directory" in result.output


@pytest.mark.parametrize("ok", ["a.json", "sub/a.json", "./a.json"])
def test_ordinary_relative_paths_are_accepted(ok):
    assert _is_unsafe_relative(ok) is False


def test_without_policy_dir_the_check_skips_rather_than_failing(tmp_path):
    digest = "sha256:" + hashlib.sha256(BUNDLE).hexdigest()
    rec = _record(tmp_path, policy_uri=URI, bundle_hash=digest)
    result = _run(rec)
    assert result.exit_code == 0, result.output
    assert "no resolver supplied" in result.output

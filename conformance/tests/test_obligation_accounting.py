"""Semantic contract tests for the bounded three-obligation accounting seam."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner

from trace_tests import accounting, report, runner
from trace_tests.cli import main
from trace_tests.modules import tr_apr, tr_env, tr_pol, tr_sca, unverified
from trace_tests.result import Finding, Status

MAX_AGE = 10**9
REPO = Path(__file__).resolve().parents[1]
BUNDLE = b"policy bundle"
DIGEST = "sha256:" + hashlib.sha256(BUNDLE).hexdigest()
A = accounting.Applicability.APPLICABLE
NA = accounting.Applicability.NOT_APPLICABLE
C = accounting.EvaluationState.COMPLETED
U = accounting.EvaluationState.ATTEMPTED_UNRESOLVED
B = accounting.EvaluationState.BLOCKED_BY_PREREQUISITE
N = accounting.EvaluationState.NOT_ATTEMPTED

# key, level, branch, applicability, state, prerequisite, finding status, contribution
BRANCH_CASES = (
    ("TR-APR-001", 0, "appraisal_missing", A, C, None, Status.FAIL, True),
    ("TR-APR-001", 0, "appraisal_not_object", A, C, None, Status.FAIL, True),
    ("TR-APR-001", 0, "status_valid", A, C, None, Status.PASS, False),
    ("TR-APR-001", 0, "status_invalid", A, C, None, Status.FAIL, True),
    ("TR-POL-003", 0, "policy_missing", A, B, "TR-POL-001", None, None),
    ("TR-POL-003", 0, "policy_not_object", A, B, "TR-POL-001", None, None),
    ("TR-POL-003", 0, "policy_uri_absent", NA, C, None, Status.SKIP, False),
    ("TR-POL-003", 0, "policy_uri_explicit_null", NA, C, None, Status.SKIP, False),
    ("TR-POL-003", 0, "policy_uri_non_string", A, C, None, Status.FAIL, True),
    ("TR-POL-003", 0, "policy_uri_malformed", A, C, None, Status.FAIL, True),
    ("TR-POL-003", 0, "bundle_hash_malformed", A, B, "TR-POL-001", Status.SKIP, False),
    ("TR-POL-003", 0, "no_resolver", A, N, None, Status.SKIP, False),
    ("TR-POL-003", 0, "resolver_exception", A, U, None, Status.UNVERIFIED, False),
    ("TR-POL-003", 0, "resolver_non_bytes", A, U, None, Status.UNVERIFIED, False),
    ("TR-POL-003", 0, "resolved_match", A, C, None, Status.PASS, False),
    ("TR-POL-003", 0, "resolved_mismatch", A, C, None, Status.FAIL, True),
    ("TR-SCA-002", 1, "build_provenance_missing", A, B, "TR-SCA-001", None, None),
    ("TR-SCA-002", 1, "build_provenance_not_object", A, B, "TR-SCA-001", None, None),
    ("TR-SCA-002", 1, "digest_valid", A, C, None, Status.PASS, False),
    ("TR-SCA-002", 1, "digest_invalid", A, C, None, Status.FAIL, True),
    ("TR-SCA-002", 0, "level0_scheduler_nonexecution", A, N, None, None, None),
)

OWNERS = {
    "TR-APR-001": "TR-APR",
    "TR-POL-003": "TR-POL",
    "TR-SCA-002": "TR-SCA",
}
PREREQUISITE_PREFIXES = {
    "policy_missing": "TR-POL-001: policy field is missing",
    "policy_not_object": "TR-POL-001: policy field is missing",
    "bundle_hash_malformed": "TR-POL-001: policy.bundle_hash must match ",
    "build_provenance_missing": "TR-SCA-001: build_provenance is required",
    "build_provenance_not_object": (
        "TR-SCA-001: build_provenance must be an object"
    ),
}
FRAGMENTS = {
    "TR-APR-001": (
        "/required/8",
        "/properties/appraisal/type",
        "/properties/appraisal/required/0",
        "/properties/appraisal/properties/status/enum",
    ),
    "TR-POL-003": (
        "/required/5",
        "/properties/policy/type",
        "/properties/policy/required",
        "/properties/policy/properties/bundle_hash/pattern",
        "/properties/policy/properties/policy_uri",
    ),
    "TR-SCA-002": (
        "/required/7",
        "/properties/build_provenance/type",
        "/properties/build_provenance/required/1",
        "/properties/build_provenance/properties/digest/pattern",
    ),
}
LOCATOR_VALUE_SHA256 = {
    "/required/8": ("sha256:a7fe3dfe02e11f3334cdaeb057718697d00825596549db11c3510d84f0d928e1"),
    "/properties/appraisal/type": (
        "sha256:626992da9517ee49930ee1340383a0cc334563d9aa429619a17842d0eeecb524"
    ),
    "/properties/appraisal/required/0": (
        "sha256:cfc31bcc34ed7f4cc7895026ae8a54f0494f73757e9f914d0f6ed90f9bc34f51"
    ),
    "/properties/appraisal/properties/status/enum": (
        "sha256:1150b2eb1c222f1b6d183a1e60848fee1542c3d287afb649996a9bdfdcf086b1"
    ),
    "/required/5": ("sha256:17ad92e63c962393c0329c658937d16eccaea13036412a3d1d0a5b6b8f29d738"),
    "/properties/policy/type": (
        "sha256:626992da9517ee49930ee1340383a0cc334563d9aa429619a17842d0eeecb524"
    ),
    "/properties/policy/required": (
        "sha256:2ea88ea65da4e90d9b33a9ed9150a62ff25085c4378d6d7480f419014ed4ec90"
    ),
    "/properties/policy/properties/bundle_hash/pattern": (
        "sha256:f1109a5bb3b1215602b0209949c8d080aeddfbfcec346132facba03f38528af5"
    ),
    "/properties/policy/properties/policy_uri": (
        "sha256:70bbbdd4920e8ea88e0c02016ecb61e6cce41d01601ae7c7b3c6ce5f63986509"
    ),
    "/required/7": ("sha256:e131727bb1bf583b7afc0a1850aa491d3ec4d251c42c381e4b42e05c1bc5d389"),
    "/properties/build_provenance/type": (
        "sha256:626992da9517ee49930ee1340383a0cc334563d9aa429619a17842d0eeecb524"
    ),
    "/properties/build_provenance/required/1": (
        "sha256:2c41adee85872a98b2515461f36e31bfe1da7029bbe4375742be2f794862ef36"
    ),
    "/properties/build_provenance/properties/digest/pattern": (
        "sha256:f1109a5bb3b1215602b0209949c8d080aeddfbfcec346132facba03f38528af5"
    ),
}
SCHEDULES = (
    ("TR-ENV", "TR-SIG", "TR-POL", "TR-APR"),
    ("TR-ENV", "TR-SIG", "TR-POL", "TR-APR", "TR-RTE", "TR-SCA"),
    ("TR-ENV", "TR-SIG", "TR-POL", "TR-APR", "TR-RTE", "TR-SCA", "TR-TXN", "TR-ANC"),
)
CANONICALIZATION_VECTORS = sorted((REPO / "tests/vectors/canonicalization").glob("*.json"))


def _execute(
    record: dict[str, Any],
    levels: tuple[int, ...] = (0, 1, 2),
    resolver: Callable[[str], bytes] | None = None,
) -> accounting._Execution:
    return runner._run_levels(
        record, "trace", levels, max_age_seconds=MAX_AGE, policy_resolver=resolver
    )


def _row(execution: accounting._Execution, level: int, key: str) -> accounting.AccountingRow:
    return next(
        row for row in execution.rows if (row.attempted_level, row.obligation_key) == (level, key)
    )


def _assert_public_and_report_compatibility(
    record: dict[str, Any],
    levels: tuple[int, ...] = (0, 1, 2),
    resolver: Callable[[str], bytes] | None = None,
) -> accounting._Execution:
    execution = _execute(copy.deepcopy(record), levels, resolver)
    assert execution.compatibility_results == {
        level: runner.run(
            copy.deepcopy(record),
            "trace",
            level,
            max_age_seconds=MAX_AGE,
            policy_resolver=resolver,
        )
        for level in levels
    }
    common = {
        "record": record,
        "record_path": "record.json",
        "record_format": "trace",
        "suite_version": "0.5.1",
        "library_version": None,
        "generated_at": "2026-08-31 12:00 UTC",
    }
    legacy = report.build(results_by_level=execution.compatibility_results, **common)
    accounted = report._build_from_execution(
        execution=execution,
        **{key: value for key, value in common.items() if key != "record_format"},
    )
    legacy_json = json.loads(report.to_json(legacy))
    accounted_json = json.loads(report.to_json(accounted))
    assert set(accounted_json) - set(legacy_json) == {"obligation_accounting"}
    accounted_json.pop("obligation_accounting")
    assert accounted_json == legacy_json
    assert report.to_html(accounted) == report.to_html(legacy)
    assert report.badge_svg(accounted) == report.badge_svg(legacy)
    return execution


def _branch_input(
    valid: dict[str, Any], branch: str
) -> tuple[dict[str, Any], Callable[[str], bytes] | None]:
    record = copy.deepcopy(valid)
    if branch == "appraisal_missing":
        record.pop("appraisal")
    elif branch == "appraisal_not_object":
        record["appraisal"] = []
    elif branch == "status_invalid":
        record["appraisal"]["status"] = "wrong"
    elif branch == "policy_missing":
        record.pop("policy")
    elif branch == "policy_not_object":
        record["policy"] = []
    elif branch == "policy_uri_explicit_null":
        record["policy"]["policy_uri"] = None
    elif branch == "policy_uri_non_string":
        record["policy"]["policy_uri"] = []
    elif branch == "policy_uri_malformed":
        record["policy"]["policy_uri"] = "relative"
    elif branch == "bundle_hash_malformed":
        record["policy"].update(policy_uri="https://p.example/x", bundle_hash="bad")
    elif branch in {
        "no_resolver",
        "resolver_exception",
        "resolver_non_bytes",
        "resolved_match",
        "resolved_mismatch",
    }:
        record["policy"].update(policy_uri="https://p.example/x", bundle_hash=DIGEST)
    elif branch == "build_provenance_missing":
        record.pop("build_provenance")
    elif branch == "build_provenance_not_object":
        record["build_provenance"] = []
    elif branch == "digest_invalid":
        record["build_provenance"]["digest"] = "bad"

    if branch == "resolver_exception":
        return record, lambda _uri: (_ for _ in ()).throw(OSError("offline"))
    if branch == "resolver_non_bytes":
        return record, lambda _uri: "wrong"  # type: ignore[return-value]
    if branch == "resolved_match":
        return record, lambda _uri: BUNDLE
    if branch == "resolved_mismatch":
        return record, lambda _uri: b"other"
    return record, None


def _role(branch: str) -> str:
    if branch in {
        "policy_missing",
        "policy_not_object",
        "bundle_hash_malformed",
        "build_provenance_missing",
        "build_provenance_not_object",
    }:
        return "prerequisite"
    return {
        "policy_uri_absent": "not_applicable",
        "policy_uri_explicit_null": "not_applicable",
        "no_resolver": "not_attempted",
        "resolver_exception": "target_attempted_unresolved",
        "resolver_non_bytes": "target_attempted_unresolved",
        "level0_scheduler_nonexecution": "scheduler_nonexecution_applicable",
    }.get(branch, "target_completed")


def test_complete_matrix_atomic_views_and_public_report_wire(
    valid_level0: dict[str, Any],
) -> None:
    for width in (1, 2, 3):
        levels = tuple(range(width))
        execution = _execute(valid_level0, levels)
        document = accounting._accounting_document(execution)
        rows = document["rows"]
        assert set(document) == {"registry", "accounting_complete", "rows"}
        assert document["accounting_complete"] is True
        assert isinstance(rows, list) and len(rows) == width * 3
        assert [(row["attempted_level"], row["suite_obligation_key"]) for row in rows] == [
            (level, key)
            for level in levels
            for key in ("TR-APR-001", "TR-POL-003", "TR-SCA-002")
        ]
        assert execution.compatibility_results == {
            level: runner.run(
                copy.deepcopy(valid_level0), "trace", level, max_age_seconds=MAX_AGE
            )
            for level in levels
        }
        assert [tuple(execution.compatibility_results[level]) for level in levels] == list(
            SCHEDULES[:width]
        )

    execution = _execute(valid_level0)
    rows = accounting._accounting_document(execution)["rows"]
    assert isinstance(rows, list)
    row_fields = {
        "attempted_level",
        "suite_obligation_key",
        "applicability",
        "evaluation_state",
        "state_reason",
        "producer_branch",
        "prerequisite_code",
        "observed_finding",
        "counts_as_level_failure",
    }
    for row in rows:
        assert set(row) == row_fields
        finding = row["observed_finding"]
        assert (finding is None) == (row["counts_as_level_failure"] is None)
        if finding is not None:
            assert set(finding) == {"code", "status"}
            assert type(row["counts_as_level_failure"]) is bool
    assert _row(execution, 0, "TR-SCA-002") == accounting.AccountingRow(
        0,
        "TR-SCA-002",
        A,
        N,
        "TR-SCA is not scheduled at attempted Level 0",
        "level0_scheduler_nonexecution",
        None,
        None,
        None,
        None,
    )
    assert all(
        row.state_reason is None
        for row in execution.rows
        if (row.attempted_level, row.obligation_key) != (0, "TR-SCA-002")
    )
    assert [
        (_row(execution, level, "TR-SCA-002").producer_branch,
         _row(execution, level, "TR-SCA-002").evaluation_state)
        for level in (1, 2)
    ] == [("digest_valid", C), ("digest_valid", C)]

    # Returned findings/documents are copies; neither can splice run B into this snapshot.
    untouched = accounting._accounting_document(execution)
    changed = execution.compatibility_results
    changed[0]["TR-APR"][0].code = "spliced"
    other = _execute({**valid_level0, "appraisal": {"status": "wrong"}}, (0,))
    changed[0]["TR-APR"] = other.compatibility_results[0]["TR-APR"]
    changed_document = accounting._accounting_document(execution)
    changed_document["rows"] = accounting._accounting_document(other)["rows"]
    assert accounting._accounting_document(execution) == untouched
    assert execution.compatibility_results[0]["TR-APR"][0].code != "spliced"

    built = report._build_from_execution(
        record=valid_level0,
        record_path="record.json",
        execution=execution,
        suite_version="0.5.1",
        library_version=None,
        generated_at="2026-08-31 12:00 UTC",
    )
    rendered = (report.to_json(built), report.to_html(built), report.badge_svg(built))
    parsed = json.loads(rendered[0])
    assert parsed["schema"] == "agentrust-io/trace-tests/report/1"
    registry = accounting._accounting_document(execution)["registry"]
    assert isinstance(registry, dict)
    assert parsed["obligation_accounting"] == {
        "schema": report.ACCOUNTING_REPORT_SCHEMA,
        "registry_id": registry["id"],
        "registry_sha256": registry["sha256"],
        **accounting._accounting_document(execution),
    }
    assert all("obligation_accounting" not in value for value in rendered[1:])
    help_result = CliRunner().invoke(main, ["report", "--help"])
    assert help_result.exit_code == 0 and "accounting" not in help_result.output.lower()


def test_report_rejects_incomplete_or_mismatched_execution(
    valid_level0: dict[str, Any],
) -> None:
    execution = _execute(valid_level0, (0,))
    payload = json.loads(execution._payload)

    payload["accounting"]["rows"].pop()
    incomplete = accounting._Execution(json.dumps(payload).encode("ascii"))
    with pytest.raises(ValueError, match="incomplete obligation accounting"):
        report._build_from_execution(
            record=valid_level0,
            record_path="record.json",
            execution=incomplete,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )

    payload = json.loads(execution._payload)
    payload["accounting"]["registry"]["id"] = "spliced"
    mismatched = accounting._Execution(json.dumps(payload).encode("ascii"))
    with pytest.raises(ValueError, match="unexpected obligation registry"):
        report._build_from_execution(
            record=valid_level0,
            record_path="record.json",
            execution=mismatched,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )

    with pytest.raises(ValueError, match="report record does not match"):
        report._build_from_execution(
            record={**valid_level0, "subject": "spiffe://example.org/agent/spliced"},
            record_path="record.json",
            execution=execution,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )


@pytest.mark.parametrize("attack", ["missing", "duplicate", "substitute"])
def test_accounted_emission_binds_rows_to_the_exact_pilot_registry(
    valid_level0: dict[str, Any], attack: str
) -> None:
    execution = _execute(valid_level0, (0,))
    payload = json.loads(execution._payload)
    registry = payload["accounting"]["registry"]
    obligations = registry["obligations"]

    if attack == "missing":
        obligations.pop()
    elif attack == "duplicate":
        obligations.append(copy.deepcopy(obligations[-1]))
    else:
        obligations[-1]["key"] = "TR-SCA-009"

    body = {key: value for key, value in registry.items() if key != "sha256"}
    registry["sha256"] = "sha256:" + hashlib.sha256(
        accounting._canonical_json(body)
    ).hexdigest()
    forged = accounting._Execution(accounting._canonical_json(payload))

    with pytest.raises(ValueError, match="pilot registry does not match its rows"):
        report._build_from_execution(
            record=valid_level0,
            record_path="record.json",
            execution=forged,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )


def test_accounted_emission_cannot_drop_every_row_for_an_attempted_level(
    valid_level0: dict[str, Any],
) -> None:
    execution = _execute(valid_level0, (0, 1))
    payload = json.loads(execution._payload)
    payload["accounting"]["rows"] = [
        row for row in payload["accounting"]["rows"] if row["attempted_level"] != 1
    ]
    forged = accounting._Execution(accounting._canonical_json(payload))

    with pytest.raises(ValueError, match="incomplete obligation accounting"):
        report._build_from_execution(
            record=valid_level0,
            record_path="record.json",
            execution=forged,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )


def test_accounted_emission_binds_state_reason_to_the_registered_branch(
    valid_level0: dict[str, Any],
) -> None:
    execution = _execute(valid_level0, (0,))
    payload = json.loads(execution._payload)
    sca = next(
        row
        for row in payload["accounting"]["rows"]
        if row["suite_obligation_key"] == "TR-SCA-002"
    )
    sca["state_reason"] = "totally false reason"
    forged = accounting._Execution(accounting._canonical_json(payload))

    with pytest.raises(
        ValueError, match="accounting row does not match its registered branch"
    ):
        report._build_from_execution(
            record=valid_level0,
            record_path="record.json",
            execution=forged,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )


@pytest.mark.parametrize(
    ("attack", "error"),
    [
        ("row_status", "accounting row does not match its finding"),
        ("row_contribution", "accounting contribution does not match frozen policy"),
        ("tally", "report tallies do not match frozen results"),
    ],
)
def test_accounted_emission_revalidates_rows_findings_policy_and_tallies(
    valid_level0: dict[str, Any], attack: str, error: str
) -> None:
    execution = _execute(valid_level0, (0,))
    payload = json.loads(execution._payload)
    apr = next(
        row
        for row in payload["accounting"]["rows"]
        if row["suite_obligation_key"] == "TR-APR-001"
    )

    if attack == "row_status":
        apr["observed_finding"]["status"] = "fail"
    elif attack == "row_contribution":
        apr["counts_as_level_failure"] = True
    else:
        payload["report_tallies"][0][1] += 1

    forged = accounting._Execution(accounting._canonical_json(payload))
    with pytest.raises(ValueError, match=error):
        report._build_from_execution(
            record=valid_level0,
            record_path="record.json",
            execution=forged,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )


@pytest.mark.parametrize(
    ("field", "bad_value", "error_field"),
    [
        ("result_level", False, "results.level"),
        ("result_level", 0.0, "results.level"),
        ("tally_level", False, "report_tallies.level"),
        ("tally_level", 0.0, "report_tallies.level"),
        ("row_level", False, "accounting.rows.attempted_level"),
        ("row_level", 0.0, "accounting.rows.attempted_level"),
        ("failure_count", False, "report_tallies.failures"),
        ("failure_count", 0.0, "report_tallies.failures"),
        ("unverified_count", True, "report_tallies.unverified"),
        ("unverified_count", 1.0, "report_tallies.unverified"),
    ],
)
def test_accounted_emission_requires_exact_integer_machine_fields(
    valid_level0: dict[str, Any],
    field: str,
    bad_value: bool | float,
    error_field: str,
) -> None:
    execution = _execute(valid_level0, (0,))
    payload = json.loads(execution._payload)
    if field == "result_level":
        payload["results"][0][0] = bad_value
    elif field == "tally_level":
        payload["report_tallies"][0][0] = bad_value
    elif field == "row_level":
        payload["accounting"]["rows"][0]["attempted_level"] = bad_value
    elif field == "failure_count":
        payload["report_tallies"][0][1] = bad_value
    else:
        payload["report_tallies"][0][2] = bad_value

    forged = accounting._Execution(accounting._canonical_json(payload))
    with pytest.raises(
        ValueError, match=rf"invalid frozen execution integer: {error_field}"
    ):
        report._build_from_execution(
            record=valid_level0,
            record_path="record.json",
            execution=forged,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-09-03 12:00 UTC",
        )


def test_accounted_emission_requires_a_failing_prerequisite_finding(
    valid_level0: dict[str, Any],
) -> None:
    record = copy.deepcopy(valid_level0)
    record.pop("policy")
    execution = _execute(record, (0,))
    payload = json.loads(execution._payload)
    modules = dict(payload["results"][0][1])
    prerequisite = next(
        finding for finding in modules["TR-POL"] if finding[0] == "TR-POL-001"
    )
    prerequisite[1] = "pass"
    forged = accounting._Execution(accounting._canonical_json(payload))

    with pytest.raises(
        ValueError, match="accounting prerequisite does not match frozen results"
    ):
        report._build_from_execution(
            record=record,
            record_path="record.json",
            execution=forged,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )


def test_accounted_json_is_a_post_build_immutable_snapshot(
    valid_level0: dict[str, Any],
) -> None:
    execution = _execute(valid_level0, (0,))
    built = report._build_from_execution(
        record=valid_level0,
        record_path="record.json",
        execution=execution,
        suite_version="0.5.1",
        library_version=None,
        generated_at="2026-08-31 12:00 UTC",
    )
    before = report.to_json(built)

    built.findings[0]["TR-APR"][0].code = "SPLICED"

    assert report.to_json(built) == before


def test_cli_report_emits_accounting_from_one_execution(
    valid_level0: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from trace_tests import cli

    record_path = tmp_path / "record.json"
    report_path = tmp_path / "report.json"
    record_path.write_text(json.dumps(valid_level0), encoding="utf-8")
    original = cli._run_levels
    calls = 0

    def counted(*args: object, **kwargs: object) -> accounting._Execution:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(cli, "_run_levels", counted)
    result = CliRunner().invoke(
        main,
        [
            "report",
            "--record",
            str(record_path),
            "--max-level",
            "0",
            "--max-age",
            str(MAX_AGE),
            "--json",
            str(report_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert calls == 1
    extension = json.loads(report_path.read_text(encoding="utf-8"))["obligation_accounting"]
    assert extension["schema"] == report.ACCOUNTING_REPORT_SCHEMA
    assert extension["accounting_complete"] is True
    assert len(extension["rows"]) == 3


def test_all_twenty_one_registered_branches_have_exact_integration_witnesses(
    valid_level0: dict[str, Any],
) -> None:
    projected = []
    for case in BRANCH_CASES:
        key, level, branch, applicability, state, prerequisite, status, contribution = case
        record, resolver = _branch_input(valid_level0, branch)
        execution = _assert_public_and_report_compatibility(
            record, tuple(range(level + 1)), resolver
        )
        row = _row(execution, level, key)
        assert (
            row.producer_branch,
            row.applicability,
            row.evaluation_state,
            row.prerequisite_code,
            row.finding_code,
            row.finding_status,
            row.counts_as_level_failure,
        ) == (
            branch,
            applicability,
            state,
            prerequisite,
            key if status is not None else None,
            status,
            contribution,
        )
        projected.append(row)

    document = accounting._accounting_document(_execute(valid_level0, (0,)))
    registry = document["registry"]
    assert isinstance(registry, dict)
    registered = {
        branch["branch"] for item in registry["obligations"] for branch in item["branches"]
    }
    witnessed = {row.producer_branch for row in projected}
    assert len(BRANCH_CASES) == len(witnessed) == 21 and witnessed == registered
    prerequisites = [row for row in projected if row.prerequisite_code is not None]
    assert len(prerequisites) == 5
    assert all(row.prerequisite_code != row.obligation_key for row in prerequisites)


@pytest.mark.parametrize(
    ("attack", "error"),
    [
        ("omit_prerequisite", "0 recognised producers"),
        ("omit_target", "unearned or duplicate TR-SCA-002"),
        ("duplicate_prerequisite", "2 recognised producers"),
        ("wrong_owner", "during another checker invocation"),
        ("sibling", "has no frozen #88 decision"),
        ("renamed", "unrecognised producer branch TR-SCA/renamed"),
        ("duplicate_target", "unearned or duplicate TR-SCA-002"),
        ("substitute", "did not return its exact earned Finding once"),
        ("scheduler_role", "branch contradicts actual scheduling"),
    ],
)
def test_corrupt_observation_fails_closed_for_its_named_reason(
    valid_level0: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    error: str,
) -> None:
    record = copy.deepcopy(valid_level0)
    if attack in {"omit_prerequisite", "duplicate_prerequisite"}:
        record.pop("build_provenance")
    original = tr_sca._observe

    def hostile(module: str, branch: str, finding: Finding | None = None) -> Finding | None:
        if attack in {"omit_prerequisite", "omit_target"}:
            return finding
        if attack == "wrong_owner":
            return original("TR-POL", branch, finding)
        if attack == "sibling":
            assert finding is not None
            sibling = Finding("TR-SCA-001", finding.status, finding.message)
            return original(module, branch, sibling)
        if attack == "renamed":
            return original(module, "renamed", finding)
        if attack in {"duplicate_prerequisite", "duplicate_target"}:
            original(module, branch, finding)
            return original(module, branch, finding)
        if attack == "substitute":
            assert finding is not None
            original(module, branch, finding)
            return Finding(finding.code, finding.status, finding.message)
        assert attack == "scheduler_role"
        original(module, "level0_scheduler_nonexecution")
        return Finding("TR-SCA-001", Status.PASS, "scheduler-role plant")

    monkeypatch.setattr(tr_sca, "_observe", hostile)
    with pytest.raises((ValueError, RuntimeError), match=error):
        _execute(record, (0, 1))


def test_registry_binds_declared_sources_rules_candidate_bytes_and_hash(
    valid_level0: dict[str, Any],
) -> None:
    registry = accounting._accounting_document(_execute(valid_level0, (0,)))["registry"]
    assert isinstance(registry, dict)
    assert set(registry) == {"schema", "id", "contribution_policy", "obligations", "sha256"}
    assert (registry["schema"], registry["id"]) == (
        "agentrust-io/trace-tests/obligation-registry/1",
        "agentrust-io/trace-tests/obligation-registry/pilot-1",
    )

    policy = registry["contribution_policy"]
    assert isinstance(policy, dict)
    assert set(policy) == {
        "repository",
        "path",
        "symbol",
        "source_sha256",
        "unverified_fails_from_level",
        "default_fails_from_level",
    }
    assert (
        policy["repository"],
        policy["path"],
        policy["symbol"],
        policy["unverified_fails_from_level"],
        policy["default_fails_from_level"],
    ) == (
        "https://github.com/agentrust-io/trace-tests",
        "src/trace_tests/modules/unverified.py",
        "finding_counts_as_level_failure",
        {"TR-POL-003": 2, "TR-SIG-005": 1},
        1,
    )
    assert policy["source_sha256"] == (
        "sha256:" + hashlib.sha256((REPO / policy["path"]).read_bytes()).hexdigest()
    )

    obligations = registry["obligations"]
    assert isinstance(obligations, list)
    assert [(item["key"], item["owner"]) for item in obligations] == list(OWNERS.items())
    for item in obligations:
        key = item["key"]
        assert set(item) == {
            "key",
            "owner",
            "normative_sources",
            "structural_sources",
            "checker_binding",
            "branches",
        }
        schema_sources = (
            item["structural_sources"]
            if key == "TR-POL-003"
            else item["normative_sources"]
        )
        assert [source["locator"] for source in schema_sources] == list(FRAGMENTS[key])
        for source in schema_sources:
            assert set(source) == {
                "repository",
                "commit",
                "path",
                "locator_kind",
                "locator",
                "value_sha256",
            }
            assert (source["repository"], source["commit"], source["path"]) == (
                "https://github.com/agentrust-io/trace-spec",
                "c111c2f0fc8df214fe9bc339769cf71d33a4af52",
                "schema/trace-claim.json",
            )
            assert source["locator_kind"] == "json_pointer"
            assert source["value_sha256"] == LOCATOR_VALUE_SHA256[source["locator"]]
        if key != "TR-POL-003":
            assert item["structural_sources"] == []

        binding = item["checker_binding"]
        module_name = item["owner"].lower().replace("-", "_")
        assert set(binding) == {
            "repository",
            "path",
            "module",
            "checker_symbol",
            "source_sha256",
        }
        assert (
            binding["repository"],
            binding["path"],
            binding["module"],
            binding["checker_symbol"],
        ) == (
            "https://github.com/agentrust-io/trace-tests",
            f"src/trace_tests/modules/{module_name}.py",
            f"trace_tests.modules.{module_name}",
            "check",
        )
        assert binding["source_sha256"] == (
            "sha256:" + hashlib.sha256((REPO / binding["path"]).read_bytes()).hexdigest()
        )

        expected_rules = [case for case in BRANCH_CASES if case[0] == key]
        assert [
            (
                branch["branch"],
                branch["role"],
                branch["finding_code"],
                branch["finding_statuses"],
                branch["prerequisite_code"],
                branch["prerequisite_statuses"],
                branch["prerequisite_message_prefix"],
            )
            for branch in item["branches"]
        ] == [
            (
                branch,
                _role(branch),
                key if status is not None else None,
                [status.value] if status is not None else [],
                prerequisite,
                [Status.FAIL.value] if prerequisite is not None else [],
                PREREQUISITE_PREFIXES.get(branch),
            )
            for key, _level, branch, _app, _state, prerequisite, status, _counts in expected_rules
        ]
        assert all(
            set(branch)
            == {
                "branch",
                "role",
                "finding_code",
                "finding_statuses",
                "prerequisite_code",
                "prerequisite_statuses",
                "prerequisite_message_prefix",
            }
            for branch in item["branches"]
        )

    # These are pinned external locators, not claims about the repository's local
    # schema copy. Resolving them against that different file would not prove the
    # trace-spec preimage named above.
    assert sum(len(FRAGMENTS[key]) for key in OWNERS) == 13

    body = {key: value for key, value in registry.items() if key != "sha256"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert registry["sha256"] == "sha256:" + hashlib.sha256(canonical).hexdigest()


def test_execution_freezes_input_dispatch_and_direct_central_88(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    record = copy.deepcopy(valid_level0)
    record["policy"].update(
        policy_uri="https://p.example/x", bundle_hash="sha256:" + "0" * 64
    )
    pristine = accounting._canonical_json(record)
    central = unverified._finding_counts_as_level_failure
    contribution_calls: list[tuple[str, Status, int]] = []
    resolver_calls = 0

    def spy(
        finding: Finding,
        level: int,
        unverified_rule: Callable[[str, int], bool],
    ) -> bool:
        contribution_calls.append((finding.code, finding.status, level))
        return central(finding, level, unverified_rule)

    with monkeypatch.context() as patch:
        patch.setattr(unverified, "_finding_counts_as_level_failure", spy)

        def resolver(_uri: str) -> bytes:
            nonlocal resolver_calls
            resolver_calls += 1
            if resolver_calls == 1:
                record["appraisal"]["status"] = "wrong"
                patch.setattr(tr_apr, "check", lambda _trace, _level: [])
                patch.setattr(runner, "run", lambda *_args, **_kwargs: {})
                patch.setattr(runner, "_run_core", lambda *_args, **_kwargs: {})
                patch.setattr(runner, "_LEVEL_MODULES", {0: ("TR-APR",)})
                patch.setattr(accounting, "_invoke", lambda _module, checker: checker())
                patch.setattr(accounting, "_begin_level", lambda _level: None)
                patch.setattr(accounting, "_end_level", lambda _level: None)
                patch.setattr(accounting, "_complete_execution", lambda *_args: None)
                patch.setattr(accounting, "_execution", lambda *_args: None)
                patch.setattr(accounting, "_collect_specs", lambda: ())
                patch.setattr(accounting, "_registry_body", lambda _specs: {})
                patch.setattr(
                    unverified,
                    "finding_counts_as_level_failure",
                    lambda _finding, _level: True,
                )
                patch.setattr(
                    unverified,
                    "_finding_counts_as_level_failure",
                    lambda _finding, _level, _rule: True,
                )
                patch.setattr(unverified, "unverified_fails", lambda _code, _level: True)
            raise OSError("offline")

        execution = _execute(record, resolver=resolver)

    assert resolver_calls == 3 and execution.record_bytes == pristine
    assert [
        _row(execution, level, "TR-APR-001").producer_branch for level in range(3)
    ] == ["status_valid"] * 3
    assert [tuple(execution.compatibility_results[level]) for level in range(3)] == list(
        SCHEDULES
    )
    assert [
        _row(execution, level, "TR-POL-003").counts_as_level_failure for level in range(3)
    ] == [False, False, True]
    finding_rows = [row for row in execution.rows if row.finding_code is not None]
    expected_calls = [
        (row.finding_code, row.finding_status, row.attempted_level) for row in finding_rows
    ]
    report_calls = [
        (finding.code, finding.status, level)
        for level, results in execution.compatibility_results.items()
        for findings in results.values()
        for finding in findings
    ]
    assert Counter(contribution_calls) == Counter(expected_calls + report_calls)
    for row in execution.rows:
        if row.finding_code is None:
            assert row.counts_as_level_failure is None
        else:
            assert row.finding_status is not None
            finding = Finding(row.finding_code, row.finding_status, "")
            assert row.counts_as_level_failure is central(
                finding, row.attempted_level, unverified.unverified_fails
            )


@pytest.mark.parametrize("part", ["threshold", "default"])
def test_callback_cannot_change_central_88_metadata_mid_execution(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch, part: str
) -> None:
    record = copy.deepcopy(valid_level0)
    record["policy"].update(
        policy_uri="https://p.example/x", bundle_hash="sha256:" + "0" * 64
    )

    def resolver(_uri: str) -> bytes:
        if part == "threshold":
            monkeypatch.setitem(unverified.UNVERIFIED_FAILS_FROM_LEVEL, "TR-POL-003", 0)
        else:
            monkeypatch.setattr(unverified, "DEFAULT_FAILS_FROM_LEVEL", 0)
        raise OSError("offline")

    with pytest.raises(RuntimeError, match="central #88 policy changed during execution"):
        _execute(record, (0,), resolver)


def test_later_callback_cannot_mutate_an_earlier_finding(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    record = copy.deepcopy(valid_level0)
    record["policy"].update(policy_uri="https://p.example/x", bundle_hash=DIGEST)
    retained: list[Finding] = []
    original = tr_sca._observe

    def retaining(module: str, branch: str, finding: Finding | None = None) -> Finding | None:
        observed = original(module, branch, finding)
        if finding is not None:
            retained.append(finding)
        return observed

    calls = 0

    def resolver(_uri: str) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 3:
            retained[0].message = "later mutation"
        return BUNDLE

    monkeypatch.setattr(tr_sca, "_observe", retaining)
    with pytest.raises(RuntimeError, match="mutated its Finding after earning it"):
        _execute(record, resolver=resolver)


@pytest.mark.parametrize("inner_raises", [False, True], ids=["returns", "raises"])
def test_public_run_inside_resolver_is_isolated_from_accounting_capture(
    valid_level0: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    inner_raises: bool,
) -> None:
    outer = copy.deepcopy(valid_level0)
    outer["policy"].update(policy_uri="https://p.example/x", bundle_hash=DIGEST)
    inner = copy.deepcopy(valid_level0)
    resolver_calls = 0

    def resolver(_uri: str) -> bytes:
        nonlocal resolver_calls
        resolver_calls += 1
        if inner_raises:

            def explode(*_args: object, **_kwargs: object) -> list[Finding]:
                raise RuntimeError("inner checker boom")

            with monkeypatch.context() as patch:
                patch.setattr(tr_env, "check", explode)
                with pytest.raises(RuntimeError, match="inner checker boom"):
                    runner.run(copy.deepcopy(inner), "trace", 0, max_age_seconds=MAX_AGE)
        else:
            nested = runner.run(
                copy.deepcopy(inner), "trace", 0, max_age_seconds=MAX_AGE
            )
            assert "TR-ENV" in nested
        return BUNDLE

    legacy = runner.run(
        copy.deepcopy(outer),
        "trace",
        0,
        max_age_seconds=MAX_AGE,
        policy_resolver=resolver,
    )
    execution = _execute(copy.deepcopy(outer), (0,), resolver)

    legacy_finding = next(item for item in legacy["TR-POL"] if item.code == "TR-POL-003")
    accounted_finding = next(
        item
        for item in execution.compatibility_results[0]["TR-POL"]
        if item.code == "TR-POL-003"
    )
    row = _row(execution, 0, "TR-POL-003")
    assert resolver_calls == 2
    assert (legacy_finding.status, accounted_finding.status) == (Status.PASS, Status.PASS)
    assert (row.evaluation_state, row.finding_status) == (C, Status.PASS)
    assert accounting._accounting_document(execution)["accounting_complete"] is True
    assert accounting._CAPTURE.get() is None


def test_explicit_null_preserves_legacy_skip_and_invalid_levels_emit_no_accounting(
    valid_level0: dict[str, Any],
) -> None:
    explicit_null = copy.deepcopy(valid_level0)
    explicit_null["policy"]["policy_uri"] = None
    public = runner.run(explicit_null, "trace", 0, max_age_seconds=MAX_AGE)
    finding = next(item for item in public["TR-POL"] if item.code == "TR-POL-003")
    assert (finding.status, finding.message) == (
        Status.SKIP,
        "policy.policy_uri not present (optional); no bundle to resolve",
    )
    execution = _execute(explicit_null, (0,))
    assert _row(execution, 0, "TR-POL-003") == accounting.AccountingRow(
        0,
        "TR-POL-003",
        NA,
        C,
        None,
        "policy_uri_explicit_null",
        None,
        "TR-POL-003",
        Status.SKIP,
        False,
    )

    for levels in ((), (1,), (0, 2), (0, 0), (0, True), (0, 1, 3)):
        with pytest.raises(ValueError, match="attempted levels"):
            _execute(valid_level0, levels)  # type: ignore[arg-type]


def test_accounted_renderers_and_verdict_share_one_post_build_snapshot(
    valid_level0: dict[str, Any],
) -> None:
    execution = _execute(valid_level0, (0,))

    def assembled() -> report.ReportData:
        return report._build_from_execution(
            record=valid_level0,
            record_path="record.json",
            execution=execution,
            suite_version="0.5.1",
            library_version=None,
            generated_at="2026-08-31 12:00 UTC",
        )

    untouched = assembled()
    mutated = assembled()
    expected = (
        report.to_json(untouched),
        report.to_html(untouched),
        report.badge_svg(untouched),
        untouched.verdict,
        untouched.highest_level,
    )

    mutated.findings[0]["TR-APR"][0].code = "SPLICED"
    mutated.levels.clear()

    assert (
        report.to_json(mutated),
        report.to_html(mutated),
        report.badge_svg(mutated),
        mutated.verdict,
        mutated.highest_level,
    ) == expected


def test_accounted_renderers_are_exactly_legacy_plus_the_json_extension(
    valid_level0: dict[str, Any],
) -> None:
    execution = _execute(valid_level0, (0,))
    common = {
        "record": valid_level0,
        "record_path": "record.json",
        "record_format": "trace",
        "suite_version": "0.5.1",
        "library_version": None,
        "generated_at": "2026-08-31 12:00 UTC",
    }
    legacy = report.build(results_by_level=execution.compatibility_results, **common)
    accounted = report._build_from_execution(
        execution=execution,
        **{key: value for key, value in common.items() if key != "record_format"},
    )
    legacy_json = json.loads(report.to_json(legacy))
    accounted_json = json.loads(report.to_json(accounted))

    assert set(accounted_json) - set(legacy_json) == {"obligation_accounting"}
    accounted_json.pop("obligation_accounting")
    assert accounted_json == legacy_json
    assert report.to_html(accounted) == report.to_html(legacy)
    assert report.badge_svg(accounted) == report.badge_svg(legacy)


@pytest.mark.parametrize("path", CANONICALIZATION_VECTORS, ids=lambda path: path.stem)
def test_accounted_path_preserves_public_outputs_at_canonicalization_boundaries(
    path: Path,
) -> None:
    vector = json.loads(path.read_text(encoding="utf-8"))
    _assert_public_and_report_compatibility(vector["record"])


@pytest.mark.parametrize("width", [1, 2, 3])
def test_accounted_path_preserves_public_outputs_for_every_attempted_width(
    valid_level0: dict[str, Any], width: int
) -> None:
    _assert_public_and_report_compatibility(valid_level0, tuple(range(width)))


@pytest.mark.parametrize(
    "value",
    ["modèle-géant", 1.25, 2**60, float("nan")],
    ids=["non-ascii", "float", "jcs-unsafe-integer", "nan"],
)
def test_accounted_path_preserves_public_outputs_for_json_boundary_values(
    valid_level0: dict[str, Any], value: object
) -> None:
    record = copy.deepcopy(valid_level0)
    record["model"]["model_id"] = value
    _assert_public_and_report_compatibility(record)


def test_temporary_policy_mutation_cannot_change_frozen_contributions(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    record = copy.deepcopy(valid_level0)
    record["policy"].update(policy_uri="https://p.example/x", bundle_hash="sha256:" + "0" * 64)
    calls = 0

    def resolver(_uri: str) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            monkeypatch.setitem(unverified.UNVERIFIED_FAILS_FROM_LEVEL, "TR-POL-003", 0)
        elif calls == 3:
            monkeypatch.setitem(unverified.UNVERIFIED_FAILS_FROM_LEVEL, "TR-POL-003", 2)
        raise OSError("offline")

    execution = _execute(record, resolver=resolver)
    assert calls == 3
    assert [_row(execution, level, "TR-POL-003").counts_as_level_failure for level in range(3)] == [
        False,
        False,
        True,
    ]
    built = report._build_from_execution(
        record=record,
        record_path="record.json",
        execution=execution,
        suite_version="0.5.1",
        library_version=None,
        generated_at="2026-08-31 12:00 UTC",
    )
    document = json.loads(report.to_json(built))
    control = _execute(
        copy.deepcopy(record),
        resolver=lambda _uri: (_ for _ in ()).throw(OSError("offline")),
    )
    control_built = report._build_from_execution(
        record=record,
        record_path="record.json",
        execution=control,
        suite_version="0.5.1",
        library_version=None,
        generated_at="2026-08-31 12:00 UTC",
    )
    assert document["levels"] == json.loads(report.to_json(control_built))["levels"]
    assert (
        document["obligation_accounting"]["registry"]["contribution_policy"][
            "unverified_fails_from_level"
        ]["TR-POL-003"]
        == 2
    )


def test_report_tally_uses_the_execution_policy_snapshot(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    record = copy.deepcopy(valid_level0)
    record["policy"].update(policy_uri="https://p.example/x", bundle_hash="sha256:" + "0" * 64)
    execution = _execute(
        record,
        (0,),
        lambda _uri: (_ for _ in ()).throw(OSError("offline")),
    )
    assert _row(execution, 0, "TR-POL-003").counts_as_level_failure is False

    monkeypatch.setitem(unverified.UNVERIFIED_FAILS_FROM_LEVEL, "TR-POL-003", 0)
    built = report._build_from_execution(
        record=record,
        record_path="record.json",
        execution=execution,
        suite_version="0.5.1",
        library_version=None,
        generated_at="2026-08-31 12:00 UTC",
    )
    document = json.loads(report.to_json(built))
    assert document["levels"][0]["failures"] == 0
    assert (
        document["obligation_accounting"]["registry"]["contribution_policy"][
            "unverified_fails_from_level"
        ]["TR-POL-003"]
        == 2
    )


@pytest.mark.parametrize("registered", [0, 2])
def test_scheduler_nonexecution_requires_exactly_one_registered_rule(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch, registered: int
) -> None:
    specs = accounting._collect_specs()
    amended = []
    for spec in specs:
        if spec.key != "TR-SCA-002":
            amended.append(spec)
            continue
        scheduler = next(
            rule
            for rule in spec.branches
            if rule.role is accounting.ProducerRole.SCHEDULER_NONEXECUTION_APPLICABLE
        )
        without_scheduler = tuple(rule for rule in spec.branches if rule is not scheduler)
        scheduler_rules = (
            ()
            if registered == 0
            else (scheduler, scheduler._replace(branch="second_scheduler_nonexecution"))
        )
        amended.append(spec._replace(branches=without_scheduler + scheduler_rules))
    monkeypatch.setattr(accounting, "_collect_specs", lambda: tuple(amended))

    with pytest.raises(ValueError, match="exactly one scheduler nonexecution rule"):
        _execute(valid_level0, (0,))


def test_no_finding_rule_rejects_an_attached_pilot_finding(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    record = copy.deepcopy(valid_level0)
    record.pop("build_provenance")

    def hostile(_trace: dict[str, Any]) -> list[Finding]:
        planted = Finding("TR-SCA-002", Status.PASS, "must not be discarded")
        accounting._observe("TR-SCA", "build_provenance_missing", planted)
        return [
            Finding(
                "TR-SCA-001",
                Status.FAIL,
                "TR-SCA-001: build_provenance is required at Level 1+",
            ),
            planted,
        ]

    monkeypatch.setattr(tr_sca, "check", hostile)
    with pytest.raises(ValueError, match="no-finding branch carried a finding"):
        _execute(record, (0, 1))


def test_no_finding_rule_rejects_an_attached_contribution(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    original = accounting._end_level

    def hostile(level: int) -> None:
        original(level)
        capture = accounting._CAPTURE.get()
        assert capture is not None
        fact = capture.producers[-1]
        capture.producers[-1] = fact._replace(counts_as_level_failure=True)

    monkeypatch.setattr(accounting, "_end_level", hostile)
    with pytest.raises(ValueError, match="no-finding branch carried a finding"):
        _execute(valid_level0, (0,))


def test_unknown_producer_role_fails_closed() -> None:
    with pytest.raises(ValueError, match="unknown producer role"):
        accounting._role_projection(cast(accounting.ProducerRole, "future_role"))


def test_normative_source_locator_identity_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert accounting._SOURCE_VALUE_MANIFEST_IDENTITY == (
        "https://github.com/agentrust-io/trace-spec",
        "c111c2f0fc8df214fe9bc339769cf71d33a4af52",
        "schema/trace-claim.json",
    )
    with pytest.raises(ValueError, match="unbound normative source locator"):
        accounting._normative_sources("/properties/appraisal/properties/status/enums")

    monkeypatch.setattr(accounting, "_TRACE_SPEC_REVISION", "future-revision")
    with pytest.raises(ValueError, match="unbound normative source locator"):
        accounting._normative_sources("/properties/appraisal/properties/status/enum")


def test_normative_text_locator_identity_and_value_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert accounting._TEXT_SOURCE_VALUE_MANIFEST_IDENTITY == (
        "https://github.com/agentrust-io/trace-spec",
        "c111c2f0fc8df214fe9bc339769cf71d33a4af52",
        "spec/trace-v0.2.md",
    )
    with pytest.raises(ValueError, match="unbound normative source locator"):
        accounting._normative_text_sources(
            "5. Policy hash matches the policy bundle a verifier expects."
        )

    monkeypatch.setattr(accounting, "_TRACE_SPEC_TEXT_PATH", "spec/future.md")
    with pytest.raises(ValueError, match="unbound normative source locator"):
        accounting._normative_text_sources(accounting._POLICY_CORRESPONDENCE_RULE)


def test_json_only_cli_does_not_execute_unrequested_renderers(
    valid_level0: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    record = copy.deepcopy(valid_level0)
    record["transparency"] = {"loader_accepted": True}
    record_path = tmp_path / "record.json"
    json_path = tmp_path / "report.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    def forbidden(_data: report.ReportData) -> str:
        raise AssertionError("HTML renderer executed during a JSON-only request")

    monkeypatch.setattr(report, "to_html", forbidden)
    result = CliRunner().invoke(
        main,
        [
            "report",
            "--record",
            str(record_path),
            "--max-level",
            "0",
            "--max-age",
            str(MAX_AGE),
            "--json",
            str(json_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json_path.exists()
    assert "obligation_accounting" in json.loads(json_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "returned",
    [
        pytest.param((), id="absent"),
        pytest.param(
            (Finding("TR-POL-001", Status.PASS, "not blocking"),),
            id="non-blocking",
        ),
        pytest.param(
            (
                Finding("TR-POL-001", Status.FAIL, "first"),
                Finding("TR-POL-001", Status.FAIL, "second"),
            ),
            id="duplicate",
        ),
        pytest.param(
            (Finding("TR-POL-002", Status.FAIL, "wrong prerequisite"),),
            id="wrong-code",
        ),
        pytest.param(
            (Finding("TR-POL-001", Status.FAIL, "unrelated failure reason"),),
            id="wrong-reason",
        ),
    ],
)
def test_prerequisite_row_requires_one_exact_blocking_same_run_finding(
    valid_level0: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    returned: tuple[Finding, ...],
) -> None:
    record = copy.deepcopy(valid_level0)
    record.pop("policy")

    def hostile(
        _trace: dict[str, Any], *, policy_resolver: Callable[[str], bytes] | None = None
    ) -> list[Finding]:
        del policy_resolver
        accounting._observe("TR-POL", "policy_missing")
        return list(returned)

    monkeypatch.setattr(tr_pol, "check", hostile)
    with pytest.raises(ValueError, match="blocking prerequisite"):
        _execute(record, (0,))


def test_prerequisite_row_is_derived_from_the_returned_blocking_finding(
    valid_level0: dict[str, Any],
) -> None:
    record = copy.deepcopy(valid_level0)
    record.pop("policy")
    row = _row(_execute(record, (0,)), 0, "TR-POL-003")
    assert row.evaluation_state is B
    assert row.prerequisite_code == "TR-POL-001"


def test_returned_prerequisite_finding_cannot_mutate_later_in_the_same_run(
    valid_level0: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    record = copy.deepcopy(valid_level0)
    record.pop("build_provenance")
    original_sca = tr_sca.check
    original_txn = runner.tr_txn.check
    retained: list[Finding] = []

    def retaining(trace: dict[str, Any]) -> list[Finding]:
        findings = original_sca(trace)
        retained.extend(item for item in findings if item.code == "TR-SCA-001")
        return findings

    def mutating(trace: dict[str, Any]) -> list[Finding]:
        retained[0].message = "mutated after the prerequisite checker returned"
        return original_txn(trace)

    monkeypatch.setattr(tr_sca, "check", retaining)
    monkeypatch.setattr(runner.tr_txn, "check", mutating)
    with pytest.raises(RuntimeError, match="findings changed during execution"):
        _execute(record)


def test_tr_pol_registry_separates_operational_rule_from_schema_support(
    valid_level0: dict[str, Any],
) -> None:
    registry = accounting._accounting_document(_execute(valid_level0, (0,)))["registry"]
    assert isinstance(registry, dict)
    obligation = next(
        item for item in registry["obligations"] if item["key"] == "TR-POL-003"
    )
    assert obligation["normative_sources"] == [
        {
            "repository": "https://github.com/agentrust-io/trace-spec",
            "commit": "c111c2f0fc8df214fe9bc339769cf71d33a4af52",
            "path": "spec/trace-v0.2.md",
            "locator_kind": "exact_text",
            "locator": "5. Policy hash matches the policy bundle the verifier expects.",
            "value_sha256": (
                "sha256:ea109c835a9f84804af8583d4ed6284c8a82afdd6ca05e45c2dd767d70024ba6"
            ),
        }
    ]
    assert len(obligation["structural_sources"]) == 5
    assert {source["locator_kind"] for source in obligation["structural_sources"]} == {
        "json_pointer"
    }


def test_execution_backed_builder_is_not_a_public_api() -> None:
    assert "build_from_execution" not in report.__all__
    assert not hasattr(report, "build_from_execution")
    assert hasattr(report, "_build_from_execution")
    assert not hasattr(accounting, "accounting_document")


def test_execution_binds_record_format_without_a_report_relabel_seam(
    valid_level0: dict[str, Any],
) -> None:
    execution = _execute(valid_level0, (0,))
    assert execution.record_format == "trace"
    assert "record_format" not in inspect.signature(
        report._build_from_execution
    ).parameters

    built = report._build_from_execution(
        record=valid_level0,
        record_path="record.json",
        execution=execution,
        suite_version="0.5.1",
        library_version=None,
        generated_at="2026-09-03 12:00 UTC",
    )
    assert json.loads(report.to_json(built))["record"]["format"] == "trace"


def test_central_contribution_callable_keeps_dynamic_two_argument_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = Finding("TR-POL-003", Status.UNVERIFIED, "unresolved")
    monkeypatch.setattr(unverified, "unverified_fails", lambda _code, _level: True)
    assert unverified.finding_counts_as_level_failure(finding, 0) is True


def test_hosted_homepage_explains_the_bounded_accounting_surface() -> None:
    homepage = (REPO / "index.md").read_text(encoding="utf-8")
    assert "obligation_accounting" in homepage
    assert "three-obligation" in homepage

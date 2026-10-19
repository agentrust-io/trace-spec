"""TR-POL-003 with an expected policy hash: every branch the expectation adds.

A matching ``bundle_hash`` shows the resolved bytes are the ones the record
cited, not that they are the policy the verifier expected (trace-spec §3.3,
step 5). The expectation is verifier context, so it is a keyword argument to
``check``, never a field of the record. Every case below holds the record and
resolver fixed and varies only the expectation, so the expectation is the
only thing a changed status can be attributed to.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from trace_tests.cli import main
from trace_tests.modules.tr_pol import check
from trace_tests.modules.unverified import finding_counts_as_level_failure
from trace_tests.result import Finding, Status, finding_from_row, finding_row
from trace_tests.runner import _run_levels, run

BUNDLE = b'{"policy_id":"appraisal/agent-v1","version":"1.0.0"}'
EXPECTED = b'{"policy_id":"appraisal/agent-v2","version":"2.0.0"}'
URI = "https://policy.example.org/bundles/policy-bundle-base.json"

SHA256 = "sha256:" + hashlib.sha256(BUNDLE).hexdigest()
SHA384 = "sha384:" + hashlib.sha384(BUNDLE).hexdigest()
EXPECTED_SHA256 = "sha256:" + hashlib.sha256(EXPECTED).hexdigest()
EXPECTED_SHA384 = "sha384:" + hashlib.sha384(EXPECTED).hexdigest()

VECTOR_DIR = Path(__file__).resolve().parents[1] / "vectors" / "policy-resolution"


def resolver(mapping: dict[str, bytes]):
    def _resolve(uri: str) -> bytes:
        return mapping[uri]

    return _resolve


def offline(_uri: str) -> bytes:
    raise OSError("offline")


def trace_with(**policy):
    base = {"bundle_hash": SHA256, "enforcement_mode": "enforce"}
    base.update(policy)
    return {"policy": base}


def pol003(trace, policy_resolver=None, expected=None):
    findings = check(trace, policy_resolver=policy_resolver, expected_policy_hash=expected)
    return next(f for f in findings if f.code == "TR-POL-003")


# --- the requested pair ----------------------------------------------------


def test_a_correct_digest_over_the_expected_policy_passes():
    f = pol003(trace_with(policy_uri=URI), resolver({URI: BUNDLE}), SHA256)
    assert f.status is Status.PASS
    assert "the policy the verifier expects" in f.message


def test_a_correct_digest_over_a_different_policy_fails():
    trace = trace_with(policy_uri=URI)
    honest = resolver({URI: BUNDLE})
    assert pol003(trace, honest).status is Status.PASS, "the record itself is consistent"
    f = pol003(trace, honest, EXPECTED_SHA256)
    assert f.status is Status.FAIL
    assert "not the policy the verifier expects" in f.message


# --- mismatch is told apart from integrity failure and from no read ------


def test_a_mismatch_is_reported_without_a_resolver():
    f = pol003(trace_with(policy_uri=URI), None, EXPECTED_SHA256)
    assert f.status is Status.FAIL
    assert "not the policy the verifier expects" in f.message


def test_a_mismatch_is_a_failure_even_when_the_bundle_cannot_be_read():
    f = pol003(trace_with(policy_uri=URI), offline, EXPECTED_SHA256)
    assert f.status is Status.FAIL, "the declaration alone decides it, so it is not unverified"


def test_a_matching_expectation_does_not_hide_an_unreadable_bundle():
    f = pol003(trace_with(policy_uri=URI), offline, SHA256)
    assert f.status is Status.UNVERIFIED
    assert "could not be resolved" in f.message


def test_a_matching_expectation_does_not_hide_a_substituted_bundle():
    f = pol003(trace_with(policy_uri=URI), resolver({URI: EXPECTED}), SHA256)
    assert f.status is Status.FAIL
    assert "does not describe what policy.policy_uri resolves to" in f.message
    assert "verifier expects" not in f.message, "this is an integrity failure, not a mismatch"


def test_a_matching_expectation_without_a_resolver_still_skips():
    f = pol003(trace_with(policy_uri=URI), None, SHA256)
    assert f.status is Status.SKIP


@pytest.mark.parametrize("policy", [{}, {"policy_uri": None}], ids=["absent", "null"])
def test_omitting_policy_uri_does_not_escape_the_expectation(policy):
    trace = trace_with(**policy)
    assert pol003(trace, None, EXPECTED_SHA256).status is Status.FAIL
    assert pol003(trace, None, SHA256).status is Status.SKIP


# --- an expectation in another algorithm ----------------------------------


def test_an_expectation_in_another_algorithm_is_compared_over_the_resolved_bytes():
    trace = trace_with(policy_uri=URI)
    honest = resolver({URI: BUNDLE})
    assert pol003(trace, honest, SHA384).status is Status.PASS
    f = pol003(trace, honest, EXPECTED_SHA384)
    assert f.status is Status.FAIL
    assert "not the policy the verifier expects" in f.message


def test_a_sha384_record_is_held_to_a_sha256_expectation():
    trace = trace_with(bundle_hash=SHA384, policy_uri=URI)
    honest = resolver({URI: BUNDLE})
    assert pol003(trace, honest, SHA256).status is Status.PASS
    assert pol003(trace, honest, EXPECTED_SHA256).status is Status.FAIL


def non_bytes(_uri: str):
    return "not bytes"


UNEVALUATED = [
    ({"policy_uri": URI}, None, "no resolver was supplied"),
    ({"policy_uri": URI}, offline, "OSError: offline"),
    ({"policy_uri": URI}, non_bytes, "rather than bytes"),
    ({}, None, "policy.policy_uri is absent"),
    ({"policy_uri": None}, None, "policy.policy_uri is null"),
]
UNEVALUATED_IDS = ["no-resolver", "unreadable", "non-bytes", "uri-absent", "uri-null"]


@pytest.mark.parametrize("policy,policy_resolver,reason", UNEVALUATED, ids=UNEVALUATED_IDS)
def test_an_uncompared_expectation_fails_every_level_without_claiming_a_mismatch(
    policy, policy_resolver, reason
):
    f = pol003(trace_with(**policy), policy_resolver, EXPECTED_SHA384)
    assert f.status is Status.UNVERIFIED
    assert f.unverified_fails_from_level == 0
    assert "the expected policy was not compared" in f.message
    assert reason in f.message
    assert "not the policy the verifier expects" not in f.message
    assert [finding_counts_as_level_failure(f, level) for level in (0, 1, 2)] == [True] * 3


@pytest.mark.parametrize("policy,policy_resolver,reason", UNEVALUATED, ids=UNEVALUATED_IDS)
def test_without_an_expectation_the_same_inputs_keep_their_previous_result(
    policy, policy_resolver, reason
):
    f = pol003(trace_with(**policy), policy_resolver, None)
    assert f.unverified_fails_from_level is None
    assert "expected policy" not in f.message
    if policy_resolver in (offline, non_bytes):
        assert f.status is Status.UNVERIFIED
        assert [finding_counts_as_level_failure(f, level) for level in (0, 1, 2)] == [
            False, False, True,
        ]
    else:
        assert f.status is Status.SKIP
        assert not any(finding_counts_as_level_failure(f, level) for level in (0, 1, 2))


@pytest.mark.parametrize("policy_resolver", [offline, non_bytes], ids=["unreadable", "non-bytes"])
def test_a_settled_same_algorithm_expectation_keeps_the_generic_threshold(policy_resolver):
    # The declaration already equals the expectation, so the expectation was
    # compared. What is left unresolved is the bundle itself, which keeps the
    # registered TR-POL-003 threshold.
    f = pol003(trace_with(policy_uri=URI), policy_resolver, SHA256)
    assert f.status is Status.UNVERIFIED
    assert f.unverified_fails_from_level is None
    assert [finding_counts_as_level_failure(f, level) for level in (0, 1, 2)] == [
        False, False, True,
    ]


def test_a_finding_threshold_only_tightens_its_code():
    tighter = Finding("TR-POL-003", Status.UNVERIFIED, "m", unverified_fails_from_level=0)
    looser = Finding("TR-SIG-005", Status.UNVERIFIED, "m", unverified_fails_from_level=2)
    assert [finding_counts_as_level_failure(tighter, lv) for lv in (0, 1, 2)] == [True] * 3
    assert [finding_counts_as_level_failure(looser, lv) for lv in (0, 1, 2)] == [
        False, True, True,
    ]


def test_finding_rows_round_trip_and_stay_three_wide_without_a_threshold():
    plain = Finding("TR-POL-003", Status.SKIP, "m")
    tight = Finding("TR-POL-003", Status.UNVERIFIED, "m", unverified_fails_from_level=0)
    assert finding_row(plain) == ["TR-POL-003", "skip", "m"]
    assert finding_row(tight) == ["TR-POL-003", "unverified", "m", 0]
    assert finding_from_row(finding_row(plain)) == plain
    assert finding_from_row(finding_row(tight)) == tight
    for bad in (["c", "skip", "m", -1], ["c", "skip", "m", True], ["c", "skip", "m", "0"], ["c"]):
        with pytest.raises(ValueError):
            finding_from_row(bad)


@pytest.mark.parametrize("level", [0, 1, 2])
def test_run_level_tally_counts_an_uncompared_expectation(level):
    trace = trace_with(policy_uri=URI)
    results = run(trace, "trace", level, expected_policy_hash=EXPECTED_SHA384)
    pol = [f for f in results["TR-POL"] if f.code == "TR-POL-003"]
    assert len(pol) == 1 and finding_counts_as_level_failure(pol[0], level)


# --- the expectation is caller input --------------------------------------


@pytest.mark.parametrize(
    "bad",
    ["", "sha256:abc", "md5:" + "0" * 32, SHA256.upper(), SHA256 + "\n", 42],
    ids=["empty", "short", "md5", "uppercase", "newline", "int"],
)
def test_a_malformed_expectation_is_refused_by_every_entry_point(bad):
    with pytest.raises(ValueError, match="expected_policy_hash"):
        check(trace_with(policy_uri=URI), expected_policy_hash=bad)
    with pytest.raises(ValueError, match="expected_policy_hash"):
        run(trace_with(policy_uri=URI), "trace", 0, expected_policy_hash=bad)
    with pytest.raises(ValueError, match="expected_policy_hash"):
        _run_levels(trace_with(policy_uri=URI), "trace", (0,), expected_policy_hash=bad)


def test_no_expectation_is_the_previous_behaviour():
    trace = trace_with(policy_uri=URI)
    for policy_resolver in (None, offline, resolver({URI: BUNDLE}), resolver({URI: EXPECTED})):
        default = check(trace, policy_resolver=policy_resolver)
        explicit = check(trace, policy_resolver=policy_resolver, expected_policy_hash=None)
        assert default == explicit


# --- the CLI ---------------------------------------------------------------


def _cli(tmp_path: Path, vector: str, *extra: str):
    record = json.loads((VECTOR_DIR / vector).read_text(encoding="utf-8"))["record"]
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return CliRunner().invoke(
        main,
        [
            "verify",
            "--record",
            str(path),
            "--max-age",
            "3153600000",
            "--policy-dir",
            str(VECTOR_DIR),
            *extra,
        ],
    )


def test_the_cli_carries_the_expectation_to_tr_pol_003(tmp_path):
    vector = json.loads(
        (VECTOR_DIR / "13-expected-policy-differs.json").read_text(encoding="utf-8")
    )
    expected = vector["context"]["expected_policy_hash"]
    plain = _cli(tmp_path, "13-expected-policy-differs.json")
    held = _cli(tmp_path, "13-expected-policy-differs.json", "--expected-policy-hash", expected)
    assert "not the policy the verifier expects" not in plain.output
    assert "not the policy the verifier expects" in held.output


def test_the_cli_refuses_a_malformed_expectation(tmp_path):
    result = _cli(tmp_path, "02-resolved-and-matches.json", "--expected-policy-hash", "sha256:x")
    assert result.exit_code == 2
    assert "--expected-policy-hash" in result.output


def test_the_report_command_carries_the_expectation_too(tmp_path):
    vector = json.loads(
        (VECTOR_DIR / "13-expected-policy-differs.json").read_text(encoding="utf-8")
    )
    record = tmp_path / "record.json"
    record.write_text(json.dumps(vector["record"]), encoding="utf-8")
    outputs = {}
    for label, extra in (
        ("plain", []),
        ("held", ["--expected-policy-hash", vector["context"]["expected_policy_hash"]]),
    ):
        out = tmp_path / f"{label}.json"
        result = CliRunner().invoke(
            main,
            [
                "report",
                "--record",
                str(record),
                "--max-level",
                "0",
                "--max-age",
                "3153600000",
                "--policy-dir",
                str(VECTOR_DIR),
                "--json",
                str(out),
                *extra,
            ],
        )
        assert result.exit_code == 0, result.output
        outputs[label] = out.read_text(encoding="utf-8")
    assert "not the policy the verifier expects" not in outputs["plain"]
    assert "not the policy the verifier expects" in outputs["held"]

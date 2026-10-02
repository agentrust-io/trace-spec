"""Obligation accounting for the bounded three-obligation TRACE pilot.

The legacy runner remains the public findings path.  A private multi-level
entry point records the exact checker branches used by that runner and builds
one immutable accounting snapshot from the same traversal.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, NamedTuple, cast, overload

from trace_tests.modules import unverified as _contribution_policy
from trace_tests.result import Finding, Status

REGISTRY_ID = "agentrust-io/trace-tests/obligation-registry/pilot-1"
REGISTRY_SCHEMA = "agentrust-io/trace-tests/obligation-registry/1"
# This sentinel closes the declared three-obligation pilot. Branches, source
# locators, and checker bindings remain derived from executable checker specs.
_PILOT_OWNERS = (
    ("TR-APR-001", "TR-APR"),
    ("TR-POL-003", "TR-POL"),
    ("TR-SCA-002", "TR-SCA"),
)
_TRACE_TESTS_REPOSITORY = "https://github.com/agentrust-io/trace-tests"
_TRACE_SPEC_REPOSITORY = "https://github.com/agentrust-io/trace-spec"
_TRACE_SPEC_REVISION = "c111c2f0fc8df214fe9bc339769cf71d33a4af52"
_TRACE_SPEC_SCHEMA_PATH = "schema/trace-claim.json"
_TRACE_SPEC_TEXT_PATH = "spec/trace-v0.2.md"
_POLICY_CORRESPONDENCE_RULE = (
    "5. Policy hash matches the policy bundle the verifier expects."
)

# SHA-256 of the RFC 8785 bytes of the RFC 6901-resolved JSON value. Keep the
# manifest anchor independent from the locator constants used to construct the
# registry: editing a revision, repository, or path must not silently carry
# forward digests earned by a different pinned source.
_SOURCE_VALUE_MANIFEST_IDENTITY = (
    "https://github.com/agentrust-io/trace-spec",
    "c111c2f0fc8df214fe9bc339769cf71d33a4af52",
    "schema/trace-claim.json",
)
_SOURCE_VALUE_SHA256 = MappingProxyType(
    {
        "/required/8": "sha256:a7fe3dfe02e11f3334cdaeb057718697d00825596549db11c3510d84f0d928e1",
        "/properties/appraisal/type": (
            "sha256:626992da9517ee49930ee1340383a0cc334563d9aa429619a17842d0eeecb524"
        ),
        "/properties/appraisal/required/0": (
            "sha256:cfc31bcc34ed7f4cc7895026ae8a54f0494f73757e9f914d0f6ed90f9bc34f51"
        ),
        "/properties/appraisal/properties/status/enum": (
            "sha256:1150b2eb1c222f1b6d183a1e60848fee1542c3d287afb649996a9bdfdcf086b1"
        ),
        "/required/5": "sha256:17ad92e63c962393c0329c658937d16eccaea13036412a3d1d0a5b6b8f29d738",
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
        "/required/7": "sha256:e131727bb1bf583b7afc0a1850aa491d3ec4d251c42c381e4b42e05c1bc5d389",
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
)
_TEXT_SOURCE_VALUE_MANIFEST_IDENTITY = (
    "https://github.com/agentrust-io/trace-spec",
    "c111c2f0fc8df214fe9bc339769cf71d33a4af52",
    "spec/trace-v0.2.md",
)
_TEXT_SOURCE_VALUE_SHA256 = MappingProxyType(
    {
        _POLICY_CORRESPONDENCE_RULE: (
            "sha256:ea109c835a9f84804af8583d4ed6284c8a82afdd6ca05e45c2dd767d70024ba6"
        )
    }
)


class Applicability(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


class EvaluationState(StrEnum):
    COMPLETED = "completed"
    ATTEMPTED_UNRESOLVED = "attempted_unresolved"
    BLOCKED_BY_PREREQUISITE = "blocked_by_prerequisite"
    NOT_ATTEMPTED = "not_attempted"


class ProducerRole(StrEnum):
    TARGET_COMPLETED = "target_completed"
    TARGET_ATTEMPTED_UNRESOLVED = "target_attempted_unresolved"
    PREREQUISITE = "prerequisite"
    NOT_APPLICABLE = "not_applicable"
    NOT_ATTEMPTED = "not_attempted"
    SCHEDULER_NONEXECUTION_APPLICABLE = "scheduler_nonexecution_applicable"


class SourceLocator(NamedTuple):
    repository: str
    commit: str
    path: str
    fragment: str
    value_sha256: str


class CheckerBinding(NamedTuple):
    repository: str
    path: str
    module: str
    checker_symbol: str
    source_sha256: str


class BranchRule(NamedTuple):
    branch: str
    role: ProducerRole
    finding_code: str | None = None
    finding_statuses: tuple[Status, ...] = ()
    prerequisite_code: str | None = None
    prerequisite_statuses: tuple[Status, ...] = ()
    prerequisite_message_prefix: str | None = None


class ObligationSpec(NamedTuple):
    key: str
    owner: str
    normative_sources: tuple[SourceLocator, ...]
    checker_binding: CheckerBinding
    branches: tuple[BranchRule, ...]
    structural_sources: tuple[SourceLocator, ...] = ()


class AccountingRow(NamedTuple):
    attempted_level: int
    obligation_key: str
    applicability: Applicability
    evaluation_state: EvaluationState
    state_reason: str | None
    producer_branch: str
    prerequisite_code: str | None
    finding_code: str | None
    finding_status: Status | None
    counts_as_level_failure: bool | None


class _FindingWitness(NamedTuple):
    finding: Finding
    code: str
    status: Status
    message: str


class _ProducerFact(NamedTuple):
    level: int
    module: str
    branch: str
    finding: _FindingWitness | None
    counts_as_level_failure: bool | None


@dataclass(frozen=True)
class _FrozenContributionPolicy:
    evaluate: Callable[[Finding, int], bool]
    thresholds: tuple[tuple[str, int], ...]
    default: int


def _exact_execution_int(
    value: object,
    field: str,
    *,
    maximum: int | None = None,
) -> int:
    """Reject JSON booleans/floats before Python equality can treat them as integers."""
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise ValueError(f"invalid frozen execution integer: {field}")
    return value


@dataclass(frozen=True)
class _Execution:
    """One canonical snapshot containing both result and accounting views."""

    _payload: bytes

    def _value(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._payload))

    @property
    def record_bytes(self) -> bytes:
        return cast(str, self._value()["record"]).encode("ascii")

    @property
    def record_format(self) -> str:
        return cast(str, self._value()["record_format"])

    @property
    def compatibility_results(self) -> dict[int, dict[str, list[Finding]]]:
        results: dict[int, dict[str, list[Finding]]] = {}
        for raw_level, modules in self._value()["results"]:
            level = _exact_execution_int(raw_level, "results.level", maximum=2)
            if level in results:
                raise ValueError("duplicate frozen execution level")
            results[level] = {
                module: [Finding(code, Status(status), message) for code, status, message in items]
                for module, items in modules
            }
        return results

    @property
    def report_tallies(self) -> tuple[tuple[int, int, int], ...]:
        tallies = []
        for raw_level, raw_failures, raw_unverified in self._value()["report_tallies"]:
            tallies.append(
                (
                    _exact_execution_int(raw_level, "report_tallies.level", maximum=2),
                    _exact_execution_int(raw_failures, "report_tallies.failures"),
                    _exact_execution_int(raw_unverified, "report_tallies.unverified"),
                )
            )
        return tuple(tallies)

    @property
    def rows(self) -> tuple[AccountingRow, ...]:
        return tuple(
            AccountingRow(
                _exact_execution_int(
                    row["attempted_level"], "accounting.rows.attempted_level", maximum=2
                ),
                row["suite_obligation_key"],
                Applicability(row["applicability"]),
                EvaluationState(row["evaluation_state"]),
                row["state_reason"],
                row["producer_branch"],
                row["prerequisite_code"],
                row["observed_finding"]["code"] if row["observed_finding"] else None,
                Status(row["observed_finding"]["status"])
                if row["observed_finding"]
                else None,
                row["counts_as_level_failure"],
            )
            for row in self._value()["accounting"]["rows"]
        )

    def _accounting_document(self) -> dict[str, object]:
        return cast(dict[str, object], self._value()["accounting"])


@dataclass
class _Capture:
    record_bytes: bytes
    record_format: str
    levels: tuple[int, ...]
    specs: tuple[ObligationSpec, ...]
    planned_schedule: tuple[tuple[int, str], ...]
    registry_json: bytes
    contribution_policy: _FrozenContributionPolicy
    actual_schedule: list[tuple[int, str]]
    producers: list[_ProducerFact]
    returned: dict[tuple[int, str], tuple[_FindingWitness, ...]]
    current_level: int | None = None
    current_module: str | None = None


_CAPTURE: ContextVar[_Capture | None] = ContextVar("trace_accounting_capture", default=None)


@contextmanager
def _without_capture() -> Iterator[None]:
    """Keep a public runner invocation outside any caller's accounting run."""
    token = _CAPTURE.set(None)
    try:
        yield
    finally:
        _CAPTURE.reset(token)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=True
    ).encode("ascii")


def _normative_sources(*fragments: str) -> tuple[SourceLocator, ...]:
    sources = []
    source_identity = (
        _TRACE_SPEC_REPOSITORY,
        _TRACE_SPEC_REVISION,
        _TRACE_SPEC_SCHEMA_PATH,
    )
    if source_identity != _SOURCE_VALUE_MANIFEST_IDENTITY:
        raise ValueError(f"unbound normative source locator {source_identity!r}")
    for fragment in fragments:
        try:
            value_sha256 = _SOURCE_VALUE_SHA256[fragment]
        except KeyError as exc:
            raise ValueError(
                f"unbound normative source locator {source_identity + (fragment,)!r}"
            ) from exc
        sources.append(SourceLocator(*source_identity, fragment, value_sha256))
    return tuple(sources)


def _structural_sources(*fragments: str) -> tuple[SourceLocator, ...]:
    """Return schema sources that support shape but do not state an operational rule."""
    return _normative_sources(*fragments)


def _normative_text_sources(*exact_texts: str) -> tuple[SourceLocator, ...]:
    source_identity = (
        _TRACE_SPEC_REPOSITORY,
        _TRACE_SPEC_REVISION,
        _TRACE_SPEC_TEXT_PATH,
    )
    if source_identity != _TEXT_SOURCE_VALUE_MANIFEST_IDENTITY:
        raise ValueError(f"unbound normative source locator {source_identity!r}")
    sources = []
    for exact_text in exact_texts:
        try:
            value_sha256 = _TEXT_SOURCE_VALUE_SHA256[exact_text]
        except KeyError as exc:
            raise ValueError(
                f"unbound normative source locator {source_identity + (exact_text,)!r}"
            ) from exc
        sources.append(SourceLocator(*source_identity, exact_text, value_sha256))
    return tuple(sources)


def _checker_binding(module: str) -> CheckerBinding:
    module_name = module.lower().replace("-", "_")
    path = f"src/trace_tests/modules/{module_name}.py"
    source = Path(__file__).resolve().parent / "modules" / f"{module_name}.py"
    return CheckerBinding(
        _TRACE_TESTS_REPOSITORY,
        path,
        f"trace_tests.modules.{module_name}",
        "check",
        "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
    )


def _collect_specs() -> tuple[ObligationSpec, ...]:
    from trace_tests.modules import tr_apr, tr_pol, tr_sca

    return tr_apr._ACCOUNTING_SPEC, tr_pol._ACCOUNTING_SPEC, tr_sca._ACCOUNTING_SPEC


def _freeze_contribution_policy() -> _FrozenContributionPolicy:
    central = _contribution_policy._finding_counts_as_level_failure
    thresholds = tuple(sorted(_contribution_policy.UNVERIFIED_FAILS_FROM_LEVEL.items()))
    frozen_thresholds = dict(thresholds)
    default = _contribution_policy.DEFAULT_FAILS_FROM_LEVEL

    def frozen_unverified_fails(code: str, level: int) -> bool:
        return level >= frozen_thresholds.get(code, default)

    def evaluate(finding: Finding, level: int) -> bool:
        return central(finding, level, frozen_unverified_fails)

    return _FrozenContributionPolicy(evaluate, thresholds, default)


def _registry_body(
    specs: tuple[ObligationSpec, ...], policy: _FrozenContributionPolicy
) -> dict[str, object]:
    policy_path = Path(__file__).resolve().parent / "modules" / "unverified.py"
    return {
        "schema": REGISTRY_SCHEMA,
        "id": REGISTRY_ID,
        "contribution_policy": {
            "repository": _TRACE_TESTS_REPOSITORY,
            "path": "src/trace_tests/modules/unverified.py",
            "symbol": "finding_counts_as_level_failure",
            "source_sha256": "sha256:"
            + hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            "unverified_fails_from_level": dict(policy.thresholds),
            "default_fails_from_level": policy.default,
        },
        "obligations": [
            {
                "key": spec.key,
                "owner": spec.owner,
                "normative_sources": [
                    {
                        "repository": source.repository,
                        "commit": source.commit,
                        "path": source.path,
                        "locator_kind": (
                            "json_pointer"
                            if source.path.endswith(".json")
                            else "exact_text"
                        ),
                        "locator": source.fragment,
                        "value_sha256": source.value_sha256,
                    }
                    for source in spec.normative_sources
                ],
                "structural_sources": [
                    {
                        "repository": source.repository,
                        "commit": source.commit,
                        "path": source.path,
                        "locator_kind": "json_pointer",
                        "locator": source.fragment,
                        "value_sha256": source.value_sha256,
                    }
                    for source in spec.structural_sources
                ],
                "checker_binding": {
                    "repository": spec.checker_binding.repository,
                    "path": spec.checker_binding.path,
                    "module": spec.checker_binding.module,
                    "checker_symbol": spec.checker_binding.checker_symbol,
                    "source_sha256": spec.checker_binding.source_sha256,
                },
                "branches": [
                    {
                        "branch": rule.branch,
                        "role": rule.role.value,
                        "finding_code": rule.finding_code,
                        "finding_statuses": [
                            status.value for status in rule.finding_statuses
                        ],
                        "prerequisite_code": rule.prerequisite_code,
                        "prerequisite_statuses": [
                            status.value for status in rule.prerequisite_statuses
                        ],
                        "prerequisite_message_prefix": rule.prerequisite_message_prefix,
                    }
                    for rule in spec.branches
                ],
            }
            for spec in specs
        ],
    }


def _witness(finding: Finding) -> _FindingWitness:
    return _FindingWitness(finding, finding.code, finding.status, finding.message)


def _unchanged(witness: _FindingWitness, finding: Finding) -> bool:
    return (
        finding is witness.finding
        and finding.code == witness.code
        and finding.status is witness.status
        and finding.message == witness.message
    )


def _validate_returned(
    module: str,
    facts: tuple[_ProducerFact, ...],
    findings: list[Finding],
    pilot_code: str | None,
) -> None:
    for fact in facts:
        if fact.finding is None:
            continue
        if sum(item is fact.finding.finding for item in findings) != 1:
            raise RuntimeError(
                f"{module}/{fact.branch} did not return its exact earned Finding once"
            )
        if not _unchanged(fact.finding, fact.finding.finding):
            raise RuntimeError(f"{module}/{fact.branch} mutated its Finding after earning it")
    if pilot_code is not None:
        observed = [
            fact.finding.finding
            for fact in facts
            if fact.finding is not None and fact.finding.code == pilot_code
        ]
        returned = [finding for finding in findings if finding.code == pilot_code]
        if len(returned) != len(observed) or any(
            actual is not expected
            for actual, expected in zip(returned, observed, strict=True)
        ):
            raise RuntimeError(
                f"{module} returned an unearned or duplicate {pilot_code} Finding"
            )


@contextmanager
def _execution(
    record: dict[str, Any],
    record_format: str,
    levels: tuple[int, ...],
    planned_schedule: tuple[tuple[int, str], ...],
) -> Iterator[_Capture]:
    specs = _collect_specs()
    policy = _freeze_contribution_policy()
    body = _registry_body(specs, policy)
    registry = {
        **body,
        "sha256": "sha256:" + hashlib.sha256(_canonical_json(body)).hexdigest(),
    }
    capture = _Capture(
        _canonical_json(record),
        record_format,
        levels,
        specs,
        planned_schedule,
        _canonical_json(registry),
        policy,
        [],
        [],
        {},
    )
    token = _CAPTURE.set(capture)
    try:
        yield capture
    finally:
        _CAPTURE.reset(token)


def _validate_contribution_policy(capture: _Capture) -> None:
    if (
        capture.contribution_policy.thresholds
        != tuple(sorted(_contribution_policy.UNVERIFIED_FAILS_FROM_LEVEL.items()))
        or capture.contribution_policy.default
        != _contribution_policy.DEFAULT_FAILS_FROM_LEVEL
    ):
        raise RuntimeError("central #88 policy changed during execution")


def _begin_level(level: int) -> None:
    capture = _CAPTURE.get()
    if capture is None or capture.current_level is not None or level not in capture.levels:
        raise RuntimeError("invalid accounting level traversal")
    capture.current_level = level


def _end_level(level: int) -> None:
    capture = _CAPTURE.get()
    if capture is None or capture.current_level != level or capture.current_module is not None:
        raise RuntimeError("invalid accounting level completion")
    planned = tuple(cell for cell in capture.planned_schedule if cell[0] == level)
    actual = tuple(cell for cell in capture.actual_schedule if cell[0] == level)
    if actual != planned:
        raise RuntimeError(f"Level {level} execution did not match its scheduler plan")
    scheduled = {module for _, module in planned}
    for spec in capture.specs:
        if spec.owner not in scheduled:
            rules = tuple(
                rule
                for rule in spec.branches
                if rule.role is ProducerRole.SCHEDULER_NONEXECUTION_APPLICABLE
            )
            if len(rules) != 1:
                raise ValueError(f"{spec.key} requires exactly one scheduler nonexecution rule")
            capture.producers.append(
                _ProducerFact(level, spec.owner, rules[0].branch, None, None)
            )
    capture.current_level = None


@overload
def _observe(module: str, branch: str, finding: Finding) -> Finding: ...


@overload
def _observe(module: str, branch: str, finding: None = None) -> None: ...


def _observe(module: str, branch: str, finding: Finding | None = None) -> Finding | None:
    capture = _CAPTURE.get()
    if capture is not None:
        if capture.current_module != module or capture.current_level is None:
            raise RuntimeError(f"{module} produced accounting during another checker invocation")
        pilot_code = next(
            (spec.key for spec in capture.specs if spec.owner == module), None
        )
        if finding is not None and finding.code != pilot_code:
            raise RuntimeError(f"{module}/{branch} has no frozen #88 decision")
        if finding is not None:
            contribution = capture.contribution_policy.evaluate(finding, capture.current_level)
        else:
            contribution = None
        capture.producers.append(
            _ProducerFact(
                capture.current_level,
                module,
                branch,
                _witness(finding) if finding is not None else None,
                contribution,
            )
        )
    return finding


def _invoke(module: str, checker: Callable[[], list[Finding]]) -> list[Finding]:
    capture = _CAPTURE.get()
    if capture is None:
        return checker()
    if capture.current_level is None or capture.current_module is not None:
        raise RuntimeError("checker invoked outside one accounting scheduler cell")
    level = capture.current_level
    cell = level, module
    index = len(capture.actual_schedule)
    if index >= len(capture.planned_schedule) or capture.planned_schedule[index] != cell:
        raise RuntimeError(f"unexpected accounting scheduler cell {cell}")
    capture.actual_schedule.append(cell)
    capture.current_module = module
    start = len(capture.producers)
    try:
        findings = checker()
    finally:
        capture.current_module = None
    facts = tuple(capture.producers[start:])
    pilot_code = next((spec.key for spec in capture.specs if spec.owner == module), None)
    _validate_returned(module, facts, findings, pilot_code)
    capture.returned[cell] = tuple(_witness(finding) for finding in findings)
    return findings


def _role_projection(role: ProducerRole) -> tuple[Applicability, EvaluationState]:
    if role is ProducerRole.TARGET_COMPLETED:
        return Applicability.APPLICABLE, EvaluationState.COMPLETED
    if role is ProducerRole.TARGET_ATTEMPTED_UNRESOLVED:
        return Applicability.APPLICABLE, EvaluationState.ATTEMPTED_UNRESOLVED
    if role is ProducerRole.PREREQUISITE:
        return Applicability.APPLICABLE, EvaluationState.BLOCKED_BY_PREREQUISITE
    if role is ProducerRole.NOT_APPLICABLE:
        return Applicability.NOT_APPLICABLE, EvaluationState.COMPLETED
    if role in (
        ProducerRole.NOT_ATTEMPTED,
        ProducerRole.SCHEDULER_NONEXECUTION_APPLICABLE,
    ):
        return Applicability.APPLICABLE, EvaluationState.NOT_ATTEMPTED
    raise ValueError(f"unknown producer role {role!r}")


def _project(capture: _Capture) -> tuple[AccountingRow, ...]:
    rules = {
        (spec.owner, rule.branch): (spec, rule)
        for spec in capture.specs
        for rule in spec.branches
    }
    scheduled = set(capture.actual_schedule)
    selected: dict[tuple[int, str], list[tuple[_ProducerFact, BranchRule]]] = {
        (level, spec.key): [] for level in capture.levels for spec in capture.specs
    }
    for fact in capture.producers:
        matched = rules.get((fact.module, fact.branch))
        if matched is None:
            raise ValueError(f"unrecognised producer branch {fact.module}/{fact.branch}")
        spec, rule = matched
        scheduler_role = rule.role is ProducerRole.SCHEDULER_NONEXECUTION_APPLICABLE
        if ((fact.level, fact.module) in scheduled) == scheduler_role:
            raise ValueError(f"{fact.level}/{spec.key} branch contradicts actual scheduling")
        try:
            selected[(fact.level, spec.key)].append((fact, rule))
        except KeyError as exc:
            raise ValueError("producer lies outside the attempted schedule") from exc

    rows: list[AccountingRow] = []
    for level in capture.levels:
        for spec in sorted(capture.specs, key=lambda item: item.key):
            producers = selected[(level, spec.key)]
            if len(producers) != 1:
                raise ValueError(
                    f"{level}/{spec.key} has {len(producers)} recognised producers; "
                    "exactly one required"
                )
            fact, rule = producers[0]
            prerequisite_code = None
            if rule.role is ProducerRole.PREREQUISITE:
                if rule.prerequisite_code is None or not rule.prerequisite_statuses:
                    raise ValueError(
                        f"{level}/{spec.key}/{rule.branch} has no declared blocking prerequisite"
                    )
                witnesses = tuple(
                    witness
                    for witness in capture.returned[(level, spec.owner)]
                    if witness.code == rule.prerequisite_code
                )
                if (
                    len(witnesses) != 1
                    or witnesses[0].status not in rule.prerequisite_statuses
                    or rule.prerequisite_message_prefix is None
                    or not witnesses[0].message.startswith(
                        rule.prerequisite_message_prefix
                    )
                    or not capture.contribution_policy.evaluate(
                        Finding(
                            witnesses[0].code,
                            witnesses[0].status,
                            witnesses[0].message,
                        ),
                        level,
                    )
                ):
                    raise ValueError(
                        f"{level}/{spec.key}/{rule.branch} has no exact blocking "
                        "prerequisite finding"
                    )
                prerequisite_code = witnesses[0].code
            elif (
                rule.prerequisite_code is not None
                or rule.prerequisite_statuses
                or rule.prerequisite_message_prefix is not None
            ):
                raise ValueError(
                    f"{level}/{spec.key}/{rule.branch} declares a prerequisite "
                    "for a non-prerequisite role"
                )
            if rule.finding_code is None:
                if fact.finding is not None or fact.counts_as_level_failure is not None:
                    raise ValueError(
                        f"{level}/{spec.key}/{rule.branch} no-finding branch carried a finding "
                        "or contribution"
                    )
                code = None
                status = None
                contribution = None
            else:
                if (
                    fact.finding is None
                    or fact.finding.code != rule.finding_code
                    or fact.finding.status not in rule.finding_statuses
                    or type(fact.counts_as_level_failure) is not bool
                ):
                    raise ValueError(f"wrong finding for {level}/{spec.key}/{rule.branch}")
                code = fact.finding.code
                status = fact.finding.status
                contribution = fact.counts_as_level_failure
            applicability, state = _role_projection(rule.role)
            state_reason = (
                f"{spec.owner} is not scheduled at attempted Level {level}"
                if rule.role is ProducerRole.SCHEDULER_NONEXECUTION_APPLICABLE
                else None
            )
            rows.append(
                AccountingRow(
                    level,
                    spec.key,
                    applicability,
                    state,
                    state_reason,
                    fact.branch,
                    prerequisite_code,
                    code,
                    status,
                    contribution,
                )
            )
    return tuple(rows)


def _validate_final_results(
    capture: _Capture, results: dict[int, dict[str, list[Finding]]]
) -> None:
    planned_by_level = {
        level: tuple(
            module for cell_level, module in capture.planned_schedule if cell_level == level
        )
        for level in capture.levels
    }
    if tuple(results) != capture.levels or any(
        tuple(results[level]) != planned_by_level[level] for level in capture.levels
    ):
        raise RuntimeError("runner results do not match the witnessed module schedule")
    for level, modules in results.items():
        for module, findings in modules.items():
            facts = tuple(
                fact
                for fact in capture.producers
                if fact.level == level and fact.module == module
            )
            pilot_code = next(
                (spec.key for spec in capture.specs if spec.owner == module), None
            )
            _validate_returned(module, facts, findings, pilot_code)
            witnesses = capture.returned[(level, module)]
            if len(findings) != len(witnesses) or any(
                not _unchanged(witness, finding)
                for witness, finding in zip(witnesses, findings, strict=True)
            ):
                raise RuntimeError(f"{level}/{module} findings changed during execution")


def _complete_execution(
    capture: _Capture, results: dict[int, dict[str, list[Finding]]]
) -> _Execution:
    _validate_contribution_policy(capture)
    if (
        capture.current_level is not None
        or tuple(capture.actual_schedule) != capture.planned_schedule
    ):
        raise RuntimeError("executed module schedule does not match its runner plan")
    _validate_final_results(capture, results)
    rows = _project(capture)
    report_tallies = []
    for level in capture.levels:
        findings = [
            witness
            for (finding_level, _module), witnesses in capture.returned.items()
            if finding_level == level
            for witness in witnesses
        ]
        report_tallies.append(
            [
                level,
                sum(
                    capture.contribution_policy.evaluate(
                        Finding(witness.code, witness.status, witness.message), level
                    )
                    for witness in findings
                ),
                sum(witness.status is Status.UNVERIFIED for witness in findings),
            ]
        )
    results_document = [
        [
            level,
            [
                [
                    module,
                    [
                        [item.code, item.status.value, item.message]
                        for item in capture.returned[(level, module)]
                    ],
                ]
                for module in modules
            ],
        ]
        for level, modules in (
            (level, tuple(results[level])) for level in capture.levels
        )
    ]
    registry = json.loads(capture.registry_json)
    return _Execution(
        _canonical_json(
            {
                "record": capture.record_bytes.decode("ascii"),
                "record_format": capture.record_format,
                "results": results_document,
                "report_tallies": report_tallies,
                "accounting": {
                    "registry": registry,
                    "accounting_complete": True,
                    "rows": [_row_document(row) for row in rows],
                },
            }
        )
    )


def _row_document(row: AccountingRow) -> dict[str, object]:
    finding = (
        {"code": row.finding_code, "status": row.finding_status.value}
        if row.finding_code is not None and row.finding_status is not None
        else None
    )
    return {
        "attempted_level": row.attempted_level,
        "suite_obligation_key": row.obligation_key,
        "applicability": row.applicability.value,
        "evaluation_state": row.evaluation_state.value,
        "state_reason": row.state_reason,
        "producer_branch": row.producer_branch,
        "prerequisite_code": row.prerequisite_code,
        "observed_finding": finding,
        "counts_as_level_failure": row.counts_as_level_failure,
    }


def _frozen_policy_counts(
    finding: Finding, level: int, contribution_policy: dict[str, object]
) -> bool:
    thresholds = contribution_policy.get("unverified_fails_from_level")
    default = contribution_policy.get("default_fails_from_level")
    if not isinstance(thresholds, dict) or type(default) is not int:
        raise ValueError("invalid frozen contribution policy")
    if any(
        not isinstance(code, str) or type(value) is not int
        for code, value in thresholds.items()
    ):
        raise ValueError("invalid frozen contribution policy")
    if finding.failed():
        return True
    if finding.unverified():
        threshold = thresholds.get(finding.code, default)
        if type(threshold) is not int:
            raise ValueError("invalid frozen contribution policy")
        return level >= threshold
    return False


def _validate_document_relations(
    execution: _Execution,
    rows: tuple[AccountingRow, ...],
    registry: dict[str, object],
) -> None:
    obligations = registry.get("obligations")
    if not isinstance(obligations, list) or any(
        not isinstance(item, dict) for item in obligations
    ):
        raise ValueError("pilot registry does not match its rows")
    registry_identity = tuple(
        (item.get("key"), item.get("owner")) for item in obligations
    )
    if registry_identity != _PILOT_OWNERS:
        raise ValueError("pilot registry does not match its rows")

    results = execution.compatibility_results
    levels = tuple(results)
    tally_levels = tuple(level for level, _failures, _unverified in execution.report_tallies)
    if levels != tally_levels or levels not in ((0,), (0, 1), (0, 1, 2)):
        raise ValueError("frozen execution levels do not match report tallies")
    registry_keys = tuple(key for key, _owner in registry_identity)
    expected_cells = tuple((level, key) for level in levels for key in registry_keys)
    observed_cells = tuple((row.attempted_level, row.obligation_key) for row in rows)
    if observed_cells != expected_cells:
        raise ValueError("pilot registry does not match its rows")

    policy = registry.get("contribution_policy")
    if not isinstance(policy, dict):
        raise ValueError("invalid frozen contribution policy")
    rules: dict[tuple[str, str], dict[str, object]] = {}
    owners: dict[str, str] = {}
    for item in obligations:
        key = item["key"]
        owner = item["owner"]
        branches = item.get("branches")
        if (
            not isinstance(key, str)
            or not isinstance(owner, str)
            or not isinstance(branches, list)
        ):
            raise ValueError("invalid obligation registry")
        owners[key] = owner
        for branch in branches:
            if not isinstance(branch, dict) or not isinstance(
                branch.get("branch"), str
            ):
                raise ValueError("invalid obligation registry")
            identity = key, branch["branch"]
            if identity in rules:
                raise ValueError("duplicate obligation branch")
            rules[identity] = branch

    for row in rows:
        rule = rules.get((row.obligation_key, row.producer_branch))
        if rule is None:
            raise ValueError("accounting row names an unregistered branch")
        owner = owners[row.obligation_key]
        level_results = results.get(row.attempted_level)
        if not isinstance(level_results, dict):
            raise ValueError("accounting row lies outside frozen results")
        findings = level_results.get(owner, [])

        try:
            role = ProducerRole(cast(str, rule.get("role")))
            expected_applicability, expected_state = _role_projection(role)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid obligation branch role") from exc
        expected_reason = (
            f"{owner} is not scheduled at attempted Level {row.attempted_level}"
            if role is ProducerRole.SCHEDULER_NONEXECUTION_APPLICABLE
            else None
        )
        if (
            row.applicability is not expected_applicability
            or row.evaluation_state is not expected_state
            or row.state_reason != expected_reason
            or row.prerequisite_code != rule.get("prerequisite_code")
        ):
            raise ValueError("accounting row does not match its registered branch")

        registered_code = rule.get("finding_code")
        registered_statuses = rule.get("finding_statuses")
        if registered_code is None:
            if row.finding_code is not None or row.finding_status is not None:
                raise ValueError("accounting row does not match its registered branch")
            if row.counts_as_level_failure is not None:
                raise ValueError("accounting contribution does not match frozen policy")
            if row.prerequisite_code is not None:
                prerequisite_statuses = rule.get("prerequisite_statuses")
                prerequisite_prefix = rule.get("prerequisite_message_prefix")
                prerequisites = [
                    finding
                    for finding in findings
                    if finding.code == row.prerequisite_code
                ]
                if (
                    not isinstance(prerequisite_statuses, list)
                    or not isinstance(prerequisite_prefix, str)
                    or len(prerequisites) != 1
                    or prerequisites[0].status.value not in prerequisite_statuses
                    or not prerequisites[0].message.startswith(prerequisite_prefix)
                    or not _frozen_policy_counts(
                        prerequisites[0], row.attempted_level, policy
                    )
                ):
                    raise ValueError(
                        "accounting prerequisite does not match frozen results"
                    )
            elif owner in level_results:
                raise ValueError("scheduler nonexecution row contradicts frozen results")
            continue

        if not isinstance(registered_code, str) or not isinstance(
            registered_statuses, list
        ):
            raise ValueError("invalid obligation registry")
        matches = [finding for finding in findings if finding.code == registered_code]
        if (
            len(matches) != 1
            or row.finding_code != matches[0].code
            or row.finding_status is not matches[0].status
        ):
            raise ValueError("accounting row does not match its finding")
        if row.finding_status.value not in registered_statuses:
            raise ValueError("accounting row does not match its registered branch")
        expected_contribution = _frozen_policy_counts(
            matches[0], row.attempted_level, policy
        )
        if row.counts_as_level_failure is not expected_contribution:
            raise ValueError("accounting contribution does not match frozen policy")

    expected_tallies = []
    for level, modules in results.items():
        findings = [
            finding
            for module_findings in modules.values()
            for finding in module_findings
        ]
        expected_tallies.append(
            (
                level,
                sum(
                    _frozen_policy_counts(finding, level, policy)
                    for finding in findings
                ),
                sum(finding.unverified() for finding in findings),
            )
        )
    if execution.report_tallies != tuple(expected_tallies):
        raise ValueError("report tallies do not match frozen results")


def _accounting_document(execution: _Execution) -> dict[str, object]:
    """Return the validated bounded accounting projection used by the JSON report."""
    document = execution._accounting_document()
    rows = execution.rows
    levels = tuple(execution.compatibility_results)
    tally_levels = tuple(level for level, _failures, _unverified in execution.report_tallies)
    expected = tuple((level, key) for level in levels for key, _owner in _PILOT_OWNERS)
    observed = tuple((row.attempted_level, row.obligation_key) for row in rows)
    if (
        set(document) != {"registry", "accounting_complete", "rows"}
        or document["accounting_complete"] is not True
        or levels != tally_levels
        or levels not in ((0,), (0, 1), (0, 1, 2))
        or observed != expected
    ):
        raise ValueError("incomplete obligation accounting")
    registry = document["registry"]
    if not isinstance(registry, dict) or set(registry) != {
        "schema",
        "id",
        "contribution_policy",
        "obligations",
        "sha256",
    }:
        raise ValueError("invalid obligation registry")
    body = {key: value for key, value in registry.items() if key != "sha256"}
    digest = "sha256:" + hashlib.sha256(_canonical_json(body)).hexdigest()
    if registry["schema"] != REGISTRY_SCHEMA or registry["id"] != REGISTRY_ID:
        raise ValueError("unexpected obligation registry")
    if registry["sha256"] != digest:
        raise ValueError("obligation registry hash mismatch")
    _validate_document_relations(execution, rows, registry)
    return document

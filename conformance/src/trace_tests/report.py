"""Conformance results as an artifact somebody can hand to somebody else.

A pass/fail in a terminal is useful to the person who ran it and to nobody else.
What an enterprise needs is something it can give an auditor, a counterparty or
an acquirer: which level the record reaches, which checks failed and why, and
enough detail for the reader to run the check themselves rather than believe it.

**What this report is not.** It is not evidence. It is HTML and JSON, unsigned,
and anyone can edit either. The evidence is the Trust Record; this is a rendering
of what one particular run of one particular suite version concluded about it.
That is why every report carries the record's digest, the suite and library
versions, and the exact command to reproduce it: so a reader who does not trust
the sender can stop reading the report and go check the record.

Saying so on the artifact matters more here than anywhere else in this project.
A conformance report that looks authoritative and cannot be checked is the same
shape of thing as a control plane writing its own log.
"""

from __future__ import annotations

import hashlib
import html
import json
from dataclasses import dataclass, replace
from typing import Any

from trace_tests import accounting
from trace_tests.modules.unverified import finding_counts_as_level_failure
from trace_tests.result import Finding, Status

__all__ = [
    "LEVEL_NAMES",
    "ReportData",
    "badge_svg",
    "build",
    "record_digest",
    "to_html",
    "to_json",
]

LEVEL_NAMES = {
    0: "Software-only",
    1: "TEE-attested",
    2: "Transparency-anchored",
}

ACCOUNTING_REPORT_SCHEMA = "agentrust-io/trace-tests/obligation-accounting/1"

#: Modules introduced at each level, for the per-level breakdown.
LEVEL_MODULES = {
    0: ("TR-ENV", "TR-SIG", "TR-POL"),
    1: ("TR-RTE", "TR-SCA"),
    2: ("TR-TXN", "TR-ANC"),
}


def record_digest(record: dict[str, Any]) -> str:
    """Digest of the record this report describes.

    Sorted-key JSON, matching the registry anchor's canonicalization rather than
    RFC 8785, because this is an identifier for a reader to compare against, not
    a signature pre-image. The distinction is spelled out in the anchor format
    specification, section 0; getting it backwards here would be harmless but
    confusing, so the choice is stated rather than left implicit.
    """
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class LevelOutcome:
    level: int
    attempted: bool
    passed: bool
    failures: int
    unverified: int


@dataclass(frozen=True)
class ReportData:
    """Everything the renderers need. Deliberately a plain structure.

    ``build`` preserves the legacy mutable projections. The private accounted
    builder seals one semantic snapshot at the CLI boundary, so later mutation
    cannot make JSON, HTML, badge, highest level, and verdict disagree.
    """

    record_path: str
    record_format: str
    digest: str
    suite_version: str
    library_version: str | None
    generated_at: str
    levels: list[LevelOutcome]
    findings: dict[int, dict[str, list[Finding]]]
    transparency: str | None
    _obligation_accounting_json: bytes | None = None
    _accounted_snapshot: bytes | None = None

    @property
    def highest_level(self) -> int | None:
        """Highest level that passed, or ``None`` when the record fails Level 0."""
        if self._accounted_snapshot is not None:
            return _snapshot_view(self).highest_level
        passed = [lv.level for lv in self.levels if lv.attempted and lv.passed]
        return max(passed) if passed else None

    @property
    def verdict(self) -> str:
        if self._accounted_snapshot is not None:
            return _snapshot_view(self).verdict
        top = self.highest_level
        if top is None:
            return "FAIL at Level 0"
        return f"Level {top} — {LEVEL_NAMES[top]}"


def _tally(results: dict[str, list[Finding]], level: int) -> tuple[int, int]:
    failures = sum(
        1
        for findings in results.values()
        for finding in findings
        if finding_counts_as_level_failure(finding, level)
    )
    unverified_findings = [f for fs in results.values() for f in fs if f.unverified()]
    # Mirrors the CLI: an unverified finding is a failure from the level its code
    # is registered at. A report that called such a record "PASS" at a level that
    # required the check would be worse than no report. Per-code rather than
    # blanket; an unregistered code fails from level 1, as the blanket rule did.
    return failures, len(unverified_findings)


def _assemble(
    *,
    record: dict[str, Any],
    record_path: str,
    record_format: str,
    results_by_level: dict[int, dict[str, list[Finding]]],
    levels: list[LevelOutcome],
    suite_version: str,
    library_version: str | None,
    generated_at: str,
) -> ReportData:
    trace = record.get("trace", record)
    return ReportData(
        record_path=record_path,
        record_format=record_format,
        digest=record_digest(record),
        suite_version=suite_version,
        library_version=library_version,
        generated_at=generated_at,
        levels=levels,
        findings=results_by_level,
        transparency=trace.get("transparency"),
    )


def build(
    *,
    record: dict[str, Any],
    record_path: str,
    record_format: str,
    results_by_level: dict[int, dict[str, list[Finding]]],
    suite_version: str,
    library_version: str | None,
    generated_at: str,
) -> ReportData:
    levels = []
    for level in sorted(results_by_level):
        failures, unverified = _tally(results_by_level[level], level)
        levels.append(
            LevelOutcome(
                level=level,
                attempted=True,
                passed=failures == 0,
                failures=failures,
                unverified=unverified,
            )
        )
    return _assemble(
        record=record,
        record_path=record_path,
        record_format=record_format,
        results_by_level=results_by_level,
        levels=levels,
        suite_version=suite_version,
        library_version=library_version,
        generated_at=generated_at,
    )


def _freeze_semantics(data: ReportData) -> bytes:
    return json.dumps(
        {
            "record_path": data.record_path,
            "record_format": data.record_format,
            "digest": data.digest,
            "suite_version": data.suite_version,
            "library_version": data.library_version,
            "generated_at": data.generated_at,
            "levels": [
                [level.level, level.attempted, level.passed, level.failures, level.unverified]
                for level in data.levels
            ],
            "findings": [
                [
                    level,
                    [
                        [
                            module,
                            [
                                [finding.code, finding.status.value, finding.message]
                                for finding in findings
                            ],
                        ]
                        for module, findings in results.items()
                    ],
                ]
                for level, results in sorted(data.findings.items())
            ],
            "transparency": data.transparency,
            "obligation_accounting": (
                json.loads(data._obligation_accounting_json)
                if data._obligation_accounting_json is not None
                else None
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=True,
    ).encode("ascii")


def _snapshot_view(data: ReportData) -> ReportData:
    if data._accounted_snapshot is None:
        return data
    value = json.loads(data._accounted_snapshot)
    obligation_accounting = value["obligation_accounting"]
    return ReportData(
        record_path=value["record_path"],
        record_format=value["record_format"],
        digest=value["digest"],
        suite_version=value["suite_version"],
        library_version=value["library_version"],
        generated_at=value["generated_at"],
        levels=[LevelOutcome(*level) for level in value["levels"]],
        findings={
            level: {
                module: [
                    Finding(code, Status(status), message) for code, status, message in findings
                ]
                for module, findings in modules
            }
            for level, modules in value["findings"]
        },
        transparency=value["transparency"],
        _obligation_accounting_json=(
            json.dumps(
                obligation_accounting,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            if obligation_accounting is not None
            else None
        ),
    )


def _build_from_execution(
    *,
    record: dict[str, Any],
    record_path: str,
    execution: accounting._Execution,
    suite_version: str,
    library_version: str | None,
    generated_at: str,
) -> ReportData:
    """Build a report whose findings and accounting share one execution."""
    record_bytes = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=True
    ).encode("ascii")
    if record_bytes != execution.record_bytes:
        raise ValueError("report record does not match its accounting execution")
    document = accounting._accounting_document(execution)
    registry = document["registry"]
    if not isinstance(registry, dict):
        raise ValueError("report execution carries no obligation registry")
    extension = {
        "schema": ACCOUNTING_REPORT_SCHEMA,
        "registry_id": registry["id"],
        "registry_sha256": registry["sha256"],
        **document,
    }
    results = execution.compatibility_results
    tallies = execution.report_tallies
    if tuple(level for level, _failures, _unverified in tallies) != tuple(results):
        raise ValueError("report tallies do not match the accounting execution")
    levels = [
        LevelOutcome(
            level=level,
            attempted=True,
            passed=failures == 0,
            failures=failures,
            unverified=unverified,
        )
        for level, failures, unverified in tallies
    ]
    built = _assemble(
        record=record,
        record_path=record_path,
        record_format=execution.record_format,
        results_by_level=results,
        levels=levels,
        suite_version=suite_version,
        library_version=library_version,
        generated_at=generated_at,
    )
    accounted = replace(
        built,
        _obligation_accounting_json=json.dumps(
            extension, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii"),
    )
    return replace(accounted, _accounted_snapshot=_freeze_semantics(accounted))


def to_json(data: ReportData) -> str:
    """Machine-readable form, for CI gates and dashboards."""
    data = _snapshot_view(data)
    document = {
        "schema": "agentrust-io/trace-tests/report/1",
        "record": {
            "path": data.record_path,
            "format": data.record_format,
            "digest": data.digest,
            "transparency": data.transparency,
        },
        "tooling": {
            "suite": data.suite_version,
            "library": data.library_version,
        },
        "generated_at": data.generated_at,
        "verdict": data.verdict,
        "highest_level_passed": data.highest_level,
        "levels": [
            {
                "level": lv.level,
                "name": LEVEL_NAMES[lv.level],
                "passed": lv.passed,
                "failures": lv.failures,
                "unverified": lv.unverified,
            }
            for lv in data.levels
        ],
        "findings": [
            {
                "level": level,
                "module": module,
                "code": f.code,
                "status": str(f.status),
                "message": f.message,
            }
            for level, results in sorted(data.findings.items())
            for module, fs in results.items()
            for f in fs
        ],
        # Stated in the artifact, not only in the docs.
        "disclaimer": (
            "This report is a rendering of one run of one suite version. It is "
            "not signed and carries no authority of its own. The evidence is the "
            "Trust Record identified by the digest above; re-run the suite to "
            "check this report rather than trusting it."
        ),
    }
    if data._obligation_accounting_json is not None:
        document["obligation_accounting"] = json.loads(data._obligation_accounting_json)
    return json.dumps(
        document,
        indent=2,
        sort_keys=False,
    )


_BADGE_COLOURS = {
    None: "#9f1239",  # fails Level 0
    0: "#a16207",
    1: "#1d4ed8",
    2: "#15803d",
}


def badge_svg(data: ReportData) -> str:
    """A shields-style badge. Static SVG, no network, no third-party endpoint.

    Deliberately not served from a badge service: a badge that resolves through
    someone else's infrastructure adds a dependency to an artifact whose point is
    that it needs none.
    """
    data = _snapshot_view(data)
    top = data.highest_level
    right = "fails Level 0" if top is None else f"Level {top}"
    colour = _BADGE_COLOURS[top]
    left = "TRACE"
    lw = 6 * len(left) + 20
    rw = 6 * len(right) + 20
    total = lw + rw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{html.escape(left)}: {html.escape(right)}">'
        f"<title>{html.escape(left)}: {html.escape(right)}</title>"
        f'<rect width="{lw}" height="20" fill="#444"/>'
        f'<rect x="{lw}" width="{rw}" height="20" fill="{colour}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2}" y="14" text-anchor="middle">{html.escape(left)}</text>'
        f'<text x="{lw + rw / 2}" y="14" text-anchor="middle">{html.escape(right)}</text>'
        f"</g></svg>"
    )


_STATUS_CLASS = {
    Status.PASS: "pass",
    Status.FAIL: "fail",
    Status.SKIP: "skip",
    Status.UNVERIFIED: "unver",
}

_CSS = """
:root{--bg:#fff;--fg:#111;--mut:#555;--line:#e3e3e3;--pass:#15803d;--fail:#9f1239;
--skip:#6b7280;--unver:#a16207;--card:#fafafa}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--fg:#e8e8e8;--mut:#9aa0a6;
--line:#2a2f36;--card:#171b20}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:52rem;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .25rem}
h2{font-size:1.05rem;margin:2rem 0 .5rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
.sub{color:var(--mut);font-size:.85rem;margin:0 0 1.25rem}
.verdict{font-size:1.25rem;font-weight:600;padding:.85rem 1rem;border:1px solid var(--line);
border-radius:6px;background:var(--card);margin:0 0 1rem}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.03em}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;word-break:break-all}
.pass{color:var(--pass);font-weight:600}
.fail{color:var(--fail);font-weight:600}
.skip{color:var(--skip)}
.unver{color:var(--unver);font-weight:600}
.note{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--unver);
border-radius:4px;padding:.8rem 1rem;font-size:.88rem;color:var(--mut);margin:1.5rem 0}
.note strong{color:var(--fg)}
pre{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:.7rem .9rem;
overflow-x:auto;font-size:.82rem}
"""


def to_html(data: ReportData) -> str:
    """Self-contained HTML. No external CSS, no fonts, no scripts, no network."""
    data = _snapshot_view(data)
    e = html.escape
    top = data.highest_level

    rows = []
    for lv in data.levels:
        status = "PASS" if lv.passed else "FAIL"
        cls = "pass" if lv.passed else "fail"
        detail = "" if lv.passed else f"{lv.failures} failure(s)"
        if lv.unverified:
            detail += f"{', ' if detail else ''}{lv.unverified} unverified"
        rows.append(
            f"<tr><td>Level {lv.level}</td><td>{e(LEVEL_NAMES[lv.level])}</td>"
            f'<td class="{cls}">{status}</td><td>{e(detail)}</td></tr>'
        )

    finding_rows = []
    for level, results in sorted(data.findings.items()):
        for module, fs in results.items():
            for f in fs:
                if f.passed() and top is not None and level < (top or 0):
                    continue  # keep the table readable: passes at lower levels are implied
                cls = _STATUS_CLASS[f.status]
                finding_rows.append(
                    f"<tr><td>L{level}</td><td class='mono'>{e(module)}</td>"
                    f"<td class='mono'>{e(f.code)}</td>"
                    f"<td class='{cls}'>{e(str(f.status).upper())}</td>"
                    f"<td>{e(f.message)}</td></tr>"
                )

    # The record's own value, which TR-ANC-001 may have failed for not being a
    # string; html.escape takes only a str.
    shown = data.transparency
    if not isinstance(shown, str):
        shown = json.dumps(shown, ensure_ascii=True)
    anchor = (
        f"<tr><th>Transparency anchor</th><td class='mono'>{e(shown)}</td></tr>"
        if data.transparency
        else "<tr><th>Transparency anchor</th><td>none — record is unanchored</td></tr>"
    )

    lib = e(data.library_version) if data.library_version else "not installed"
    reproduce = (
        f"pip install agentrust-trace-tests=={e(data.suite_version)}\n"
        f"trace-tests verify --record &lt;your copy&gt; --level {top if top is not None else 0}"
        + (" --expected-nonce &lt;verifier challenge&gt;" if top is not None and top >= 1 else "")
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TRACE Conformance Report — {e(data.verdict)}</title>
<style>{_CSS}</style></head><body><main>
<h1>TRACE Conformance Report</h1>
<p class="sub">Generated {e(data.generated_at)} · suite {e(data.suite_version)}
 · authoring library {lib}</p>

<p class="verdict">{e(data.verdict)}</p>
<p>{badge_svg(data)}</p>

<h2>Record</h2>
<table>
<tr><th>Source</th><td class="mono">{e(data.record_path)}</td></tr>
<tr><th>Format</th><td class="mono">{e(data.record_format)}</td></tr>
<tr><th>Digest</th><td class="mono">{e(data.digest)}</td></tr>
{anchor}
</table>

<h2>Levels</h2>
<table><tr><th>Level</th><th>Name</th><th>Result</th><th>Detail</th></tr>
{"".join(rows)}
</table>

<h2>Findings</h2>
<table><tr><th>Level</th><th>Module</th><th>Code</th><th>Status</th><th>Detail</th></tr>
{"".join(finding_rows) or '<tr><td colspan="5">No findings.</td></tr>'}
</table>

<div class="note">
<strong>This report is not evidence.</strong> It is unsigned HTML describing one run of
one suite version. The evidence is the Trust Record with the digest above. A reader who
does not trust whoever sent this should not trust the report either — take the record and
run the suite:
<pre>{reproduce}</pre>
Compare the digest you compute against the one in this table. If they differ, you are
looking at a different record than this report describes.
</div>

</main></body></html>
"""

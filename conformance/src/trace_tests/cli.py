"""trace-tests CLI."""

from __future__ import annotations

import datetime as _dt
import importlib.metadata
import pathlib
import re
import sys
from collections.abc import Callable
from typing import Any

import click

from trace_tests import __version__
from trace_tests import report as report_mod
from trace_tests.loader import LoadError, load_record, loads_strict
from trace_tests.modules.tr_env import DEFAULT_MAX_AGE_SECONDS
from trace_tests.modules.unverified import finding_counts_as_level_failure
from trace_tests.result import Status
from trace_tests.runner import _run_levels, run


def _library_version() -> str | None:
    """Version of the authoring library, when it is installed alongside the suite.

    Recorded on the report because the two cut over to the v0.2 profile together
    and neither dual-accepts, so a mismatched pair produces a confident failure on
    a record that is fine. A reader of the report should be able to see the pair.
    """
    try:
        return importlib.metadata.version("agentrust-trace")
    except importlib.metadata.PackageNotFoundError:
        return None


def _fmt_status(status: Status) -> str:
    return status.value.upper().ljust(10)


def _print_report(path: str, fmt: str, level: int, results: dict[str, list[Any]]) -> int:
    """Print the conformance report and return exit code (0=pass, 1=fail)."""
    click.echo(f"\nTRACE Conformance Report -- Level {level}")
    click.echo(f"Format : {fmt}")
    click.echo(f"Record : {path}")
    click.echo("")

    failures = 0
    skips = 0
    passes = 0
    unverified = 0
    for module, findings in results.items():
        for f in findings:
            prefix = _fmt_status(f.status)
            click.echo(f"  {module}  {prefix}  {f.message}")
            counts_as_failure = finding_counts_as_level_failure(f, level)
            failures += int(counts_as_failure)
            if f.passed():
                passes += 1
            elif f.unverified():
                unverified += 1
            elif f.skipped():
                skips += 1

    # Contribution is projected exactly once per finding above. Status counters
    # remain presentation data and must not independently decide the verdict.
    total = sum(len(findings) for findings in results.values())
    click.echo("")
    if failures == 0:
        if unverified:
            click.echo(
                f"Result: PASS  ({total} checks, {skips} skipped, {unverified} UNVERIFIED "
                f"-- {unverified} check(s) could not be executed against the evidence "
                f"this record cites)"
            )
        else:
            click.echo(f"Result: PASS  ({total} checks, {skips} skipped)")
        return 0
    else:
        click.echo(f"Result: FAIL  ({total} checks, {failures} failure(s), {skips} skipped)")
        return 1



def _load_receipt(path: str | None) -> dict | None:
    """Load and shape-check an anchor receipt, or return None when not supplied."""
    if path is None:
        return None
    try:
        with open(path, "rb") as fh:
            data = loads_strict(fh.read())
    except OSError as exc:
        click.echo(f"Error: cannot read receipt {path}: {exc}", err=True)
        sys.exit(2)
    except LoadError as exc:
        click.echo(f"Error: receipt {path} is not valid JSON: {exc}", err=True)
        sys.exit(2)
    if not isinstance(data, dict):
        click.echo(
            f"Error: receipt {path} must be a JSON object, got {type(data).__name__}",
            err=True,
        )
        sys.exit(2)
    return data


def _load_policy_resolver(policy_dir: str | None) -> Callable[[str], bytes] | None:
    """Build a policy-bundle resolver from DIR/resolutions.json, or None when not supplied.

    The manifest is checked for *form* only: an object, string to string,
    relative paths, no parent traversal. Whether a mapped file is actually
    there is deliberately not checked here. Existence is a resolve-time fact,
    and a manifest that refused to load because one bundle had gone missing
    would be the manifest-level version of treating a lost referent as a wrong
    reference, which is the confusion TR-POL-003 exists to keep apart. A
    missing file surfaces as an unverified finding for the record that cites
    it, and leaves every other record in the run readable.
    """
    if policy_dir is None:
        return None
    root = pathlib.Path(policy_dir)
    manifest_path = root / "resolutions.json"
    try:
        with open(manifest_path, "rb") as fh:
            data = loads_strict(fh.read())
    except OSError as exc:
        click.echo(f"Error: cannot read policy manifest {manifest_path}: {exc}", err=True)
        sys.exit(2)
    except LoadError as exc:
        click.echo(f"Error: policy manifest {manifest_path} is not valid JSON: {exc}", err=True)
        sys.exit(2)
    if not isinstance(data, dict):
        click.echo(
            f"Error: policy manifest {manifest_path} must be a JSON object, "
            f"got {type(data).__name__}",
            err=True,
        )
        sys.exit(2)
    for uri, rel in data.items():
        if not isinstance(rel, str):
            click.echo(
                f"Error: policy manifest {manifest_path} maps {uri!r} to "
                f"{type(rel).__name__}, expected a relative path string",
                err=True,
            )
            sys.exit(2)
        if _is_unsafe_relative(rel):
            click.echo(
                f"Error: policy manifest {manifest_path} maps {uri!r} to {rel!r}; "
                "entries must be relative paths inside the directory, with no "
                "parent traversal",
                err=True,
            )
            sys.exit(2)

    def _resolve(uri: str) -> bytes:
        # A URI the manifest does not hold raises, exactly as a fetch would;
        # so does a mapped file that is not there. Both reach TR-POL-003 as
        # unverified, and the message carries which happened.
        return (root / data[uri]).read_bytes()

    return _resolve


def _is_unsafe_relative(rel: str) -> bool:
    """True when *rel* escapes the manifest's own directory, or tries to."""
    if not rel or rel.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", rel):
        return True
    return ".." in pathlib.PurePosixPath(rel.replace("\\", "/")).parts

@click.group()
@click.version_option(__version__)
def main() -> None:
    """TRACE conformance test suite."""


@main.command()
@click.option("--record", required=True, type=click.Path(), help="Path to the trust record (JSON)")
@click.option(
    "--level",
    default=0,
    type=click.IntRange(0, 2),
    show_default=True,
    help="Conformance level to check (0, 1, or 2)",
)
@click.option(
    "--max-age",
    "max_age",
    default=DEFAULT_MAX_AGE_SECONDS,
    type=click.IntRange(min=1),
    show_default=True,
    help="Maximum allowed record age in seconds (iat freshness window)",
)
@click.option(
    "--expected-nonce",
    default=None,
    help="Verifier-issued challenge nonce; required for Level 1 and Level 2.",
)
@click.option(
    "--receipt",
    default=None,
    type=click.Path(),
    help=(
        "Path to the anchor receipt (JSON) proving the record is included in the "
        "transparency log. Required for TR-ANC-002 at Level 2: the transparency URI "
        "says where the anchor lives, the receipt is what proves the record is in it."
    ),
)
@click.option(
    "--policy-dir",
    "policy_dir",
    default=None,
    type=click.Path(),
    help=(
        "Directory holding resolutions.json, a map from policy_uri to a relative "
        "path inside it. Supplying it lets TR-POL-003 resolve policy.policy_uri and "
        "compare the bundle against policy.bundle_hash; without it that check skips."
    ),
)
def verify(
    record: str,
    level: int,
    max_age: int,
    expected_nonce: str | None,
    receipt: str | None,
    policy_dir: str | None,
) -> None:
    """Verify a TRACE trust record against the conformance suite."""
    try:
        data, fmt = load_record(record)
    except LoadError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    receipt_data = _load_receipt(receipt)
    policy_resolver = _load_policy_resolver(policy_dir)

    results = run(
        data,
        fmt,
        level,
        max_age_seconds=max_age,
        expected_nonce=expected_nonce,
        receipt=receipt_data,
        policy_resolver=policy_resolver,
    )
    exit_code = _print_report(record, fmt, level, results)
    sys.exit(exit_code)


@main.command()
@click.option("--record", required=True, type=click.Path(), help="Path to the trust record (JSON)")
@click.option(
    "--max-level",
    default=2,
    type=click.IntRange(0, 2),
    show_default=True,
    help="Highest level to attempt; every level up to it is run",
)
@click.option(
    "--max-age",
    "max_age",
    default=DEFAULT_MAX_AGE_SECONDS,
    type=click.IntRange(min=1),
    show_default=True,
    help="Maximum allowed record age in seconds (iat freshness window)",
)
@click.option(
    "--html", "html_out", type=click.Path(), help="Write a self-contained HTML report here"
)
@click.option(
    "--json", "json_out", type=click.Path(), help="Write the machine-readable report here"
)
@click.option("--badge", "badge_out", type=click.Path(), help="Write a level badge (SVG) here")
@click.option(
    "--fail-under",
    type=click.IntRange(0, 2),
    help="Exit non-zero unless the record reaches this level. Omit to always exit 0, "
    "which is what you want when generating an artifact rather than gating on one.",
)
@click.option(
    "--expected-nonce",
    default=None,
    help="Verifier-issued challenge nonce; required for Level 1 and Level 2.",
)
@click.option(
    "--receipt",
    default=None,
    type=click.Path(),
    help="Path to the anchor receipt (JSON). Required for TR-ANC-002 at Level 2.",
)
@click.option(
    "--policy-dir",
    "policy_dir",
    default=None,
    type=click.Path(),
    help="Directory holding resolutions.json, a map from policy_uri to a relative "
    "path inside it. Required for TR-POL-003 to resolve the bundle; without it "
    "that check skips.",
)
def report(
    record: str,
    max_level: int,
    max_age: int,
    html_out: str | None,
    json_out: str | None,
    badge_out: str | None,
    fail_under: int | None,
    expected_nonce: str | None,
    receipt: str | None,
    policy_dir: str | None,
) -> None:
    """Produce a conformance report you can hand to someone else.

    Runs every level up to --max-level rather than one, because the useful answer
    for a reader is the highest level the record reaches, not whether it cleared
    the single level the person running the tool happened to pick.
    """
    try:
        data, fmt = load_record(record)
    except LoadError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    receipt_data = _load_receipt(receipt)
    policy_resolver = _load_policy_resolver(policy_dir)

    execution = _run_levels(
        data,
        fmt,
        range(max_level + 1),
        max_age_seconds=max_age,
        expected_nonce=expected_nonce,
        receipt=receipt_data,
        policy_resolver=policy_resolver,
    )

    built = report_mod._build_from_execution(
        record=data,
        record_path=record,
        execution=execution,
        suite_version=__version__,
        library_version=_library_version(),
        generated_at=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    wrote = []
    for path, render in (
        (html_out, report_mod.to_html),
        (json_out, report_mod.to_json),
        (badge_out, report_mod.badge_svg),
    ):
        if path:
            pathlib.Path(path).write_text(render(built), encoding="utf-8")
            wrote.append(path)

    click.echo(f"TRACE Conformance Report -- {built.verdict}")
    click.echo(f"Record : {record}")
    click.echo(f"Digest : {built.digest}")
    for lv in built.levels:
        mark = "PASS" if lv.passed else "FAIL"
        click.echo(f"  Level {lv.level}  {mark}")
    for path in wrote:
        click.echo(f"Wrote  : {path}")
    if not wrote:
        click.echo("")
        click.echo(report_mod.to_json(built))

    if fail_under is not None:
        top = built.highest_level
        if top is None or top < fail_under:
            click.echo(f"Result: below the required Level {fail_under}", err=True)
            sys.exit(1)


if __name__ == "__main__":
    main()

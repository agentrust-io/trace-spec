"""Conformance finding types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Status(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    # The check could not be executed against the evidence the record cites.
    # Distinct from SKIP so callers can never mistake an unverified check for a
    # benign omission. Whether it fails the run is per-code, from the table in
    # modules/unverified.py, rather than one rule over every unverified finding.
    UNVERIFIED = "unverified"


@dataclass
class Finding:
    code: str
    status: Status
    message: str
    #: Lowest level at which this one unverified finding fails the run, when it
    #: must fail earlier than its code's registered threshold. It can only
    #: tighten that threshold, never relax it, and it is None for every finding
    #: whose meaning the per-code table already captures. TR-POL-003 sets it to
    #: 0 when the verifier supplied an expected policy hash that could not be
    #: compared: the caller asked for that comparison, so leaving it unevaluated
    #: is not tolerable at any level, though it is still not a disproof.
    unverified_fails_from_level: int | None = field(default=None, kw_only=True)

    def passed(self) -> bool:
        return self.status == Status.PASS

    def failed(self) -> bool:
        return self.status == Status.FAIL

    def skipped(self) -> bool:
        return self.status == Status.SKIP

    def unverified(self) -> bool:
        return self.status == Status.UNVERIFIED


def finding_row(finding: Finding) -> list[object]:
    """Serialise *finding* as a JSON row.

    The fourth element is written only when the finding tightens its threshold,
    so a run that never does produces exactly the rows it produced before.
    """
    row: list[object] = [finding.code, finding.status.value, finding.message]
    if finding.unverified_fails_from_level is not None:
        row.append(finding.unverified_fails_from_level)
    return row


def finding_from_row(row: list[object] | tuple[object, ...]) -> Finding:
    """Rebuild a Finding from a row written by `finding_row`."""
    if len(row) == 3:
        code, status, message = row
        return Finding(str(code), Status(str(status)), str(message))
    if len(row) == 4:
        code, status, message, fails_from = row
        if type(fails_from) is not int or fails_from < 0:
            raise ValueError(
                f"finding row threshold must be a non-negative int, got {fails_from!r}"
            )
        return Finding(
            str(code), Status(str(status)), str(message), unverified_fails_from_level=fails_from
        )
    raise ValueError(f"finding row must have 3 or 4 elements, got {len(row)}")

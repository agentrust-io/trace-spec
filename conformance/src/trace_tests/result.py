"""Conformance finding types."""

from __future__ import annotations

from dataclasses import dataclass
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

    def passed(self) -> bool:
        return self.status == Status.PASS

    def failed(self) -> bool:
        return self.status == Status.FAIL

    def skipped(self) -> bool:
        return self.status == Status.SKIP

    def unverified(self) -> bool:
        return self.status == Status.UNVERIFIED

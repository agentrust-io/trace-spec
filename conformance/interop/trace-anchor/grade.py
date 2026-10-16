"""Grade TR-ANC-002 against a pinned external registry anchor corpus.

The corpus is data. This script downloads its MANIFEST.json and each case file
from the commit named in pin.json, refuses any file whose SHA-256 differs from
its pin, and answers every case with this repository's own
``trace_tests.modules.tr_anc.check``. Nothing from the corpus repository is
installed or executed.

A TR-ANC-002 pass is read as ``anchored`` and anything else as ``refused``;
each case's expected decision comes from the manifest. The job fails when the
corpus does not hold exactly the pinned number of cases, when a file does not
match its digest, or when a case disagrees and is not listed in
``known_disagreements``. A listed case that now agrees is reported so that the
list can be shortened; it does not fail the job.

    python interop/trace-anchor/grade.py [--report build/anchor-corpus.json]
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

from trace_tests.modules import tr_anc

PIN = Path(__file__).with_name("pin.json")
RAW = "https://raw.githubusercontent.com"


def fetch(repository: str, commit: str, path: str, sha256: str) -> bytes:
    owner_repo = repository.removeprefix("https://github.com/")
    url = f"{RAW}/{owner_repo}/{commit}/{path}"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 (fixed https host)
        data: bytes = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        raise SystemExit(f"digest mismatch for {path}: got {digest}, pinned {sha256}")
    return data


def decide(case: dict[str, Any]) -> tuple[str, str]:
    claim, receipt, entry = case.get("claim"), case.get("receipt"), case.get("entry")
    if "entry" in inspect.signature(tr_anc.check).parameters:
        findings = tr_anc.check(claim, receipt, entry)  # type: ignore[call-arg]
    else:
        findings = tr_anc.check(claim, receipt)
    for finding in findings:
        if finding.code == "TR-ANC-002":
            passed = str(getattr(finding.status, "value", finding.status)).lower() == "pass"
            return ("anchored" if passed else "refused"), finding.message
    return "refused", findings[0].message if findings else "no TR-ANC finding"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=Path, help="write per-case results as JSON")
    args = parser.parse_args()

    pin = json.loads(PIN.read_text(encoding="utf-8"))
    repository, commit = pin["repository"], pin["commit"]
    manifest = json.loads(fetch(repository, commit, pin["manifest"], pin["manifest_sha256"]))
    base = pin["manifest"].rsplit("/", 1)[0]
    vectors = manifest["vectors"]
    if len(vectors) != pin["cases"]:
        print(f"corpus holds {len(vectors)} cases, pinned {pin['cases']}")
        return 1

    known: dict[str, str] = pin["known_disagreements"]
    results, unexpected, resolved = [], [], []
    for vector in vectors:
        path = f"{base}/{vector['path']}/case.json"
        data = fetch(repository, commit, path, vector["files"]["case.json"])
        got, message = decide(json.loads(data))
        want = vector["expected"]["decision"]
        agrees = got == want
        results.append(
            {
                "id": vector["id"],
                "rule": vector["rule"],
                "expected": want,
                "got": got,
                "message": message,
            }
        )
        if not agrees and vector["id"] not in known:
            unexpected.append(f"{vector['id']}: expected {want}, TR-ANC-002 says {got} ({message})")
        if agrees and vector["id"] in known:
            resolved.append(vector["id"])

    agreed = sum(r["expected"] == r["got"] for r in results)
    print(f"{repository}@{commit[:12]} {pin['corpus']}")
    print(f"TR-ANC-002 agrees on {agreed} of {len(results)}")
    print(f"known disagreements listed: {len(known)}, unexpected: {len(unexpected)}")
    for case_id in resolved:
        print(f"::notice::{case_id} now agrees; remove it from known_disagreements in pin.json")
    for line in unexpected:
        print(f"::error::{line}")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        report = json.dumps({"pin": pin, "results": results}, indent=2) + "\n"
        args.report.write_text(report, encoding="utf-8")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())

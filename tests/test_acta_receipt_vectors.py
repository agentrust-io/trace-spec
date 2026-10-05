"""The Acta receipt verifier against the receipt-signature conformance corpus.

This file runs ``tools/acta_receipt_verifier.py`` through the
``vectors-receipt-signature`` corpus of the pinned ``agent-evidence-vectors``
package (``requirements/acta-receipt-vectors.txt``). The harness calls the
verifier once per receipt, twice over: with the issuers' key set and with the
same keys stripped of their validity windows. It grades each answer against the
corpus manifest, which cites the section of draft-farley-acta-signed-receipts-03
each expected verdict comes from.

The package needs Python 3.13, so the ``CI`` matrix (3.11 and 3.12) skips this
file and ``.github/workflows/acta-receipt-vectors.yml`` runs it on 3.13. On 3.13
nothing is skipped: a missing package fails here rather than passing quietly.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "acta_receipt_verifier.py"
CORPUS = "vectors-receipt-signature"

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="agent-evidence-vectors needs Python 3.13; acta-receipt-vectors.yml runs this file",
)


@pytest.fixture(scope="module")
def report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    path = tmp_path_factory.mktemp("acta-receipt-vectors") / "report.json"
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_evidence_vectors.run_vectors",
            "--corpus",
            CORPUS,
            "--verifier",
            shlex.join([sys.executable, str(VERIFIER)]),
            "--report",
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,  # the exit status is asserted below, with the harness output
        cwd=ROOT,
    )
    assert done.returncode == 0, f"harness exited {done.returncode}\n{done.stdout}\n{done.stderr}"
    result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return result


def test_the_harness_graded_this_verifier(report: dict[str, Any]) -> None:
    assert report["suite"] == CORPUS
    assert report["rail"] == "external"
    assert str(VERIFIER) in report["verifier"]["command"]


def test_every_vector_was_executed(report: dict[str, Any]) -> None:
    totals = report["totals"]
    assert totals["vectors"] > 0
    assert report["verifier"]["vectorsExecuted"] == totals["vectors"]
    assert totals["notExercised"] == 0


def test_no_vector_fails(report: dict[str, Any]) -> None:
    failed = [v for v in report["vectors"] if v["status"] == "FAIL"]
    assert report["totals"]["fail"] == 0, failed


def test_the_section_9_2_window_check_is_applied(report: dict[str, Any]) -> None:
    """A verifier that skips the SHOULD is reported apart from a failure; this one must not."""
    assert report["totals"]["notHonoured"] == 0


def test_no_proposed_rule_is_applied(report: dict[str, Any]) -> None:
    """Revocation and commitment times are proposals, not draft text.

    The verifier answers what draft-03 says, so it must not close either gap.
    """
    assert report["totals"]["closesGap"] == 0


def test_the_suite_refused_nothing(report: dict[str, Any]) -> None:
    assert report["totals"]["suiteRefusals"] == 0

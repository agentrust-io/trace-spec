# Running trace-tests in a CI Pipeline

This guide is for teams that want every code change checked automatically. It sets up a GitHub Actions workflow (GitHub's built-in system for running jobs on each push) that installs `agentrust-trace-tests`, runs your conformance tests, and saves the results as a downloadable file.

If all you need is to stop a pipeline when a record falls below a level, one command does it: `trace-tests report --record trust-record.json --json report.json --fail-under 1` exits non-zero when the record does not reach Level 1. The rest of this page covers running your own pytest tests against the suite's library.

## What you'll learn

- A working GitHub Actions workflow file with matrix Python version testing
- What `CMCP_DEV_MODE=1` does, and does not do, for software-only records in standard CI
- How to read a failure back to the specific error code and field it names
- When to skip hardware attestation tests that require real TEE hardware

## Prerequisites

```
pip install agentrust-trace-tests pytest pytest-json-report
```

______________________________________________________________________

## Write the workflow

Create `.github/workflows/trace-tests.yml` in your repository:

```
name: TRACE conformance

on:
  push:
    branches: [main]
  pull_request:

jobs:
  conformance:
    runs-on: ubuntu-latest

    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: pip install agentrust-trace-tests pytest pytest-json-report

      - name: Run conformance suite
        env:
          CMCP_DEV_MODE: "1"
        run: |
          pytest --tb=short \
                 --json-report \
                 --json-report-file=report-${{ matrix.python-version }}.json

      - name: Upload test report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trace-report-py${{ matrix.python-version }}
          path: report-${{ matrix.python-version }}.json
```

The `fail-fast: false` setting lets all Python versions finish even if one matrix leg fails, so you can see whether a failure is version-specific.

______________________________________________________________________

## Set CMCP_DEV_MODE for software-only CI

Standard CI runners have no TEE hardware (no trusted execution environment, the processor mode that keeps a program's memory sealed off). The suite itself does not read `CMCP_DEV_MODE`: checked against the 0.6.1 source, no file under `src/` mentions it. A software-only record passes at Level 0 because Level 0 does not run TR-RTE, and it fails TR-RTE-001 at Level 1 and above whatever the environment says. Keep the variable in the workflow only if your own fixtures or tools read it.

```
- name: Run conformance suite
  env:
    CMCP_DEV_MODE: "1"
  run: pytest --tb=short
```

At Level 1 and above, TR-RTE checks that `runtime.platform` is a registered hardware TEE value (`intel-tdx`, `amd-sev-snp`, `nvidia-h100`, etc.). To check a software-only record in CI, run it at Level 0. Never treat a Level 0 pass as evidence about hardware.

______________________________________________________________________

## Skip hardware attestation tests

Some tests need real TEE hardware to produce an attestation report (the processor's signed statement of what code it is running). Mark them so they skip automatically on standard runners:

```
import os
import pytest

HW_AVAILABLE = os.getenv("TEE_HARDWARE") == "1"

@pytest.mark.skipif(not HW_AVAILABLE, reason="requires real TEE hardware")
def test_amd_sev_snp_measurement_round_trip():
    ...
```

In your workflow, standard jobs skip these tests silently. A separate job on hardware-provisioned runners can set `TEE_HARDWARE=1` to run the full set.

You can also use pytest markers to exclude the hardware group entirely in CI:

```
pytest -m "not hardware" --tb=short
```

Register the marker in `pytest.ini` or `pyproject.toml` to avoid the `PytestUnknownMarkWarning`:

```
[tool.pytest.ini_options]
markers = [
    "hardware: tests that require a physical TEE (deselect with -m 'not hardware')",
    "level0: Level 0 conformance tests",
    "level1: Level 1 conformance tests",
    "level2: Level 2 conformance tests",
]
```

______________________________________________________________________

## Read a failure back to its field

When a test fails, `--tb=short` shows the assertion message, which includes the error code:

```
FAILED tests/test_level0.py::TestLevel0Conformance::test_policy_enforcement_mode_known
AssertionError: assert 'strict' in {'advisory', 'enforce', 'silent'}
```

Match the test name to the module (`tr_pol`) and look up the code in the [Error Codes](https://trace.agentrust-io.com/conformance/docs/error-codes/index.md) table. For failures surfaced by `runner.run()`, the `Finding` object carries the code directly:

```
from trace_tests.runner import run
from trace_tests.loader import load_record

record, fmt = load_record("trust-record.json")
results = run(record, fmt, level=1)

for module_id, findings in results.items():
    for f in findings:
        if f.failed():
            print(f"{f.code}  {f.message}")
```

Output:

```
TR-RTE-001  TR-RTE-001: runtime.platform must be a recognised TEE enum value, got 'custom-tee'
```

The code `TR-RTE-001` maps to `runtime.platform`. Fix the field in your record and re-run.

______________________________________________________________________

## Upload the test report as an artifact

`pytest-json-report` writes a machine-readable JSON file. The `upload-artifact` step makes it available in the GitHub Actions UI under the run summary.

```
- name: Upload test report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: trace-report-py${{ matrix.python-version }}
    path: report-${{ matrix.python-version }}.json
```

`if: always()` uploads the report even when the test step fails, so you can inspect failures without re-running.

To produce a JUnit XML report instead (for GitHub's built-in test summary):

```
pytest --tb=short --junit-xml=results.xml
```

```
- name: Publish test results
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: junit-results
    path: results.xml
```

______________________________________________________________________

## Matrix testing across Python versions

The `strategy.matrix` block runs the full suite on Python 3.10, 3.11, and 3.12 in parallel. Each leg uploads its own artifact so version-specific regressions are visible without comparing logs manually.

To add a new version, append it to the list:

```
matrix:
  python-version: ["3.10", "3.11", "3.12", "3.13"]
```

If a module uses a stdlib API that changed between versions, the matrix will catch it. The package requires Python 3.11 or later (`requires-python = ">=3.11"` in `pyproject.toml`), so the 3.10 leg in the example above cannot install it; drop 3.10 from your matrix. On 3.11 and later, a failure that appears on one version only points at your custom tests or fixtures.

______________________________________________________________________

## Summary

You have a GitHub Actions workflow that installs `agentrust-trace-tests`, runs your tests on each Python version in the matrix, and saves per-version JSON reports as artifacts. Hardware attestation tests are marked and skipped on standard runners. When a test fails, the error code in the assertion message maps directly to the spec field that failed.

For more on what each error code means, see [Error Codes](https://trace.agentrust-io.com/conformance/docs/error-codes/index.md). To write custom tests against specific modules, see [Writing Conformance Tests](https://trace.agentrust-io.com/conformance/docs/tutorials/writing-conformance-tests/index.md).

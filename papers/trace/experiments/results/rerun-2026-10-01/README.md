# TRACE rerun, 2026-10-01

Independent rerun of `experiments/bench.py` for technical report version 3.
The committed results one level up are not modified.

## Revisions

The original run (2026-07-01T20:45:09Z) recorded `agentrust_trace` 0.2.0 and
`trace_tests` 0.2.0. Those are `__version__` strings, not release pins:

- The released `agentrust-trace` 0.2.0 wheel has no `verify_record` and
  canonicalizes with `json.dumps(sort_keys=True, ensure_ascii=True)`, so
  `bench.py` cannot import against it.
- trace-spec `523f8cc` (main at the run time) has `verify_record` and RFC 8785
  canonicalization; its `sign.py` is identical to tag `v0.3.0`, and the released
  0.3.0 wheel still reports `__version__ = "0.2.0"`. That is the code measured.
- trace-tests `661c177` (main at the run time); `src/` and `tests/vectors/` are
  identical to tag `v0.2.0` (2026-07-07) and to PyPI `agentrust-trace-tests` 0.2.0.

Current main for the staleness run: trace-spec `11c0868`, trace-tests `7d220ee`.

## Commands

Fresh venvs, CPython 3.12.10, run from a scratch copy of `experiments/` so the
committed results are not overwritten:

    py -3.12-arm64 -m venv venv
    venv/Scripts/python -m pip install <trace-spec@523f8cc> <trace-tests@661c177> rfc8785
    PYTHONUTF8=1 TRACE_VECTORS_DIR=<trace-tests@661c177>/tests/vectors venv/Scripts/python experiments/bench.py

`main-arm64` used the same command against current main, with
`TRACE_VECTORS_DIR` restricted to the five vectors named in the paper (main's
vector directory now holds deliberately non-canonical vectors that `bench.py`
cannot canonicalize).

## Results

| Quantity | Paper | pin, ARM64 (3 runs) | pin, x64 emulated | main, ARM64 |
|---|---|---|---|---|
| JCS distinct hashes | 5 of 1000 | 5 | 5 | 5 |
| sign median / mean / p99 ms | 0.094 / 0.129 / 0.580 | 0.103 (run 3) / 0.143 to 0.224 / 0.89 to 2.22 | 0.165 / 0.333 / 3.38 | 0.092 / 0.125 / 0.80 |
| verify median / mean / p99 ms | 0.158 / 0.211 / 0.856 | 0.165 (run 3) / 0.253 to 0.316 / 1.43 to 3.14 | 0.304 / 0.743 / 9.82 | 0.707 / 0.976 / 4.37 |
| verify throughput ops/s | 4,731 | 3,153 to 3,950 | 1,343 | 1,023 |
| valid_level0 bytes | 878 | 878 | 878 | 882 |
| valid_level0_with_transcript | 1,109 | 1,109 | 1,109 | 1,113 |
| synthetic full L2 | 1,385 | 1,389 | 1,389 | 1,389 |
| valid_cmcp_runtime | 1,612 | 1,612 | 1,612 | 1,616 |
| conformance table | Table 6 | identical | identical | different (more checks) |

`pin-arm64/` holds the third ARM64 run. The original environment string matches
this host (Windows 11 26200, Qualcomm ARMv8); the run 3 ARM64 medians are within 10 percent
of the paper, the x64-emulated interpreter does not.

The synthetic L2 record is 1,389 bytes because commit 3b4fa09 (2026-07-27)
changed the profile URI in `bench.py` from `tag:agentrust.io,2026:trace-v0.1`
to `tag:agentrust-io.com,2026:trace-v0.2` (4 bytes longer) without rerunning.

## Probes

`interop_probe.py` signs three records with agentrust-trace and checks them
with trace-tests TR-SIG at the same pins (`pin-arm64/interop_probe.json`). An
ASCII record passes; a record with a non-ASCII `subject` verifies in the SDK
and FAILS TR-SIG-005, because trace-tests at `661c177` canonicalizes with
`json.dumps(sort_keys=True, ensure_ascii=True)` while the SDK uses RFC 8785.
Current trace-tests main uses RFC 8785.

At the same pins, a record carrying the v0.2 profile URI the paper specifies
fails TR-ENV-001; the checker accepts only the v0.1 URI.

## Later edit to bench.py

After these runs, on October 1, 2026, the synthetic records in `bench.py` had a vendor provider
and model name replaced with same-length placeholders (`exampleco`, `example-model-4-5`), as
the paper's worked example already does. A run of the edited script at the pins (x64, same
command) gave the same canonical sizes: 878, 1,109, 1,389 and 1,612 bytes.

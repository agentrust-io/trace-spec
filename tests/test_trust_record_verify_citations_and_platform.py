"""TypeScript verifier parity for citation resolution and platform measurement appraisal.

Runs the `examples/citation-resolution/` and `examples/platform-measurement/` conformance
vectors and invariant checks through `trust-record-verify` (`verifyRecord`,
`checkCitations`, and `checkPlatformMeasurement`) to verify parity with the Python
reference implementation.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "trust-record-verify"
CITATION_VECTORS = sorted((ROOT / "examples" / "citation-resolution").glob("*.json"))
PLATFORM_VECTORS = sorted((ROOT / "examples" / "platform-measurement").glob("*.json"))


def _donor_package() -> pathlib.Path | None:
    """Locate a worktree whose `trust-record-verify/node_modules` is already installed."""
    if (PACKAGE / "node_modules").is_dir():
        return PACKAGE
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("worktree "):
            candidate = pathlib.Path(line.removeprefix("worktree ").strip()) / "trust-record-verify"
            if (candidate / "node_modules").is_dir():
                return candidate
    return None


def _ensure_built() -> None:
    """Build `trust-record-verify/dist` when absent or older than `src/*.ts`."""
    dist_index = PACKAGE / "dist" / "index.js"
    ts_sources = list((PACKAGE / "src").glob("*.ts"))
    if dist_index.is_file() and all(
        src.stat().st_mtime <= dist_index.stat().st_mtime for src in ts_sources
    ):
        return

    donor = _donor_package()
    if donor is None:
        npm = shutil.which("npm") or "npm"
        subprocess.run(
            [npm, "--prefix", str(PACKAGE), "ci"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        subprocess.run(
            [npm, "--prefix", str(PACKAGE), "run", "build"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        return

    generated = PACKAGE / "src" / "generated"
    if not (generated / "validators.js").is_file():
        if (PACKAGE / "node_modules").is_dir():
            subprocess.run(
                ["node", "scripts/generate-validators.mjs"],
                cwd=PACKAGE,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=True,
            )
        elif (donor / "src" / "generated" / "validators.js").is_file():
            shutil.copytree(donor / "src" / "generated", generated, dirs_exist_ok=True)

    tsc = donor / "node_modules" / "typescript" / "bin" / "tsc"
    subprocess.run(
        ["node", str(tsc), "-p", "tsconfig.json"],
        cwd=PACKAGE,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )


@pytest.fixture(scope="module")
def ts_results() -> dict[str, Any]:
    """Run all citation-resolution and platform-measurement vectors and checks in Node."""
    _ensure_built()
    script = """
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import * as trace from "./dist/index.js";

const root = process.argv[1];
const out = { citations: {}, platform: {}, checks: {} };

function loadDir(sub) {
  const dir = join(root, "examples", sub);
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => [f, JSON.parse(readFileSync(join(dir, f), "utf8"))]);
}

for (const [name, doc] of loadDir("citation-resolution")) {
  const ctx = doc.context;
  let citationResolver = null;
  if (Object.hasOwn(ctx, "resolutions")) {
    const table = ctx.resolutions;
    citationResolver = (uri) => {
      if (!Object.hasOwn(table, uri)) {
        const err = new Error(uri);
        err.name = "KeyError";
        throw err;
      }
      return new Uint8Array(Buffer.from(table[uri].bytes_base64, "base64"));
    };
  }
  const res = await trace.verifyRecord(doc.records[0], {
    trustedKey: ctx.trusted_key,
    now: ctx.now,
    maxAgeSeconds: ctx.max_age_seconds,
    maxFutureSkewSeconds: ctx.max_future_skew_seconds,
    citationResolver,
  });
  out.citations[name] = res.citations ?? null;
}

for (const [name, doc] of loadDir("platform-measurement")) {
  const ctx = doc.context;
  let platformAppraiser = null;
  if (Object.hasOwn(ctx, "appraisals")) {
    const table = ctx.appraisals;
    platformAppraiser = (runtime) => {
      if (!Object.hasOwn(table, runtime.measurement)) {
        const err = new Error(runtime.measurement);
        err.name = "KeyError";
        throw err;
      }
      return structuredClone(table[runtime.measurement]);
    };
  }
  const res = await trace.verifyRecord(doc.records[0], {
    trustedKey: ctx.trusted_key,
    now: ctx.now,
    maxAgeSeconds: ctx.max_age_seconds,
    maxFutureSkewSeconds: ctx.max_future_skew_seconds,
    platformAppraiser,
  });
  out.platform[name] = res.platformMeasurement ?? null;
}

async function codeOf(fn) {
  try {
    await fn();
    return "ok";
  } catch (err) {
    return err?.code ?? "other";
  }
}

out.checks.badCitationResolver = await codeOf(() =>
  trace.verifyRecord({}, { citationResolver: "bad" })
);
out.checks.badPlatformAppraiser = await codeOf(() =>
  trace.verifyRecord({}, { platformAppraiser: 123 })
);
out.checks.nonStringMeasurements = [];
const badRuntimes = [
  {},
  { measurement: null },
  { measurement: "" },
  { measurement: 123 },
  { measurement: true },
  { measurement: ["sha256:aa"] },
];
for (const badRuntime of badRuntimes) {
  const pm = await trace.checkPlatformMeasurement(
    { runtime: badRuntime },
    (rt) => ({ measurement: rt.measurement, layers: { "pcr:0": "established" } })
  );
  out.checks.nonStringMeasurements.push([pm.outcome, pm.cause]);
}

process.stdout.write(JSON.stringify(out));
"""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(ROOT)],
        cwd=PACKAGE,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    loaded: dict[str, Any] = json.loads(proc.stdout)
    return loaded


@pytest.mark.parametrize("path", CITATION_VECTORS, ids=[p.stem for p in CITATION_VECTORS])
def test_ts_citation_resolution_vector(path: pathlib.Path, ts_results: dict[str, Any]) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    got = ts_results["citations"][path.name]
    assert got == doc["expected"]["citations"], path.name


@pytest.mark.parametrize("path", PLATFORM_VECTORS, ids=[p.stem for p in PLATFORM_VECTORS])
def test_ts_platform_measurement_vector(path: pathlib.Path, ts_results: dict[str, Any]) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    got = ts_results["platform"][path.name]
    assert got == doc["expected"]["platform_measurement"], path.name


def test_ts_invalid_callback_options_rejected_at_entry(ts_results: dict[str, Any]) -> None:
    assert ts_results["checks"]["badCitationResolver"] == "invalid_argument"
    assert ts_results["checks"]["badPlatformAppraiser"] == "invalid_argument"


def test_ts_non_string_or_empty_runtime_measurement_is_field_absent(
    ts_results: dict[str, Any],
) -> None:
    assert ts_results["checks"]["nonStringMeasurements"] == [
        ["not_attempted", "field_absent"]
    ] * 6

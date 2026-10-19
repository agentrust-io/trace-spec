#!/usr/bin/env python3
"""TRACE deterministic microbenchmark harness.

Measures, against the *shipped* code (agentrust-trace, trace-tests), the
properties the paper claims:

  1. JCS (RFC 8785) canonicalization determinism: the same record canonicalizes
     to byte-identical output (and hence an identical SHA-256) across repeated
     runs and across shuffled key orderings. Reports the distinct-hash count.
  2. Ed25519 sign + verify latency (per-op timings) and derived throughput.
  3. Trust Record canonical sizes (bytes) across the shipped conformance vectors
     plus a synthetic full Level-2 record.
  4. Conformance pass/fail/skip/unverified counts produced by the shipped
     trace-tests runner over every shipped vector at each level.

No numbers are fabricated: everything written to results/ is produced here.

Run:  PYTHONUTF8=1 python experiments/bench.py
Outputs: experiments/results/*.json
"""

from __future__ import annotations

import hashlib
import os
import json
import platform
import random
import statistics
import sys
import time
from pathlib import Path

import rfc8785  # noqa: F401  (imported to assert availability / record version)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agentrust_trace
from agentrust_trace.sign import _canonical_bytes, generate_key, sign_record, verify_record

from trace_tests import __version__ as trace_tests_version
from trace_tests.runner import run as run_conformance

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
RESULTS.mkdir(parents=True, exist_ok=True)

# Shipped conformance vectors (source of truth for record shapes / sizes).
VECTORS_DIR = Path(os.environ.get("TRACE_VECTORS_DIR", "trace-tests/tests/vectors"))
if not VECTORS_DIR.is_dir() or not list(VECTORS_DIR.glob("*.json")):
    raise SystemExit("Set TRACE_VECTORS_DIR to the historical trace-tests vectors directory; refusing an empty benchmark.")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _shuffle_keys(obj):
    """Return a structurally identical object with dict key order shuffled.

    JCS must be insensitive to insertion order, so a canonicalizer that is
    correct produces the same bytes regardless of how the dict was built.
    """
    if isinstance(obj, dict):
        items = list(obj.items())
        random.shuffle(items)
        return {k: _shuffle_keys(v) for k, v in items}
    if isinstance(obj, list):
        return [_shuffle_keys(v) for v in obj]
    return obj


def load_vectors() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(VECTORS_DIR.glob("*.json")):
        out[p.stem] = json.loads(p.read_text(encoding="utf-8"))
    return out


def build_full_l2_record() -> dict:
    """A signed, structurally complete Level-2 TRACE record (all fields present).

    Built via the shipped agentrust_trace.sign_record path, then extended with the
    hardware / provenance / transparency fields a Level-2 record carries. Values
    are illustrative placeholders (hashes of fixed strings); the point of using it
    here is size + canonicalization + signing behaviour, not semantic content.
    """

    def h(s: str) -> str:
        return "sha256:" + hashlib.sha256(s.encode()).hexdigest()

    base = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": int(time.time()),
        "subject": "spiffe://cmcp.gateway/session/full-l2-example",
        "model": {"provider": "exampleco", "model_id": "example-model-4-5",
                  "version": "2026-05", "weights_digest": h("weights")},
        "runtime": {"platform": "intel-tdx", "measurement": h("mrtd"),
                    "rim_uri": "https://rim.example.org/tdx/1", "nonce": "abc123",
                    "firmware_version": "tdx-module-1.5"},
        "policy": {"bundle_hash": h("bundle"), "enforcement_mode": "enforce",
                   "version": "v1.2", "policy_uri": "https://policy.example.org/v1.2"},
        "data_class": "confidential",
        "tool_transcript": {"hash": h("transcript"), "call_count": 7,
                            "transcript_uri": "https://logs.example.org/t/1"},
        "build_provenance": {"slsa_level": 3, "builder": "github-actions",
                             "digest": h("image"),
                             "provenance_uri": "https://slsa.example.org/p/1"},
        "appraisal": {"status": "affirming", "verifier": "https://verifier.example.org",
                      "policy_ref": "rp-policy-1", "timestamp": int(time.time())},
        "transparency": "https://scitt.example.org/receipts/full-l2-example",
    }
    key = generate_key()
    return sign_record(base, key)


# --------------------------------------------------------------------------- #
# 1. JCS determinism
# --------------------------------------------------------------------------- #
def bench_jcs_determinism(vectors: dict[str, dict], repeats: int = 200) -> dict:
    """For each record, canonicalize `repeats` times (shuffling key order each
    time) and confirm every run yields the identical SHA-256. Distinct-hash
    count MUST be 1 for a deterministic canonicalizer."""
    per_record = {}
    for name, rec in vectors.items():
        hashes = set()
        first_bytes = None
        for _ in range(repeats):
            shuffled = _shuffle_keys(rec)
            cb = _canonical_bytes(shuffled)
            if first_bytes is None:
                first_bytes = cb
            hashes.add(sha256_hex(cb))
        per_record[name] = {
            "repeats": repeats,
            "distinct_hashes": len(hashes),
            "canonical_bytes": len(first_bytes),
            "hash": next(iter(hashes)),
        }
    total_distinct = sum(v["distinct_hashes"] for v in per_record.values())
    return {
        "repeats_per_record": repeats,
        "records_tested": len(per_record),
        "total_distinct_hashes_expected": len(per_record),
        "total_distinct_hashes_observed": total_distinct,
        "deterministic": all(v["distinct_hashes"] == 1 for v in per_record.values()),
        "per_record": per_record,
    }


# --------------------------------------------------------------------------- #
# 2. Ed25519 sign / verify latency + throughput
# --------------------------------------------------------------------------- #
def bench_sign_verify(iters: int = 5000, warmup: int = 500) -> dict:
    """Time sign_record and verify_record on a representative record.

    Uses the shipped agentrust_trace paths (JCS canonicalize + Ed25519). Records
    per-op latencies (milliseconds) so the paper can plot the distribution; also
    reports throughput (ops/sec) from the aggregate.
    """
    key: Ed25519PrivateKey = generate_key()
    pub = key.public_key()
    base = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": int(time.time()),
        "subject": "spiffe://cmcp.gateway/session/bench",
        "model": {"provider": "exampleco", "model_id": "example-model-4-5"},
        "runtime": {"platform": "software-only",
                    "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "1" * 64, "enforcement_mode": "advisory"},
        "data_class": "public",
        "build_provenance": {"slsa_level": 2, "digest": "sha256:" + "2" * 64},
        "appraisal": {"status": "affirming", "verifier": "https://verifier.example.org"},
        "transparency": "https://scitt.example.org/receipts/bench",
    }

    # Warmup (JIT-free CPython, but warms caches / import lazily-loaded paths).
    for _ in range(warmup):
        signed = sign_record(base, key)
        verify_record(signed, pub, max_age_seconds=None)

    sign_lat_ms: list[float] = []
    signed_ref = None
    t0 = time.perf_counter()
    for _ in range(iters):
        s = time.perf_counter()
        signed = sign_record(base, key)
        sign_lat_ms.append((time.perf_counter() - s) * 1e3)
        signed_ref = signed
    sign_wall = time.perf_counter() - t0

    verify_lat_ms: list[float] = []
    t0 = time.perf_counter()
    for _ in range(iters):
        s = time.perf_counter()
        verify_record(signed_ref, pub, max_age_seconds=None)
        verify_lat_ms.append((time.perf_counter() - s) * 1e3)
    verify_wall = time.perf_counter() - t0

    def summ(xs: list[float]) -> dict:
        xs_sorted = sorted(xs)
        n = len(xs_sorted)
        return {
            "count": n,
            "mean_ms": statistics.mean(xs_sorted),
            "median_ms": statistics.median(xs_sorted),
            "p50_ms": xs_sorted[int(0.50 * (n - 1))],
            "p90_ms": xs_sorted[int(0.90 * (n - 1))],
            "p99_ms": xs_sorted[int(0.99 * (n - 1))],
            "min_ms": xs_sorted[0],
            "max_ms": xs_sorted[-1],
            "stdev_ms": statistics.pstdev(xs_sorted),
        }

    return {
        "iters": iters,
        "warmup": warmup,
        "sign": {
            **summ(sign_lat_ms),
            "throughput_ops_per_sec": iters / sign_wall,
            "wall_sec": sign_wall,
        },
        "verify": {
            **summ(verify_lat_ms),
            "throughput_ops_per_sec": iters / verify_wall,
            "wall_sec": verify_wall,
        },
        # Raw latencies for plotting (kept bounded so the JSON stays readable).
        "sign_latencies_ms": sign_lat_ms,
        "verify_latencies_ms": verify_lat_ms,
    }


# --------------------------------------------------------------------------- #
# 3. Record sizes
# --------------------------------------------------------------------------- #
def bench_record_sizes(vectors: dict[str, dict], full_l2: dict) -> dict:
    sizes = {}
    for name, rec in vectors.items():
        cb = _canonical_bytes(rec)
        sizes[name] = {"canonical_bytes": len(cb),
                       "pretty_bytes": len(json.dumps(rec, indent=2).encode())}
    cb = _canonical_bytes({k: v for k, v in full_l2.items() if k != "signature"})
    sizes["synthetic_full_l2"] = {
        "canonical_bytes": len(cb),
        "pretty_bytes": len(json.dumps(full_l2, indent=2).encode()),
    }
    return sizes


# --------------------------------------------------------------------------- #
# 4. Conformance pass counts
# --------------------------------------------------------------------------- #
def _detect_fmt(rec: dict) -> str:
    """Mirror trace_tests.loader format detection (positive markers)."""
    return "cmcp-runtime" if "cmcp_version" in rec else "trace"


def bench_conformance(vectors: dict[str, dict]) -> dict:
    """Run the shipped trace-tests runner over each vector at levels 0/1/2 and
    tally pass/fail/skip/unverified per (vector, level).

    The shipped vectors are archived (iat in 2025) and unsigned, so the
    freshness (TR-ENV) and signature (TR-SIG) checks would otherwise dominate.
    To measure *structural* conformance we disable the age bound with a large
    max_age. TR-SIG legitimately reports UNVERIFIED for these unsigned vectors;
    that is the honest expected outcome (the signed-record path is exercised
    separately by the sign/verify benchmark)."""
    big_max_age = 10 * 365 * 24 * 3600  # 10 years: neutralize archival staleness
    out = {}
    for name, rec in vectors.items():
        fmt = _detect_fmt(rec)
        per_level = {}
        for level in (0, 1, 2):
            try:
                results = run_conformance(rec, fmt, level, max_age_seconds=big_max_age)
            except Exception as exc:  # malformed vector for that fmt/level
                per_level[str(level)] = {"error": str(exc)}
                continue
            counts = {"pass": 0, "fail": 0, "skip": 0, "unverified": 0}
            for _mod, findings in results.items():
                for f in findings:
                    if f.passed():
                        counts["pass"] += 1
                    elif f.failed():
                        counts["fail"] += 1
                    elif f.unverified():
                        counts["unverified"] += 1
                    else:
                        counts["skip"] += 1
            counts["modules_run"] = len(results)
            counts["overall_pass"] = counts["fail"] == 0 and not (
                counts["unverified"] and level >= 1
            )
            per_level[str(level)] = counts
        out[name] = {"fmt": fmt, "levels": per_level}
    return out


def main() -> None:
    random.seed(1729)
    env = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "agentrust_trace": agentrust_trace.__version__,
        "trace_tests": trace_tests_version,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    vectors = load_vectors()
    full_l2 = build_full_l2_record()

    jcs = bench_jcs_determinism(vectors)
    sv = bench_sign_verify()
    sizes = bench_record_sizes(vectors, full_l2)
    conf = bench_conformance(vectors)

    (RESULTS / "environment.json").write_text(json.dumps(env, indent=2))
    (RESULTS / "jcs_determinism.json").write_text(json.dumps(jcs, indent=2))
    (RESULTS / "sign_verify.json").write_text(json.dumps(sv, indent=2))
    (RESULTS / "record_sizes.json").write_text(json.dumps(sizes, indent=2))
    (RESULTS / "conformance.json").write_text(json.dumps(conf, indent=2))

    print("=== ENVIRONMENT ===")
    print(json.dumps(env, indent=2))
    print("\n=== JCS DETERMINISM ===")
    print(f"records={jcs['records_tested']} repeats/rec={jcs['repeats_per_record']} "
          f"distinct_hashes_observed={jcs['total_distinct_hashes_observed']} "
          f"(expected {jcs['total_distinct_hashes_expected']}) "
          f"deterministic={jcs['deterministic']}")
    print("\n=== SIGN / VERIFY ===")
    print(f"sign  : mean={sv['sign']['mean_ms']:.4f}ms p99={sv['sign']['p99_ms']:.4f}ms "
          f"thru={sv['sign']['throughput_ops_per_sec']:.0f} ops/s")
    print(f"verify: mean={sv['verify']['mean_ms']:.4f}ms p99={sv['verify']['p99_ms']:.4f}ms "
          f"thru={sv['verify']['throughput_ops_per_sec']:.0f} ops/s")
    print("\n=== RECORD SIZES (canonical bytes) ===")
    for k, v in sizes.items():
        print(f"  {k:30s} {v['canonical_bytes']:6d} B")
    print("\n=== CONFORMANCE (per vector, level -> pass/fail/skip/unverified) ===")
    for name, entry in conf.items():
        print(f"  {name} [{entry['fmt']}]")
        for lvl, c in entry["levels"].items():
            if "error" in c:
                print(f"    L{lvl}: ERROR {c['error']}")
            else:
                print(f"    L{lvl}: pass={c['pass']} fail={c['fail']} skip={c['skip']} "
                      f"unverified={c['unverified']} overall_pass={c['overall_pass']}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate the paper's result figures from experiments/results/*.json.

Two figures, both saved as PDF (the only data-plot mechanism allowed):

  1. figures/verify_latency.pdf  -- verify vs sign per-op latency distribution
     (histogram, ms), annotated with mean and p99.
  2. figures/throughput.pdf      -- sign vs verify throughput (ops/sec), with
     the record-size range noted in the caption of the paper.

Run:  PYTHONUTF8=1 python experiments/plots.py
Requires experiments/results/sign_verify.json (produced by bench.py).
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
FIGURES = HERE.parent / "figures"
FIGURES.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.size": 10,
    "font.family": "serif",
    "axes.grid": True,
    "grid.alpha": 0.3,
    "figure.dpi": 150,
})


def load(name: str) -> dict:
    return json.loads((RESULTS / name).read_text())


def fig_latency(sv: dict) -> None:
    sign = sv["sign_latencies_ms"]
    verify = sv["verify_latencies_ms"]
    ss, vs = sv["sign"], sv["verify"]

    fig, ax = plt.subplots(figsize=(5.4, 3.3))
    # Clip the long tail for a readable body; a handful of scheduler-induced
    # outliers otherwise flatten the distribution.
    hi = max(vs["p99_ms"], ss["p99_ms"]) * 1.3
    bins = 60
    ax.hist(sign, bins=bins, range=(0, hi), alpha=0.6, label="sign", color="#2a6f97")
    ax.hist(verify, bins=bins, range=(0, hi), alpha=0.6, label="verify", color="#c1492b")
    ax.axvline(ss["mean_ms"], color="#2a6f97", ls="--", lw=1)
    ax.axvline(vs["mean_ms"], color="#c1492b", ls="--", lw=1)
    ax.set_xlabel("per-operation latency (ms)")
    ax.set_ylabel("count")
    ax.set_title("Ed25519 + JCS sign/verify latency")
    ax.legend(
        title=(f"sign mean {ss['mean_ms']:.3f} ms, p99 {ss['p99_ms']:.3f} ms\n"
               f"verify mean {vs['mean_ms']:.3f} ms, p99 {vs['p99_ms']:.3f} ms"),
        title_fontsize=8, fontsize=9, loc="upper right",
    )
    fig.tight_layout()
    fig.savefig(FIGURES / "verify_latency.pdf")
    plt.close(fig)


def fig_throughput(sv: dict) -> None:
    ss, vs = sv["sign"], sv["verify"]
    ops = ["sign", "verify"]
    thru = [ss["throughput_ops_per_sec"], vs["throughput_ops_per_sec"]]
    colors = ["#2a6f97", "#c1492b"]

    fig, ax = plt.subplots(figsize=(4.2, 3.3))
    bars = ax.bar(ops, thru, color=colors, width=0.55)
    for b, t in zip(bars, thru):
        ax.text(b.get_x() + b.get_width() / 2, t, f"{t:,.0f}",
                ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("throughput (operations / second)")
    ax.set_title(f"Single-core throughput (n={sv['iters']} ops)")
    ax.set_ylim(0, max(thru) * 1.18)
    fig.tight_layout()
    fig.savefig(FIGURES / "throughput.pdf")
    plt.close(fig)


def main() -> None:
    sv = load("sign_verify.json")
    fig_latency(sv)
    fig_throughput(sv)
    print(f"wrote {FIGURES / 'verify_latency.pdf'}")
    print(f"wrote {FIGURES / 'throughput.pdf'}")


if __name__ == "__main__":
    main()

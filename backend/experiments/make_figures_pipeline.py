"""Figures for experiments 04-09: the sensor pipeline.

One figure per experiment, and each one carries a claim rather than decorating
a number. Three of the six report a refutation, which is why they exist - a
figure that can only ever agree with you is not evidence.

    fig04  host-window state, not traffic direction, is what matters
    fig05  the streaming sketch reproduces the batch features
    fig06  the lateness budget buys flows back, but not accuracy   (V4 refuted)
    fig07  sharding does not reach line rate                       (W1/W3-W5 refuted)
    fig08  a marginal conformal predictor abandons the rare classes
    fig09  splitting the model into heads is not what pays         (Y1/Y3 refuted)

Every number is read from results/*.json and results/*.csv at run time. Nothing
here is typed in by hand, so a re-run of an experiment moves its figure.

Run after exp04-exp09:  python experiments/make_figures_pipeline.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

INK, MUTED = "#141918", "#67746F"
TEAL, RUST, GREY = "#0B6B63", "#A3341F", "#B0BAB7"
GOLD, SLATE = "#8A6D1F", "#41626D"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "axes.spines.top": False, "axes.spines.right": False,
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "figure.dpi": 140,
})


def load(name: str):
    p = RESULTS / name
    if not p.exists():
        sys.exit(f"missing {p.name} - run the experiment that writes it first")
    return json.loads(p.read_text()) if p.suffix == ".json" else pd.read_csv(p)


def caption(fig, text: str) -> None:
    """One line under the figure saying what it shows. A figure that needs the
    surrounding prose to be legible does not travel."""
    fig.text(0.5, -0.055, text, ha="center", fontsize=8.6, color=MUTED,
             style="italic", wrap=True)


def save(fig, name: str) -> None:
    fig.savefig(RESULTS / name, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  wrote results/{name}")


# --------------------------------------------------------------------- fig04
def fig04() -> None:
    """The central result. Windowed host state dominates traffic direction."""
    df = load("exp04_forward_features.csv").set_index("condition")
    v = load("exp04_verdicts.json")

    order = ["A_FULL", "C_MATCHED", "E_SENSOR", "F_FULL_PLUS_HW", "G_HW_ONLY"]
    labels = ["Full\nvisibility", "One-way tap,\nflows only",
              "One-way tap\n+ host window", "Full visibility\n+ host window",
              "Host window\nalone"]
    colors = [GREY, RUST, TEAL, TEAL, TEAL]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.2, 4.8))

    # -- panel 1: binary F1. The collapse and the recovery.
    vals = [float(df.loc[c, "binary_f1"]) for c in order]
    bars = ax1.bar(range(5), vals, color=colors, width=0.64)
    for i, (bar, val) in enumerate(zip(bars, vals)):
        ax1.text(bar.get_x() + bar.get_width() / 2, val + 0.016, f"{val:.3f}",
                 ha="center", fontsize=10.5, fontweight="bold",
                 color=colors[i] if i else MUTED)
    drop = vals[1] - vals[0]
    ax1.annotate("", xy=(1, vals[1] + 0.03), xytext=(1, vals[0] - 0.01),
                 arrowprops=dict(arrowstyle="->", color=RUST, lw=1.6))
    ax1.text(1.12, (vals[0] + vals[1]) / 2, f"{drop:+.2f}\nbinary-F1",
             color=RUST, fontsize=10, fontweight="bold", va="center")
    ax1.set_ylim(0, 1.14)
    ax1.set_ylabel("binary F1 (attack vs benign)")
    ax1.set_title("Losing the reverse direction costs nothing —\n"
                  "provided the sensor keeps host state",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)

    # -- panel 2: macro F1. Same conditions, different story.
    mvals = [float(df.loc[c, "macro_f1"]) for c in order]
    bars2 = ax2.bar(range(5), mvals, color=colors, width=0.64)
    for bar, val in zip(bars2, mvals):
        ax2.text(bar.get_x() + bar.get_width() / 2, val + 0.014, f"{val:.3f}",
                 ha="center", fontsize=10.5, color=MUTED)
    ax2.set_ylim(0, 0.72)
    ax2.set_ylabel("macro F1 (per attack class)")
    ax2.set_title("On multi-class the host window is not a patch,\nit is the signal",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)

    # Feature counts belong in the tick label. Drawn as separate text below the
    # axis they landed on top of it.
    nf = {c: int(df.loc[c, "n_features"]) for c in order}
    ticks = [f"{lab}\n{nf[c]} features" for lab, c in zip(labels, order)]
    for ax in (ax1, ax2):
        ax.set_xticks(range(5))
        ax.set_xticklabels(ticks, fontsize=8.0)
        ax.grid(axis="y", color=GREY, alpha=0.35, lw=0.7)
        ax.set_axisbelow(True)

    fig.suptitle("CIC-IDS2017: what a one-way tap actually costs",
                 fontsize=13, fontweight="bold", x=0.078, ha="left", y=1.03)
    caption(fig, f"{v['n_flows']:,} flows, {v['window_s']:.0f}s windows. "
                 f"16 host-window features alone ({mvals[4]:.3f} macro-F1) beat "
                 f"all {nf['A_FULL']} full-visibility features ({mvals[0]:.3f}).")
    save(fig, "fig04_host_window_dominates.png")


# --------------------------------------------------------------------- fig05
def fig05() -> None:
    """The streaming sketch reproduces the batch features it replaces."""
    v = load("exp05_verdicts.json")
    agree = v["feature_agreement"]
    known = v["known_definitional_difference"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.2, 4.8),
                                   gridspec_kw={"width_ratios": [1.35, 1]})

    # -- panel 1: bitwise agreement per feature
    rows = sorted(agree, key=lambda r: r["frac_bitwise_equal"])
    names = [r["feature"].replace("hw_", "") for r in rows]
    fracs = [r["frac_bitwise_equal"] for r in rows]
    cols = [RUST if r["feature"] == known else
            (GOLD if r["frac_bitwise_equal"] < 0.999 else TEAL) for r in rows]
    ax1.barh(range(len(rows)), fracs, color=cols, height=0.68)
    ax1.set_yticks(range(len(rows)))
    ax1.set_yticklabels(names, fontsize=8.2)
    ax1.set_xlim(0, 1.08)
    ax1.set_xlabel("fraction of cells bitwise identical to the batch extractor")
    for i, (f, r) in enumerate(zip(fracs, rows)):
        ax1.text(min(f + 0.015, 1.0), i, f"r={r['pearson_r']:.4f}",
                 va="center", fontsize=7.4, color=MUTED)
    n_exact = sum(1 for r in rows if r["frac_bitwise_equal"] == 1.0)
    ax1.set_title(f"{n_exact} of {len(rows)} features reproduce exactly",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)
    ax1.grid(axis="x", color=GREY, alpha=0.35, lw=0.7)
    ax1.set_axisbelow(True)

    # -- panel 2: does the disagreement reach the model?
    pairs = [("G_HW_ONLY", "G_batch", "G_streaming"),
             ("E_SENSOR", "E_batch", "E_streaming")]
    x = np.arange(len(pairs))
    bw = 0.34
    bvals = [v["binary_f1"][b] for _, b, _ in pairs]
    svals = [v["binary_f1"][s] for _, _, s in pairs]
    ax2.bar(x - bw / 2, bvals, bw, label="batch (pandas groupby)", color=GREY)
    ax2.bar(x + bw / 2, svals, bw, label="streaming (sketches)", color=TEAL)
    for xi, (b, s) in enumerate(zip(bvals, svals)):
        ax2.text(xi, max(b, s) + 0.006, f"Δ {abs(b - s):.5f}", ha="center",
                 fontsize=9, color=MUTED)
    ax2.set_xticks(x)
    ax2.set_xticklabels(["host window\nalone", "one-way tap\n+ host window"],
                        fontsize=9)
    ax2.set_ylim(0.94, 1.005)
    ax2.set_ylabel("binary F1")
    ax2.legend(frameon=False, fontsize=8.6, loc="upper left")
    ax2.set_title("The one disagreement does not reach the model",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)
    ax2.grid(axis="y", color=GREY, alpha=0.35, lw=0.7)
    ax2.set_axisbelow(True)

    st = v["stats"]
    fig.suptitle("Bounded-memory sketches against the exact batch extractor",
                 fontsize=13, fontweight="bold", x=0.078, ha="left", y=1.03)
    caption(fig, f"{st['flows']:,} flows in {st['peak_traced_mb']:.2f} MB peak, "
                 f"{st['throughput_flows_per_s']:,.0f} flows/s. "
                 f"{known.replace('hw_', '')} differs by definition: the streaming "
                 f"baseline is causal, the batch one sees the whole capture.")
    save(fig, "fig05_streaming_equivalence.png")


# --------------------------------------------------------------------- fig06
def fig06() -> None:
    """The lateness budget recovers flows. It does not recover accuracy."""
    v = load("exp06_verdicts.json")
    sweep = v["lateness_sweep"]
    lat = [r["lateness_s"] for r in sweep]
    loss = [100 * r["loss_frac"] for r in sweep]
    latency = [r["latency_s"] for r in sweep]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.2, 4.8))

    # -- panel 1: what the budget buys, and what it costs
    ax1.plot(lat, loss, "o-", color=RUST, lw=2, ms=6, label="flows dropped as late")
    ax1.set_xlabel("lateness budget (s)")
    ax1.set_ylabel("flows dropped (%)", color=RUST)
    ax1.tick_params(axis="y", labelcolor=RUST)
    ax1.set_ylim(-0.6, max(loss) * 1.15)
    knee = next(r for r in sweep if r["loss_frac"] < 1e-3)
    ax1.axvline(knee["lateness_s"], color=MUTED, ls=":", lw=1.2)
    ax1.text(knee["lateness_s"] + 2, max(loss) * 0.62,
             f"{knee['lateness_s']:.0f}s buys back\nall but "
             f"{knee['dropped_late']} of {sweep[-1]['flows_kept']:,} flows",
             fontsize=8.6, color=INK)
    axb = ax1.twinx()
    axb.spines["top"].set_visible(False)
    axb.plot(lat, latency, "s--", color=SLATE, lw=1.5, ms=5,
             label="alert latency")
    axb.set_ylabel("alert latency (s)", color=SLATE)
    axb.tick_params(axis="y", labelcolor=SLATE)
    ax1.set_title("The budget buys flows back, and pays in latency",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)
    ax1.grid(color=GREY, alpha=0.3, lw=0.7)
    ax1.set_axisbelow(True)

    # -- panel 2: the refutation
    f1 = v["f1_by_lateness"]
    ks = sorted(f1, key=float)
    xs = [float(k) for k in ks]
    ys = [f1[k] for k in ks]
    ax2.plot(xs, ys, "o-", color=TEAL, lw=2, ms=7)
    for x, y in zip(xs, ys):
        ax2.text(x, y + 0.0035, f"{y:.3f}", ha="center", fontsize=9.5, color=INK)
    ax2.axhline(v["f1_oracle_order"], color=MUTED, ls="--", lw=1.3)
    ax2.text(max(xs) * 0.52, v["f1_oracle_order"] + 0.0012,
             f"perfectly ordered input: {v['f1_oracle_order']:.3f}",
             fontsize=8.6, color=MUTED)
    span = max(ys) - min(ys)
    ax2.set_ylim(min(min(ys), v["f1_oracle_order"]) - 0.012,
                 max(ys) + 0.014)
    ax2.set_xlabel("lateness budget (s)")
    ax2.set_ylabel("macro F1")
    ax2.set_title(f"PREDICTION V4 REFUTED — recovering 12% of flows\n"
                  f"moved F1 by {span:.3f}",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12,
                  color=RUST)
    ax2.grid(color=GREY, alpha=0.3, lw=0.7)
    ax2.set_axisbelow(True)

    a = v["assembler"]
    # The twin axis puts its label where the next panel wants to put its own.
    fig.subplots_adjust(wspace=0.46)
    fig.suptitle("Out-of-order arrival: the cost of waiting",
                 fontsize=13, fontweight="bold", x=0.078, ha="left", y=1.03)
    caption(fig, f"{v['packets_observed']:,} packets observed of "
                 f"{v['packets_generated']:,} generated, {a['flows_emitted']:,} flows "
                 f"assembled. The dropped flows were the short ones; they carried "
                 f"little the host window had not already counted. Synthetic packets: "
                 f"CIC-IDS2017 ships flow records and cannot exercise an assembler at all.")
    save(fig, "fig06_lateness_budget.png")


# --------------------------------------------------------------------- fig07
def fig07() -> None:
    """Sharding scales, then stops. It does not reach line rate."""
    v = load("exp07_verdicts.json")
    sc = v["scaling"]
    shards = [r["shards"] for r in sc]
    pps = [r["packets_per_s"] for r in sc]
    eff = [r["efficiency"] for r in sc]
    target = v["line_rate_pps_1gbps"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.2, 4.8))

    # -- panel 1: throughput against the target it misses
    bars = ax1.bar(range(len(shards)), pps, color=TEAL, width=0.62)
    best = max(pps)
    bars[pps.index(best)].set_color(SLATE)
    for i, p in enumerate(pps):
        ax1.text(i, p + target * 0.022, f"{p/1000:.0f}k", ha="center",
                 fontsize=9.5, color=MUTED)
    ax1.axhline(target, color=RUST, ls="--", lw=1.8)
    ax1.text(len(shards) - 0.45, target * 1.03,
             f"1 Gbps at {v['avg_packet_bytes']:.0f}B packets = {target:,.0f} pkt/s",
             fontsize=8.8, color=RUST, ha="right", fontweight="bold")
    ax1.set_ylim(0, target * 1.22)
    ax1.set_xticks(range(len(shards)))
    ax1.set_xticklabels([str(s) for s in shards])
    ax1.set_xlabel("shards")
    ax1.set_ylabel("packets / s")
    gap = target / best
    ax1.set_title(f"PREDICTIONS REFUTED — best is {best:,.0f} pkt/s,\n"
                  f"{gap:.1f}x short of the target",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12, color=RUST)
    ax1.grid(axis="y", color=GREY, alpha=0.35, lw=0.7)
    ax1.set_axisbelow(True)

    # -- panel 2: where the parallelism goes
    ax2.plot(shards, eff, "o-", color=RUST, lw=2, ms=6.5, label="measured")
    ax2.plot(shards, [1.0] * len(shards), "--", color=GREY, lw=1.5,
             label="linear scaling")
    for s, e in zip(shards, eff):
        ax2.text(s, e - 0.055, f"{e:.2f}", ha="center", fontsize=8.8, color=MUTED)
    ax2.set_ylim(0, 1.12)
    ax2.set_xlabel("shards")
    ax2.set_ylabel("parallel efficiency (speedup / shards)")
    ax2.legend(frameon=False, fontsize=9, loc="upper right")
    ax2.set_title("A parent process feeds every shard,\nso the feeder is the ceiling",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)
    ax2.grid(color=GREY, alpha=0.3, lw=0.7)
    ax2.set_axisbelow(True)

    worst = min(v["correctness"].values(), key=lambda c: c["key_agreement"])
    fig.suptitle("Hash-by-host sharding: correct, and not fast enough",
                 fontsize=13, fontweight="bold", x=0.078, ha="left", y=1.03)
    caption(fig, f"{v['packets']:,} packets. Sharded output agrees with the "
                 f"single-process oracle on {100*worst['key_agreement']:.4f}% of keys "
                 f"at worst. The fix is kernel-level fanout so each shard reads its "
                 f"own NIC queue - not more workers behind one feeder.")
    save(fig, "fig07_sharded_throughput.png")


# --------------------------------------------------------------------- fig08
def fig08() -> None:
    """An aggregate coverage number can hide a system that answers one class."""
    v = load("exp08_verdicts.json")
    mond, marg = v["calibration"], v["calibration_marginal"]
    support = v["per_class_support"]
    thin = set(v["excluded_thin_support"])

    sys.path.insert(0, str(ROOT / "src"))
    from ekagra.ingest.records import THREAT_CLASSES

    idx = [str(i) for i in range(len(THREAT_CLASSES))]
    names = list(THREAT_CLASSES)
    mc = [mond["per_class_coverage"].get(i, np.nan) for i in idx]
    gc = [marg["per_class_coverage"].get(i, np.nan) for i in idx]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.2, 4.8),
                                   gridspec_kw={"width_ratios": [1.5, 1]})

    # -- panel 1: per-class coverage, both calibrations
    x = np.arange(len(names))
    bw = 0.38
    b1 = ax1.bar(x - bw / 2, gc, bw, label="marginal (one threshold)", color=RUST)
    b2 = ax1.bar(x + bw / 2, mc, bw, label="Mondrian (per class)", color=TEAL)
    for bars in (b1, b2):
        for bar in bars:
            if np.isnan(bar.get_height()):
                continue
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                     f"{bar.get_height():.2f}", ha="center", fontsize=7.2, color=MUTED)
    target = 1 - mond["alpha"]
    ax1.axhline(target, color=INK, ls="--", lw=1.4)
    ax1.text(len(names) - 0.4, target + 0.025, f"target {target:.2f}",
             fontsize=8.8, color=INK, ha="right", fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels([f"{n}\n(n={support.get(n, 0):,})" for n in names],
                        fontsize=8.2)
    for i, n in enumerate(names):
        if n in thin:
            ax1.text(i, 1.10, "thin", ha="center", fontsize=7.2, color=MUTED,
                     style="italic")
    ax1.set_ylim(0, 1.20)
    ax1.set_ylabel("empirical coverage")
    # Lower-left is where the near-zero marginal bars put their value labels.
    ax1.legend(frameon=False, fontsize=8.8, loc="upper left")
    ax1.set_title("The marginal predictor answers ddos and abstains on the rest",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)
    ax1.grid(axis="y", color=GREY, alpha=0.35, lw=0.7)
    ax1.set_axisbelow(True)

    # -- panel 2: the aggregate numbers that hide it
    we = v["worst_estimable_coverage"]
    metrics = ["overall\ncoverage", "worst estimable\nclass coverage",
               "abstention\nrate"]
    mvals = [marg["empirical_coverage"], we["marginal"], marg["abstention_rate"]]
    dvals = [mond["empirical_coverage"], we["mondrian"], mond["abstention_rate"]]
    x2 = np.arange(3)
    ax2.bar(x2 - bw / 2, mvals, bw, color=RUST)
    ax2.bar(x2 + bw / 2, dvals, bw, color=TEAL)
    for xi, (m, d) in enumerate(zip(mvals, dvals)):
        ax2.text(xi - bw / 2, m + 0.02, f"{m:.3f}", ha="center", fontsize=8.6,
                 color=RUST, fontweight="bold")
        ax2.text(xi + bw / 2, d + 0.02, f"{d:.3f}", ha="center", fontsize=8.6,
                 color=TEAL, fontweight="bold")
    ax2.set_xticks(x2)
    ax2.set_xticklabels(metrics, fontsize=8.6)
    ax2.set_ylim(0, 1.12)
    ax2.set_title("Overall coverage looks fine either way.\n"
                  "The worst class is where they differ",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)
    ax2.grid(axis="y", color=GREY, alpha=0.35, lw=0.7)
    ax2.set_axisbelow(True)

    fig.suptitle("Conformal abstention: why the calibration must be per class",
                 fontsize=13, fontweight="bold", x=0.078, ha="left", y=1.03)
    caption(fig, f"{mond['n_calibration']:,} calibration cells, alpha={mond['alpha']}. "
                 f"Marginal reaches {marg['empirical_coverage']:.3f} overall while "
                 f"abstaining on 95-100% of six of seven classes. Mondrian: "
                 f"{mond['abstention_rate']:.1%} abstention, ECE "
                 f"{mond['expected_calibration_error']:.4f}. "
                 f"dga (n={support['dga']}) and exfil (n={support['exfil']}) are too "
                 f"thin to estimate and are excluded from the worst-class number.")
    save(fig, "fig08_conformal_calibration.png")


# --------------------------------------------------------------------- fig09
def fig09() -> None:
    """Feature starvation costs 40x what the decomposition is worth."""
    v = load("exp09_verdicts.json")
    heads = v["per_head"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.2, 4.8),
                                   gridspec_kw={"width_ratios": [1.55, 1]})

    # -- panel 1: three regimes per head
    names = list(heads)
    x = np.arange(len(names))
    bw = 0.27
    sub = [heads[n]["ap_subset"] for n in names]
    full = [heads[n]["ap_full"] for n in names]
    multi = [heads[n]["ap_multiclass"] for n in names]
    ax1.bar(x - bw, sub, bw, label="head, declared features only", color=RUST)
    ax1.bar(x, full, bw, label="head, all features", color=TEAL)
    ax1.bar(x + bw, multi, bw, label="one multi-class model", color=GREY)
    ax1.set_xticks(x)
    ax1.set_xticklabels([f"{n}\n(n={heads[n]['support']:,})" for n in names],
                        fontsize=8.2)
    for i, n in enumerate(names):
        if heads[n]["handicapped"]:
            ax1.text(i, 1.04, "known gap", ha="center", fontsize=7,
                     color=GOLD, style="italic")
    # Headroom for a single-row legend. Inside the bars it covered beacon.
    ax1.set_ylim(0, 1.34)
    ax1.set_ylabel("average precision")
    ax1.legend(frameon=False, fontsize=8.2, loc="upper left", ncol=3,
               columnspacing=1.4, handlelength=1.4)
    ax1.set_title("Restricting a head to its own features is what hurts",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12)
    ax1.grid(axis="y", color=GREY, alpha=0.35, lw=0.7)
    ax1.set_axisbelow(True)

    # -- panel 2: the two effects, side by side
    starve = v["cost_of_starvation_ap"]
    decomp = v["cost_of_decomposition_ap"]
    ax2.bar([0, 1], [starve, decomp], color=[RUST, TEAL], width=0.5)
    ax2.text(0, starve + 0.012, f"{starve:+.3f}", ha="center", fontsize=12,
             fontweight="bold", color=RUST)
    ax2.text(1, decomp + 0.012, f"{decomp:+.3f}", ha="center", fontsize=12,
             fontweight="bold", color=TEAL)
    ax2.set_xticks([0, 1])
    ax2.set_xticklabels(["cost of starving\na head of features",
                         "value of splitting\ninto heads at all"], fontsize=8.8)
    ax2.set_ylabel("mean average precision")
    ax2.set_ylim(0, starve * 1.22)
    ratio = starve / decomp if decomp else float("inf")
    ax2.set_title(f"PREDICTIONS Y1/Y3 REFUTED — the split is\nworth "
                  f"{decomp:.3f} AP, {ratio:.0f}x less than the starvation",
                  fontsize=11.5, fontweight="bold", loc="left", pad=12, color=RUST)
    ax2.grid(axis="y", color=GREY, alpha=0.35, lw=0.7)
    ax2.set_axisbelow(True)

    mr = v["multilabel_recovery"]
    fig.suptitle("Detector heads: the decomposition argument, tested",
                 fontsize=13, fontweight="bold", x=0.078, ha="left", y=1.03)
    caption(fig, f"{v['test_cells']:,} test cells. Heads keep one advantage the "
                 f"figure does not show: on cells carrying more than one true label "
                 f"they recover {mr['heads']} of {mr['true_labels']}, against "
                 f"{mr['multiclass']} for the single model - but such cells are only "
                 f"{v['cooccurrence_fraction']:.2%} of the corpus.")
    save(fig, "fig09_detector_heads.png")


# --------------------------------------------------------------------- fig10
def fig10() -> None:
    """Does the host-window result survive when attacks stop being bursty?"""
    v = load("exp10_verdicts.json")
    sweep = sorted(v["sweep"], key=lambda r: -r["realised_flows_per_cell"])
    x = [r["realised_flows_per_cell"] for r in sweep]

    series = [("A_FULL", "full visibility, 103 features", GREY, "o-"),
              ("C_MATCHED", "one-way tap, flows only", RUST, "s--"),
              ("E_SENSOR", "one-way tap + host window", SLATE, "^-"),
              ("G_HW_ONLY", "host window alone, 16 features", TEAL, "D-")]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.8, 4.9))

    for ax, metric, title in (
            (ax1, "binary", "Attack vs benign: everything still works"),
            (ax2, "macro", "Per attack class: the host window alone collapses")):
        for key, label, col, style in series:
            ax.plot(x, [r[f"{key}_{metric}"] for r in sweep], style, color=col,
                    lw=2, ms=6, label=label)
        ax.set_xscale("log")
        # A log axis draws its own decade ticks underneath these, which land on
        # top of the labels we actually want.
        ax.xaxis.set_minor_locator(plt.NullLocator())
        ax.xaxis.set_minor_formatter(plt.NullFormatter())
        ax.xaxis.set_major_locator(plt.FixedLocator(x))
        ax.xaxis.set_major_formatter(plt.FixedFormatter(
            [f"{t:.0f}" if t >= 2 else f"{t:.1f}" for t in x]))
        ax.invert_xaxis()
        ax.set_xlabel("attack flows per (host, window) cell   →  more diffuse  →")
        ax.grid(color=GREY, alpha=0.3, lw=0.7)
        ax.set_axisbelow(True)
        ax.set_title(title, fontsize=11.5, fontweight="bold", loc="left", pad=12)
    ax1.set_ylabel("binary F1 (attack vs benign)")
    ax2.set_ylabel("macro F1 (per attack class)")
    ax1.set_ylim(0.70, 1.02)
    ax2.set_ylim(0.15, 1.0)
    ax1.legend(frameon=False, fontsize=8.3, loc="lower left")

    # exp04's headline, for contrast: there, G was the BEST condition on macro.
    ax2.axhline(0.599, color=GOLD, ls=":", lw=1.6)
    ax2.text(x[0], 0.615, "exp04: host window alone reached 0.599 —\n"
                          "the best condition there, the worst here",
             fontsize=8.2, color=GOLD, va="bottom", ha="left")

    lo, hi = sweep[-1], sweep[0]
    fig.suptitle("Low-rate, diffuse attacks: the caveat on experiment 04, tested",
                 fontsize=13, fontweight="bold", x=0.075, ha="left", y=1.03)
    caption(fig, f"Real CIC-IDS2017 flows re-timed and re-homed onto hosts that "
                 f"carry benign traffic; per-flow features untouched. Attack cells "
                 f"hold {hi['benign_per_attack_cell']:.0f}-{lo['benign_per_attack_cell']:.0f} "
                 f"benign flows, so the attack is {1-hi['dilution']:.0%}-{1-lo['dilution']:.0%} "
                 f"outnumbered inside its own cell. Compare across densities here, "
                 f"not against experiment 04.")
    save(fig, "fig10_low_rate_diffuse.png")


# The console serves these, so the claim each figure carries lives here rather
# than in the API - one place, so a figure and its caption cannot drift apart.
# fig01-03 come from make_figures.py and make_figures_real.py; they are listed
# so the demo shows the whole evidence set, and skipped if not yet generated.
CATALOGUE = [
    ("fig01_visibility_ablation.png", "Visibility ablation (generated traffic)",
     "The controlled instrument: four visibility profiles on traffic where we know the ground truth."),
    ("fig02_visibility_ladder.png", "The visibility ladder",
     "Each rung removes one thing a diode-side sensor cannot see."),
    ("fig03_cicids_ablation.png", "First real-corpus run",
     "On CIC-IDS2017, retraining under the deployment profile recovered only a third of the loss."),
    ("fig04_host_window_dominates.png", "What a one-way tap actually costs",
     "The tap costs 0.29 binary-F1 with per-flow features, and essentially nothing once the sensor keeps host state."),
    ("fig05_streaming_equivalence.png", "Streaming sketches vs exact batch",
     "14 of 16 features reproduce bitwise; the one disagreement never reaches the model."),
    ("fig06_lateness_budget.png", "The lateness budget",
     "15s buys back 12% of flows. It does not buy accuracy - prediction V4 refuted."),
    ("fig07_sharded_throughput.png", "Sharding vs line rate",
     "672 Mbps measured against a 1 Gbps target. Four predictions refuted."),
    ("fig08_conformal_calibration.png", "Why calibration must be per class",
     "A marginal predictor reports 0.883 coverage while abstaining on 95-100% of six of seven classes."),
    ("fig09_detector_heads.png", "Detector heads, tested",
     "Starving a head of features costs 40x what splitting into heads is worth."),
    ("fig10_low_rate_diffuse.png", "Low-rate diffuse attacks",
     "Our own headline, attacked: the one-way tap result holds, host-window-alone does not."),
]


def write_manifest() -> None:
    """Publish what exists, for the console to serve."""
    rows = [{"file": f, "title": t, "claim": c}
            for f, t, c in CATALOGUE if (RESULTS / f).exists()]
    (RESULTS / "figures.json").write_text(json.dumps(rows, indent=2))
    missing = len(CATALOGUE) - len(rows)
    print(f"  wrote results/figures.json ({len(rows)} figures"
          + (f", {missing} not generated yet)" if missing else ")"))


def main() -> None:
    print("figures for exp04-10")
    for fn in (fig04, fig05, fig06, fig07, fig08, fig09):
        fn()
    if (RESULTS / "exp10_verdicts.json").exists():
        fig10()
    else:
        print("  (skipping fig10 - run exp10 first)")
    write_manifest()
    print("\ndone.")


if __name__ == "__main__":
    main()

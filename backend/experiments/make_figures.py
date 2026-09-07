"""Figures for the ablation study.

Two panels, deliberately. The left one is the whole argument; the right one is
the evidence that it is not an averaging artefact.

Run after exp01:  python experiments/make_figures.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

INK = "#141918"
MUTED = "#67746F"
TEAL = "#0B6B63"
RUST = "#A3341F"
GREY = "#B0BAB7"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.edgecolor": MUTED,
    "axes.labelcolor": INK,
    "text.color": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.titlesize": 12,
    "figure.dpi": 140,
})


def main() -> None:
    csv = RESULTS / "exp01_ablation.csv"
    if not csv.exists():
        sys.exit("run experiments/exp01_ablation.py first")
    df = pd.read_csv(csv)

    full = df[df.condition == "A_FULL"].iloc[0]
    ow = df[df.rung == "DIODE_ONEWAY"].set_index("condition")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.5, 4.6),
                                   gridspec_kw={"width_ratios": [1, 1.35]})

    # ---------------------------------------------------------------- panel 1
    labels = ["Full\nvisibility",
              "Deployed on\none-way tap",
              "Retrained under\ndeployment profile"]
    vals = [full.macro_f1, ow.loc["B_DEPLOYED"].macro_f1, ow.loc["C_RETRAINED"].macro_f1]
    colors = [GREY, RUST, TEAL]

    bars = ax1.bar(range(3), vals, color=colors, width=0.62)
    for i, (b, v) in enumerate(zip(bars, vals)):
        ax1.text(b.get_x() + b.get_width() / 2, v + 0.018, f"{v:.3f}",
                 ha="center", fontsize=11, fontweight="bold",
                 color=colors[i] if i else MUTED)

    drop = vals[1] - vals[0]
    ax1.annotate("", xy=(1, vals[1] + 0.03), xytext=(1, vals[0] - 0.01),
                 arrowprops=dict(arrowstyle="->", color=RUST, lw=1.6))
    ax1.text(1.08, (vals[0] + vals[1]) / 2, f"{drop:+.2f}\nmacro-F1",
             color=RUST, fontsize=10, fontweight="bold", va="center")

    ax1.set_xticks(range(3))
    ax1.set_xticklabels(labels, fontsize=9.5)
    ax1.set_ylim(0, 1.08)
    ax1.set_ylabel("macro-F1", fontsize=10)
    ax1.set_title("The cost of a visibility mismatch", fontweight="bold", loc="left", pad=12)
    ax1.grid(axis="y", color="#E3E8E6", lw=0.8)
    ax1.set_axisbelow(True)

    # ---------------------------------------------------------------- panel 2
    classes = ["ddos", "beacon", "dga", "encrypted", "scan", "exfil"]
    a = [full[c] for c in classes]
    b = [ow.loc["B_DEPLOYED"][c] for c in classes]
    c_ = [ow.loc["C_RETRAINED"][c] for c in classes]

    x = range(len(classes))
    w = 0.27
    ax2.bar([i - w for i in x], a, w, label="full visibility", color=GREY)
    ax2.bar(list(x), b, w, label="deployed on one-way tap", color=RUST)
    ax2.bar([i + w for i in x], c_, w, label="retrained under profile", color=TEAL)

    for i, (bv, av) in enumerate(zip(b, a)):
        if av - bv > 0.5:
            ax2.text(i, bv + 0.03, "collapse", ha="center", fontsize=8.5,
                     color=RUST, fontweight="bold", rotation=90)

    ax2.set_xticks(list(x))
    ax2.set_xticklabels(classes, fontsize=9.5)
    ax2.set_ylim(0, 1.13)
    ax2.set_ylabel("per-class F1", fontsize=10)
    ax2.set_title("Which threat classes lose the reverse channel",
                  fontweight="bold", loc="left", pad=12)
    ax2.legend(frameon=False, fontsize=9, ncol=1, loc="lower left")
    ax2.grid(axis="y", color="#E3E8E6", lw=0.8)
    ax2.set_axisbelow(True)

    fig.suptitle(
        "EKAGRA · SIH26145 · detectors trained on bidirectional traffic fail on a one-way tap — "
        "and matched retraining fixes it",
        fontsize=10.5, color=MUTED, y=1.005, x=0.005, ha="left")
    fig.tight_layout()
    out = RESULTS / "fig01_visibility_ablation.png"
    fig.savefig(out, bbox_inches="tight", facecolor="white")
    print(f"wrote {out}")

    # ------------------------------------------------- ladder figure (support)
    fig2, ax = plt.subplots(figsize=(7.6, 4.2))
    rungs = ["DIODE_FULL", "DIODE_ONEWAY", "DIODE_ONEWAY_SAMPLED"]
    nice = ["both directions\nno enrichment", "one-way tap", "one-way\n+ 1:16 sampled"]
    dep = [df[(df.rung == r) & (df.condition == "B_DEPLOYED")].macro_f1.iloc[0] for r in rungs]
    ret = [df[(df.rung == r) & (df.condition == "C_RETRAINED")].macro_f1.iloc[0] for r in rungs]

    ax.axhline(full.macro_f1, color=MUTED, ls="--", lw=1.2)
    ax.text(2.42, full.macro_f1 + 0.012, "full visibility", fontsize=9, color=MUTED, ha="right")
    ax.plot(range(3), dep, "o-", color=RUST, lw=2, ms=7, label="naive deployment")
    ax.plot(range(3), ret, "o-", color=TEAL, lw=2, ms=7, label="visibility-matched retraining")
    ax.set_xticks(range(3))
    ax.set_xticklabels(nice, fontsize=9.5)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("macro-F1", fontsize=10)
    ax.set_title("Degradation across the visibility ladder", fontweight="bold", loc="left", pad=12)
    ax.legend(frameon=False, fontsize=9)
    ax.grid(axis="y", color="#E3E8E6", lw=0.8)
    ax.set_axisbelow(True)
    fig2.tight_layout()
    out2 = RESULTS / "fig02_visibility_ladder.png"
    fig2.savefig(out2, bbox_inches="tight", facecolor="white")
    print(f"wrote {out2}")


if __name__ == "__main__":
    main()

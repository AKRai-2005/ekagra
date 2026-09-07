"""Figures for the real-corpus ablation, and the synthetic-vs-real comparison.

The second panel is the one that matters: if the generated traffic and the real
capture show the same shape of degradation, the synthetic study earns its place
as a controlled instrument rather than a substitute for evidence. If they
disagree, that is worth knowing and gets shown rather than hidden.

Run after exp01 and exp03:  python experiments/make_figures_real.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

INK, MUTED = "#141918", "#67746F"
TEAL, RUST, GREY = "#0B6B63", "#A3341F", "#B0BAB7"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "axes.spines.top": False, "axes.spines.right": False,
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "figure.dpi": 140,
})


def main() -> None:
    real_csv = RESULTS / "exp03_cicids_ablation.csv"
    if not real_csv.exists():
        sys.exit("run experiments/exp03_cicids_ablation.py first")
    real = pd.read_csv(real_csv).set_index("condition")
    verd = json.loads((RESULTS / "exp03_verdicts.json").read_text())

    a = float(real.loc["A_FULL", "binary_f1"])
    b = float(real.loc["B_DEPLOYED", "binary_f1"])
    c = float(real.loc["C_MATCHED", "binary_f1"])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.5, 4.6),
                                   gridspec_kw={"width_ratios": [1, 1.25]})

    # -------------------------------------------------- panel 1: real corpus
    labels = ["Full\nvisibility", "Deployed on\none-way tap",
              "Retrained under\ndeployment profile"]
    vals, colors = [a, b, c], [GREY, RUST, TEAL]
    bars = ax1.bar(range(3), vals, color=colors, width=0.62)
    for i, (bar, v) in enumerate(zip(bars, vals)):
        ax1.text(bar.get_x() + bar.get_width() / 2, v + 0.018, f"{v:.3f}",
                 ha="center", fontsize=11, fontweight="bold",
                 color=colors[i] if i else MUTED)
    ax1.annotate("", xy=(1, b + 0.03), xytext=(1, a - 0.01),
                 arrowprops=dict(arrowstyle="->", color=RUST, lw=1.6))
    ax1.text(1.08, (a + b) / 2, f"{b - a:+.2f}\nbinary-F1", color=RUST,
             fontsize=10, fontweight="bold", va="center")
    ax1.set_xticks(range(3)); ax1.set_xticklabels(labels, fontsize=9.5)
    ax1.set_ylim(0, 1.08); ax1.set_ylabel("binary F1", fontsize=10)
    ax1.set_title("CIC-IDS2017 — real captured traffic", fontweight="bold",
                  loc="left", pad=12)
    ax1.grid(axis="y", color="#E3E8E6", lw=0.8); ax1.set_axisbelow(True)

    # -------------------------------- panel 2: synthetic vs real, same shape?
    syn_csv = RESULTS / "exp01_ablation.csv"
    if syn_csv.exists():
        syn = pd.read_csv(syn_csv)
        sa = float(syn[syn.condition == "A_FULL"].macro_f1.iloc[0])
        sb = float(syn[(syn.rung == "DIODE_ONEWAY") &
                       (syn.condition == "B_DEPLOYED")].macro_f1.iloc[0])
        sc = float(syn[(syn.rung == "DIODE_ONEWAY") &
                       (syn.condition == "C_RETRAINED")].macro_f1.iloc[0])

        x = range(3)
        w = 0.36
        ax2.bar([i - w / 2 for i in x], [sa, sb, sc], w,
                label="generated traffic (macro-F1)", color=GREY)
        ax2.bar([i + w / 2 for i in x], [a, b, c], w,
                label="CIC-IDS2017 (binary-F1)", color=TEAL)
        for i, (sv, rv) in enumerate(zip([sa, sb, sc], [a, b, c])):
            ax2.text(i - w / 2, sv + 0.015, f"{sv:.2f}", ha="center", fontsize=8.5,
                     color=MUTED)
            ax2.text(i + w / 2, rv + 0.015, f"{rv:.2f}", ha="center", fontsize=8.5,
                     color=TEAL, fontweight="bold")
        ax2.set_xticks(list(x))
        ax2.set_xticklabels(["full", "deployed on\none-way tap", "matched\nretraining"],
                            fontsize=9.5)
        ax2.set_ylim(0, 1.15); ax2.set_ylabel("F1", fontsize=10)
        ax2.set_title("Does the generated study predict the real one?",
                      fontweight="bold", loc="left", pad=12)
        ax2.legend(frameon=False, fontsize=9, loc="lower left")
        ax2.grid(axis="y", color="#E3E8E6", lw=0.8); ax2.set_axisbelow(True)
        ax2.text(0.99, 0.97,
                 f"drop: generated {sb - sa:+.2f}   real {b - a:+.2f}",
                 transform=ax2.transAxes, ha="right", va="top", fontsize=9,
                 color=MUTED)

    n = verd.get("n_flows_used", 0)
    fig.suptitle(f"EKAGRA · SIH26145 · visibility ablation on {n:,} real flows "
                 f"(corrected CIC-IDS2017, temporal split)",
                 fontsize=10.5, color=MUTED, y=1.005, x=0.005, ha="left")
    fig.tight_layout()
    out = RESULTS / "fig03_cicids_ablation.png"
    fig.savefig(out, bbox_inches="tight", facecolor="white")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

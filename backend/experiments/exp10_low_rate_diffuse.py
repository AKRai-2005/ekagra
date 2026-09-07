"""Experiment 10 — does the host-window result survive low-rate, diffuse attacks?

The claim under test
--------------------
Experiment 04 is this project's headline: on CIC-IDS2017 a one-way tap costs
essentially nothing once the sensor keeps windowed host state (0.981 vs 0.979
binary-F1), and 16 host-window aggregates alone beat all 103 full-visibility
features. Every number in it came from a corpus whose attacks are **bursty** -
DDoS and port scans that dump hundreds of flows into one 60-second cell.

The obvious objection, which we have written into the architecture doc as an
open caveat rather than answered: a per-cell aggregate is trivially powerful
when a cell is nothing but attack. What happens when the attack is slow?

This matters for the deployment being argued for. A critical-infrastructure
enclave watched through a one-way tap is precisely where low-and-slow behaviour
is expected - scans paced under threshold alarms, beacons at minutes to hours,
exfiltration in small chunks. If host-window aggregates only work on bursts,
the architecture claim must be narrowed to say so.

The instrument
--------------
`ingest/diffuse.py` rearranges the real corpus instead of generating a new one.
Attack flows keep every per-flow feature they were measured with; only their
timestamps and source addresses move, so that a campaign puts `d` flows into a
(host, window) cell instead of its original burst, on a host that also carries
benign traffic. Density is then the single variable across the sweep.

Sweep:  d = 64, 16, 4, 1 attack flows per cell.

A capacity limit, measured before running
-----------------------------------------
Reaching d=1 needs one (host, window) cell per attack flow. This corpus offers
15 internal hosts carrying benign traffic across a 6,246-window capture, so
about 93,690 cells exist - against 428,196 attack flows in the exp04 subsample.
Left alone, the low end of the sweep would floor out at ~4.6 flows per cell and
report **capacity** as though it were density.

So the attack set is capped once, before the sweep, at 15,000 flows filled
smallest-class-first. Every density point then sees identical attack rows:
volume is held constant and density is the only thing that moves. Z0 below
checks the limit was actually respected.

The cap sits well under capacity on purpose. Placement is weighted toward
windows where the host was already busy (see `hide_in_traffic` in the transform),
and asking for more cells than there are busy ones would push the attack back
out into quiet windows, where a flow sits *alone* in its cell rather than hidden
in it - which is a different scenario, and an easier one to detect. The side
effect of the cap is an attack rate near 1.6%, closer to what a monitored
network actually sees than exp04's 49% subsample.

Conditions, matching experiment 04 so the ladder is the same one:
  A  FULL      103 features, both directions
  C  MATCHED    35 forward-observable features only
  E  SENSOR     35 forward + 16 host-window aggregates
  G  HW ONLY    16 host-window aggregates alone

Pre-registered predictions (written before the first run)
---------------------------------------------------------
  Z0  CAPACITY CONTROL. Every requested density is physically reachable - no
      campaign ran out of cells. If this fails the affected point measured the
      blend pool's size, not the attack's rate, and must be discarded.
  Z1  VALIDITY CONTROL. At d=64, G reaches >= 0.85 binary-F1. The bursty end of
      the sweep should reproduce experiment 04's regime. If it does not, the
      manipulation broke something other than density and nothing below is
      interpretable.
  Z2  G loses >= 0.15 binary-F1 going from d=64 to d=1.
  Z3  At d=1, A beats G by > 0.10 binary-F1 - experiment 04's ordering reverses.
  Z4  The cost of the one-way tap, A - C, is LARGER at d=1 than at d=64. This is
      the operationally important one: it would mean the visibility question
      this project is named for becomes decisive exactly in the regime the
      threat model cares about.
  Z5  NEGATIVE CONTROL. With labels permuted at d=1, every condition falls below
      0.55 binary-F1, confirming the re-homing did not introduce a shortcut.

Reading the numbers
-------------------
Compare **across densities within this experiment**. Absolute values are not
comparable to experiment 04: diffusion also destroys the campaign ordering that
gave exp04 its test-only classes, which changes the task. And the per-flow
conditions are flattered - a real slow adversary would likely also make single
flows less distinctive, whereas here each attack flow keeps the discriminative
power it had inside its burst. A and C are optimistic bounds.

Run:  python experiments/exp10_low_rate_diffuse.py            (~30 min)
      python experiments/exp10_low_rate_diffuse.py --quick    (small, for checks)
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.features.host_window import (  # noqa: E402
    HOST_WINDOW_FEATURES, WINDOW_S, add_host_window_features,
)
from ekagra.ingest.diffuse import DiffusionConfig, diffuse_attacks  # noqa: E402
from ekagra.ingest.replay import (  # noqa: E402
    BACKWARD_DERIVED, BIDIRECTIONAL_AGGREGATE, FORWARD_OBSERVABLE,
    CICIDS2017, load_subsampled,
)

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
SEED = 0
TRAIN_FRACTION = 0.70
DENSITIES = [64.0, 16.0, 4.0, 1.0]
ATTACK_BUDGET = 15_000


def shrink(df: pd.DataFrame) -> pd.DataFrame:
    """Halve the frame's footprint before the sweep multiplies it.

    This experiment holds the corpus, a diffused copy, and a dense feature
    matrix at the same time, three times over per density. On a 16 GB machine
    with ~2 GB free that was enough to get the process killed by the OS - no
    traceback, no stderr, just a dead PID and a truncated log, which is a
    genuinely confusing way to fail.

    Two easy wins: the flow features are measured quantities that do not need
    float64, and `Flow ID` is a long string nothing reads.
    """
    before = df.memory_usage(deep=True).sum() / 1e6
    df = df.drop(columns=[c for c in ("Flow ID",) if c in df.columns])
    for c in df.select_dtypes(include=["float64"]).columns:
        df[c] = df[c].astype(np.float32)
    for c in df.select_dtypes(include=["int64"]).columns:
        df[c] = pd.to_numeric(df[c], downcast="integer")
    # The address columns stay as objects on purpose. Making them categorical
    # would save more, but the host-window features group by them, and a
    # groupby over a categorical can materialise the full category cross
    # product - trading a memory problem for a much larger one.
    after = df.memory_usage(deep=True).sum() / 1e6
    print(f"      frame {before:,.0f} MB -> {after:,.0f} MB")
    return df


def budget_attacks(df: pd.DataFrame, budget: int, seed: int = 0) -> pd.DataFrame:
    """Cap the attack set so the low end of the sweep is physically reachable.

    At d=1 every attack flow needs its own (host, window) cell, and the capture
    only offers `blend hosts x windows` of them. CIC-IDS2017's testbed has few
    internal machines, so with the full attack set the requested density cannot
    be met and the sweep quietly floors out at whatever the capacity allows -
    measuring capacity instead of density, which is the one thing this
    experiment exists to vary.

    The cap is applied once, before the sweep, so every density point sees the
    identical attack rows. Volume is held constant; density is the only thing
    that moves. It also brings the class balance closer to the corpus's real
    ~22% attack rate than exp04's 49% subsample.

    Classes are filled smallest-first: a rare class is kept whole, and what is
    left over is split among the large ones. Losing exfil to make room for more
    DDoS would defeat the purpose.
    """
    rng = np.random.default_rng(seed)
    atk = df["Label"] != "BENIGN"
    counts = df.loc[atk, "Label"].value_counts().sort_values()

    take, remaining = {}, budget
    for i, (label, n) in enumerate(counts.items()):
        share = remaining // (len(counts) - i)
        take[label] = int(min(n, share))
        remaining -= take[label]

    keep_idx = [df.index[~atk].to_numpy()]
    for label, k in take.items():
        pos = df.index[atk & (df["Label"] == label)].to_numpy()
        keep_idx.append(rng.choice(pos, size=k, replace=False) if k < len(pos) else pos)

    out = df.loc[np.concatenate(keep_idx)].sort_values("Timestamp").reset_index(drop=True)
    kept = out["Label"].value_counts()
    print(f"      attack budget {budget:,}: " +
          ", ".join(f"{c} {kept.get(c, 0):,}/{counts[c]:,}" for c in counts.index))
    return out


def to_matrix(df: pd.DataFrame, cols) -> np.ndarray:
    x = df[list(cols)].apply(pd.to_numeric, errors="coerce")
    return x.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)


def fit(X, y, n_classes, n_estimators=150):
    m = XGBClassifier(n_estimators=n_estimators, max_depth=7, learning_rate=0.15,
                      subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                      objective="multi:softprob", num_class=n_classes,
                      n_jobs=4, eval_metric="mlogloss", random_state=SEED)
    m.fit(X, y)
    return m


def evaluate_density(df: pd.DataFrame, d: float, quick: bool,
                     permute: bool = False) -> dict:
    """Diffuse to density `d`, rebuild the window features, run the ladder."""
    cfg = DiffusionConfig(flows_per_cell=d, window_s=WINDOW_S, seed=SEED)
    t = time.time()
    dif, stats = diffuse_attacks(df, cfg)
    print(f"      diffused in {time.time()-t:.1f}s   "
          f"{stats['attack_cells']:,} attack cells, "
          f"{stats['realised_flows_per_cell']:.1f} flows/cell, "
          f"dilution {stats['dilution']:.3f}")

    t = time.time()
    dif = add_host_window_features(dif, window_s=WINDOW_S)
    print(f"      host-window features in {time.time()-t:.1f}s")

    if permute:
        # Permute within the split-defining order so the label distribution and
        # the temporal split are untouched; only the pairing is destroyed.
        rng = np.random.default_rng(SEED)
        dif["Label"] = dif["Label"].to_numpy()[rng.permutation(len(dif))]

    wq = dif["window"].quantile(TRAIN_FRACTION)
    cutoff = int(np.floor(wq))
    tr = (dif["window"] <= cutoff).to_numpy()
    te = ~tr

    train_labels = sorted(set(dif.loc[tr, "Label"]))
    idx = {c: i for i, c in enumerate(train_labels)}
    if "BENIGN" not in idx:
        raise RuntimeError("training split contains no benign flows")
    benign_i = idx["BENIGN"]

    y_tr = dif.loc[tr, "Label"].map(idx).to_numpy()
    te_lab = dif.loc[te, "Label"]
    te_known = te_lab.isin(train_labels).to_numpy()
    y_te = te_lab.map(idx).fillna(-1).astype(int).to_numpy()
    y_bin = (te_lab != "BENIGN").astype(int).to_numpy()

    full = [c for c in FORWARD_OBSERVABLE + BACKWARD_DERIVED + BIDIRECTIONAL_AGGREGATE
            if c in dif.columns]
    fwd = [c for c in FORWARD_OBSERVABLE if c in dif.columns]
    sensor = fwd + HOST_WINDOW_FEATURES

    n_trees = 60 if quick else 150
    out = {"density": d, **stats,
           "train_rows": int(tr.sum()), "test_rows": int(te.sum()),
           "n_classes": len(train_labels)}

    for name, cols in (("A_FULL", full), ("C_MATCHED", fwd),
                       ("E_SENSOR", sensor), ("G_HW_ONLY", list(HOST_WINDOW_FEATURES))):
        X = to_matrix(dif, cols)
        m = fit(X[tr], y_tr, len(train_labels), n_trees)
        pred = m.predict(X[te])
        macro = f1_score(y_te[te_known], pred[te_known], average="macro",
                         zero_division=0)
        binf = f1_score(y_bin, (pred != benign_i).astype(int), average="macro",
                        zero_division=0)
        out[f"{name}_macro"] = float(macro)
        out[f"{name}_binary"] = float(binf)
        print(f"      {name:<12s} macro-F1 {macro:.4f}   binary-F1 {binf:.4f}")
        del X, m, pred
        gc.collect()

    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true",
                    help="small subsample and shallow forests, for checking the "
                         "mechanics rather than producing a result")
    args = ap.parse_args()

    t_all = time.time()
    print("=" * 78)
    print("EKAGRA  ·  Experiment 10  ·  Does the host-window result survive")
    print("                             low-rate, temporally diffuse attacks?")
    print("=" * 78)
    if args.quick:
        print("  QUICK MODE - mechanics check only, not a result.")

    ds = CICIDS2017()
    if not Path(ds.path).exists():
        sys.exit(f"corpus not found at {ds.path}")

    # More benign than exp04's 0.30, deliberately: dilution is what drives this
    # result, and it is set by how much benign traffic sits in the cells the
    # attack hides in. At 0.60 the bursty end already measures 0.41 dilution.
    # This needs ~4 GB free alongside the float32 shrink above; earlier runs
    # died here because several orphaned copies of this experiment were holding
    # memory at once, not because one copy is too large.
    # Even 0.60 understates a real workstation's traffic, so the dilution
    # reached here is a floor - degradation seen would be larger in practice.
    keep = 0.05 if args.quick else 0.60
    budget = 4_000 if args.quick else ATTACK_BUDGET
    print(f"\n[1/3] Loading corpus (benign_keep={keep}) ...")
    df = shrink(load_subsampled(Path(ds.path), keep))
    n_atk = int((df["Label"] != "BENIGN").sum())
    print(f"      {len(df):,} flows, {n_atk:,} attack "
          f"({100*n_atk/len(df):.1f}%)")

    # Capacity check, before anything is spent on training. Measured on this
    # corpus: 15 internal hosts carry benign traffic across >= 20 windows, and
    # the capture is 6,246 windows, so there are ~93,690 (host, window) cells.
    # Asking for 1 attack flow per cell with 428,196 attack flows is asking for
    # 4.6x the cells that exist - the sweep would floor out and report capacity
    # as though it were density.
    ts = df["Timestamp"]
    n_windows = int(np.floor((ts.max() - ts.min()).total_seconds() / WINDOW_S)) + 1
    ben = df.loc[df["Label"] == "BENIGN"]
    bw = np.floor((ben["Timestamp"] - ts.min()).dt.total_seconds() / WINDOW_S)
    pool = int((pd.DataFrame({"s": ben["Src IP"].to_numpy(), "w": bw.to_numpy()})
                .groupby("s")["w"].nunique() >= 20).sum())
    capacity = pool * n_windows
    print(f"      {pool} blend hosts x {n_windows:,} windows = "
          f"{capacity:,} cells of capacity")
    df = budget_attacks(df, budget, SEED)
    n_atk = int((df["Label"] != "BENIGN").sum())
    print(f"      {len(df):,} flows kept, {n_atk:,} attack "
          f"({100*n_atk/len(df):.1f}%) - constant across the sweep")
    if n_atk > capacity:
        sys.exit(f"budget {n_atk:,} exceeds cell capacity {capacity:,}; "
                 f"d=1 is unreachable and the sweep would measure capacity")

    rows = []
    print("\n[2/3] Density sweep ...")
    for d in DENSITIES:
        print(f"\n  --- {d:.0f} attack flows per cell "
              f"{'(bursty end)' if d == max(DENSITIES) else ''}"
              f"{'(one flow alone in its cell)' if d == 1.0 else ''}")
        rows.append(evaluate_density(df, d, args.quick))

    print("\n[3/3] Negative control: permuted labels at d=1 ...")
    perm = evaluate_density(df, 1.0, args.quick, permute=True)

    res = pd.DataFrame(rows)
    res.to_csv(RESULTS / "exp10_density_sweep.csv", index=False)

    lo = rows[-1]      # d = 1
    hi = rows[0]       # d = 64
    g_drop = hi["G_HW_ONLY_binary"] - lo["G_HW_ONLY_binary"]
    a_over_g = lo["A_FULL_binary"] - lo["G_HW_ONLY_binary"]
    tap_lo = lo["A_FULL_binary"] - lo["C_MATCHED_binary"]
    tap_hi = hi["A_FULL_binary"] - hi["C_MATCHED_binary"]
    perm_max = max(perm[f"{c}_binary"] for c in
                   ("A_FULL", "C_MATCHED", "E_SENSOR", "G_HW_ONLY"))

    starved = [r["density"] for r in rows if not r["density_achieved"]]
    verdicts = {
        "Z0": bool(not starved),
        "Z1": bool(hi["G_HW_ONLY_binary"] >= 0.85),
        "Z2": bool(g_drop >= 0.15),
        "Z3": bool(a_over_g > 0.10),
        "Z4": bool(tap_lo > tap_hi),
        "Z5": bool(perm_max < 0.55),
    }

    print("\n" + "=" * 78)
    print("SWEEP  (binary-F1)")
    print("=" * 78)
    print(f"  {'flows/cell':>10s} {'dilution':>9s} "
          f"{'A FULL':>8s} {'C MATCH':>8s} {'E SENSOR':>9s} {'G HW ONLY':>10s}")
    for r in rows:
        print(f"  {r['density']:>10.0f} {r['dilution']:>9.3f} "
              f"{r['A_FULL_binary']:>8.3f} {r['C_MATCHED_binary']:>8.3f} "
              f"{r['E_SENSOR_binary']:>9.3f} {r['G_HW_ONLY_binary']:>10.3f}")
    print(f"  {'permuted':>10s} {perm['dilution']:>9.3f} "
          f"{perm['A_FULL_binary']:>8.3f} {perm['C_MATCHED_binary']:>8.3f} "
          f"{perm['E_SENSOR_binary']:>9.3f} {perm['G_HW_ONLY_binary']:>10.3f}")

    print("\n" + "=" * 78)
    print("VERDICTS")
    print("=" * 78)
    lines = [
        ("Z0", "every requested density was physically reachable",
         "ok" if not starved else f"floored at {starved}"),
        ("Z1", "validity: G >= 0.85 binary-F1 at the bursty end",
         f"{hi['G_HW_ONLY_binary']:.3f}"),
        ("Z2", "G loses >= 0.15 binary-F1 from d=64 to d=1", f"{g_drop:+.3f}"),
        ("Z3", "at d=1, A beats G by > 0.10 binary-F1", f"{a_over_g:+.3f}"),
        ("Z4", "one-way tap costs more at d=1 than d=64",
         f"{tap_lo:+.3f} vs {tap_hi:+.3f}"),
        ("Z5", "permuted labels stay below 0.55", f"{perm_max:.3f}"),
    ]
    for key, text, got in lines:
        mark = "HOLDS " if verdicts[key] else "FAILS "
        print(f"  {key}  {mark} {text:<48s} {got}")

    if not verdicts["Z0"]:
        print("\n  Z0 failed. At least one density point ran out of (host, window)")
        print("  cells, so it measured capacity rather than density. Lower the")
        print("  attack budget or drop that point.")
    if not verdicts["Z1"]:
        print("\n  Z1 failed. The bursty end does not reproduce exp04's regime,")
        print("  so the sweep is measuring something other than density and the")
        print("  remaining verdicts should not be read as evidence.")

    payload = {
        "window_s": WINDOW_S,
        "quick_mode": args.quick,
        "densities": DENSITIES,
        "sweep": rows,
        "permuted_control": perm,
        "summary": {
            "g_drop_bursty_to_diffuse": g_drop,
            "a_minus_g_at_diffuse": a_over_g,
            "tap_cost_diffuse": tap_lo,
            "tap_cost_bursty": tap_hi,
            "permuted_max_binary": perm_max,
        },
        "verdicts": verdicts,
        "caveats": [
            "per-flow features are unmodified, so A and C are optimistic bounds",
            "smallest-first budgeting keeps rare classes whole and caps the large "
            "ones, so the class mix is far more uniform than the corpus's own; "
            "this protects macro-F1 from being one DoS class in a trench coat, "
            "but it is not the corpus's real balance",
            "realised density is a mean over campaigns of unequal size - a "
            "campaign smaller than the target can never reach it",
            "diffusion destroys exp04's campaign ordering; absolute values are "
            "not comparable to exp04, only across densities here",
            "a generated arrangement can refute a claim about density, not "
            "establish the crossover point in a real network",
        ],
    }
    (RESULTS / "exp10_verdicts.json").write_text(json.dumps(payload, indent=2,
                                                           default=float))
    print("\n  wrote results/exp10_density_sweep.csv and exp10_verdicts.json")
    print(f"  total runtime {time.time()-t_all:.0f}s")


if __name__ == "__main__":
    main()

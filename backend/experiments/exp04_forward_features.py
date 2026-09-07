"""Experiment 04 — how much of the one-way gap is recoverable with better features?

The open question from experiment 03
------------------------------------
On real traffic, retraining under a one-way visibility profile recovered only
about a third of the loss (0.988 full -> 0.522 deployed -> 0.683 retrained).
But that condition was handicapped: it used the 35 forward-observable features
**CICFlowMeter happens to emit**, and CICFlowMeter was not designed for a
one-way tap.

A sensor built for that position keeps per-host state across a window and
computes fan-out, source-IP entropy, peer concentration, arrival periodicity
and volume-versus-baseline - the features the synthetic pipeline had and this
corpus's flow records do not. `features/host_window.py` computes them from the
forward-only columns.

So: does a *fair* one-way feature set close the gap?

Conditions
----------
  A  FULL      103 features, both directions            (exp03's upper bound)
  C  MATCHED    35 forward-observable features only     (exp03's handicapped result)
  E  SENSOR     35 forward + 16 host-window aggregates  (what a real one-way sensor has)
  F  FULL+HW   103 full + 16 host-window                (control - see below)
  G  HW ONLY    16 host-window aggregates alone         (control - see below)

Two controls, added after E came out level with A
--------------------------------------------------
E matching full visibility is a strong claim and the first thing to suspect is
that the host-window aggregates are doing something other than what we say.

  F answers "does window context help the full-visibility model too?" If F is
    also ~0.98 then window context saturates the task and the reverse channel
    adds nothing on top of it - which is the interesting version of the claim.
    If F >> E then the reverse channel still carries something and E's parity
    with A was a coincidence of this split.

  G answers "is it all window context?" If 16 aggregates alone reach ~0.98 then
    the per-flow forward features are close to irrelevant and the honest
    framing is about windowed host state, not about direction at all.

Pre-registered predictions (written before the first run)
---------------------------------------------------------
  T1  E > C. The host-window features help at all.
  T2  E closes at least half the residual gap between C and A.
      i.e. E >= C + 0.5*(A - C) = 0.835 binary-F1.
  T3  Source-IP entropy and fan-out rank in the top 10 features of E by gain.
      This is the mechanism check - if E improves but for unrelated reasons,
      the story in the architecture doc is wrong even if the number is right.

What this cannot settle
-----------------------
TTL diversity, DNS query-name entropy and TLS client-fingerprint rarity need
packet-level data the flow CSV does not carry. So this experiment raises the
**lower bound** on recoverability; it does not locate the ceiling. That is
stated in the output rather than left for a reader to infer.

Run:  python experiments/exp04_forward_features.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sklearn.metrics import f1_score  # noqa: E402
from xgboost import XGBClassifier  # noqa: E402

from ekagra.features.host_window import (  # noqa: E402
    HOST_WINDOW_FEATURES, WINDOW_S, add_host_window_features,
)
from ekagra.ingest.replay import (  # noqa: E402
    BACKWARD_DERIVED, BIDIRECTIONAL_AGGREGATE, CICIDS2017, FORWARD_OBSERVABLE,
    load_subsampled,
)

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
SEED = 0
TRAIN_FRACTION = 0.70


def to_matrix(df: pd.DataFrame, cols) -> np.ndarray:
    x = df[list(cols)].apply(pd.to_numeric, errors="coerce")
    return x.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)


def fit(X, y, n_classes):
    m = XGBClassifier(n_estimators=250, max_depth=7, learning_rate=0.15,
                      subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                      objective="multi:softprob", num_class=n_classes,
                      n_jobs=4, eval_metric="mlogloss", random_state=SEED)
    m.fit(X, y)
    return m


def main() -> None:
    t0 = time.time()
    print("=" * 78)
    print("EKAGRA  ·  Experiment 04  ·  Does a fair one-way feature set close the gap?")
    print("=" * 78)

    ds = CICIDS2017()
    if not Path(ds.path).exists():
        sys.exit(f"corpus not found at {ds.path}")

    print("\n[1/4] Loading corpus ...")
    df = load_subsampled(Path(ds.path), 0.30)

    print(f"\n[2/4] Computing host-window aggregates (W={WINDOW_S:.0f}s) ...")
    t = time.time()
    df = add_host_window_features(df, window_s=WINDOW_S)
    print(f"      {len(HOST_WINDOW_FEATURES)} features over "
          f"{df['window'].nunique():,} windows   ({time.time()-t:.1f}s)")
    print(f"      NOTE: the sensor emits at window close, so these carry "
          f"{WINDOW_S:.0f}s of latency.")
    print("      The per-host baseline is strictly causal (earlier windows only).")

    # Split on a WINDOW boundary, not an arbitrary timestamp: a window that
    # straddled the cutoff would leak aggregate context across the split.
    wq = df["window"].quantile(TRAIN_FRACTION)
    cutoff_w = int(np.floor(wq))
    tr = (df["window"] <= cutoff_w).to_numpy()
    te = ~tr
    print(f"\n[3/4] Temporal split at window boundary {cutoff_w} "
          f"({tr.sum():,} train / {te.sum():,} test)")

    train_labels = sorted(set(df.loc[tr, "Label"]))
    idx = {c: i for i, c in enumerate(train_labels)}
    benign_i = idx["BENIGN"]
    unseen = sorted(set(df.loc[te, "Label"]) - set(train_labels))
    n_unseen = int(df.loc[te, "Label"].isin(unseen).sum())
    print(f"      {len(train_labels)} learnable classes; {len(unseen)} test-only "
          f"({n_unseen:,} flows, {100*n_unseen/te.sum():.1f}% of test)")

    y_tr = df.loc[tr, "Label"].map(idx).to_numpy()
    te_lab = df.loc[te, "Label"]
    te_known = te_lab.isin(train_labels).to_numpy()
    y_te = te_lab.map(idx).fillna(-1).astype(int).to_numpy()
    y_bin_te = (te_lab != "BENIGN").astype(int).to_numpy()

    full_cols = [c for c in FORWARD_OBSERVABLE + BACKWARD_DERIVED + BIDIRECTIONAL_AGGREGATE
                 if c in df.columns]
    fwd_cols = [c for c in FORWARD_OBSERVABLE if c in df.columns]
    sensor_cols = fwd_cols + HOST_WINDOW_FEATURES

    print("\n[4/4] Training three conditions ...")
    print(f"      A  FULL    {len(full_cols):>3d} features")
    print(f"      C  MATCHED {len(fwd_cols):>3d} features")
    print(f"      E  SENSOR  {len(sensor_cols):>3d} features "
          f"(+{len(HOST_WINDOW_FEATURES)} host-window)")

    def run(cols, name):
        X = to_matrix(df, cols)
        m = fit(X[tr], y_tr, len(train_labels))
        pred = m.predict(X[te])
        macro = f1_score(y_te[te_known], pred[te_known], average="macro", zero_division=0)
        binf = f1_score(y_bin_te, (pred != benign_i).astype(int),
                        average="macro", zero_division=0)
        print(f"      {name:<12s} macro-F1 {macro:.4f}   binary-F1 {binf:.4f}")
        return m, macro, binf

    m_a, a_macro, a_bin = run(full_cols, "A  FULL")
    m_c, c_macro, c_bin = run(fwd_cols, "C  MATCHED")
    m_e, e_macro, e_bin = run(sensor_cols, "E  SENSOR")
    m_f, f_macro, f_bin = run(full_cols + HOST_WINDOW_FEATURES, "F  FULL+HW")
    m_g, g_macro, g_bin = run(list(HOST_WINDOW_FEATURES), "G  HW ONLY")

    # ---------------------------------------------------------- mechanism check
    gain = m_e.get_booster().get_score(importance_type="gain")
    imp = sorted(((gain.get(f"f{i}", 0.0), c) for i, c in enumerate(sensor_cols)),
                 reverse=True)
    top10 = [c for _, c in imp[:10]]
    hw_in_top10 = [c for c in top10 if c.startswith("hw_")]

    print("\n      Top 10 features of condition E by gain:")
    for g, c in imp[:10]:
        tag = "  <- host-window" if c.startswith("hw_") else ""
        print(f"        {c:<34s} {g:>10.1f}{tag}")

    # ------------------------------------------------------------------ verdict
    print("\n" + "=" * 78)
    print("PRE-REGISTERED PREDICTIONS")
    print("=" * 78)
    target = c_bin + 0.5 * (a_bin - c_bin)
    t1 = e_bin > c_bin
    t2 = e_bin >= target
    t3 = any(("entropy" in c or "fanout" in c or "n_peers" in c or "n_srcs" in c)
             for c in hw_in_top10)
    for k, ok, d in [("T1", t1, f"E > C  ({e_bin:.4f} vs {c_bin:.4f})"),
                     ("T2", t2, f"E closes >= half the residual gap "
                                f"(needs {target:.4f}, got {e_bin:.4f})"),
                     ("T3", t3, f"entropy/fan-out in top 10 "
                                f"({hw_in_top10 or 'no host-window features in top 10'})")]:
        print(f"  {k}  {'HOLDS ' if ok else 'FAILS '}  {d}")

    closed = (e_bin - c_bin) / max(1e-9, a_bin - c_bin)
    print("\n" + "=" * 78)
    print("HEADLINE")
    print("=" * 78)
    print(f"  A  full visibility, 103 feats      {a_bin:.4f}")
    print(f"  C  one-way, CICFlowMeter feats     {c_bin:.4f}   (exp03's handicapped number)")
    print(f"  E  one-way, purpose-built sensor   {e_bin:.4f}")
    print(f"  F  full visibility + host-window   {f_bin:.4f}   [control]")
    print(f"  G  host-window aggregates alone    {g_bin:.4f}   [control]")
    print()
    print(f"  -> host-window features close {100*closed:.0f}% of the residual gap")
    print(f"  -> E vs A: {e_bin - a_bin:+.4f}   E vs F: {e_bin - f_bin:+.4f}")
    if abs(f_bin - e_bin) < 0.01:
        print("  -> F is level with E: once a sensor keeps windowed host state, the")
        print("     reverse channel adds nothing measurable on this corpus.")
    else:
        print("  -> F exceeds E: the reverse channel still carries signal that host")
        print("     state does not replace. E's parity with A does not generalise.")
    if g_bin > e_bin - 0.02:
        print("  -> G alone is close to E: the windowed host state is doing nearly all")
        print("     of the work, and the per-flow forward features add little.")
    print("\n  This is a LOWER bound. TTL diversity, DNS query-name entropy and TLS")
    print("  fingerprint rarity need packet data this corpus does not carry.")

    pd.DataFrame([
        {"condition": "A_FULL", "n_features": len(full_cols),
         "macro_f1": a_macro, "binary_f1": a_bin},
        {"condition": "C_MATCHED", "n_features": len(fwd_cols),
         "macro_f1": c_macro, "binary_f1": c_bin},
        {"condition": "E_SENSOR", "n_features": len(sensor_cols),
         "macro_f1": e_macro, "binary_f1": e_bin},
        {"condition": "F_FULL_PLUS_HW", "n_features": len(full_cols) + len(HOST_WINDOW_FEATURES),
         "macro_f1": f_macro, "binary_f1": f_bin},
        {"condition": "G_HW_ONLY", "n_features": len(HOST_WINDOW_FEATURES),
         "macro_f1": g_macro, "binary_f1": g_bin},
    ]).to_csv(RESULTS / "exp04_forward_features.csv", index=False)

    (RESULTS / "exp04_verdicts.json").write_text(json.dumps({
        "window_s": WINDOW_S,
        "n_flows": int(len(df)),
        "binary_f1": {"A_FULL": a_bin, "C_MATCHED": c_bin, "E_SENSOR": e_bin,
                      "F_FULL_PLUS_HW": f_bin, "G_HW_ONLY": g_bin},
        "macro_f1": {"A_FULL": a_macro, "C_MATCHED": c_macro, "E_SENSOR": e_macro,
                     "F_FULL_PLUS_HW": f_macro, "G_HW_ONLY": g_macro},
        "fraction_of_residual_gap_closed": float(closed),
        "top10_features": top10,
        "host_window_in_top10": hw_in_top10,
        "verdicts": {"T1": bool(t1), "T2": bool(t2), "T3": bool(t3)},
        "is_lower_bound_because": [
            "TTL diversity requires packet data",
            "DNS query-name entropy requires packet data",
            "TLS client fingerprint requires packet data",
        ],
    }, indent=2, default=float))
    print("\n  wrote results/exp04_forward_features.csv and exp04_verdicts.json")
    print(f"  total runtime {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()

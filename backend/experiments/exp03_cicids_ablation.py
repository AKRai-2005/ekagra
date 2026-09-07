"""Experiment 03 — the visibility ablation on real traffic (CIC-IDS2017).

Purpose
-------
`exp01_ablation.py` found that a detector trained under full bidirectional
visibility loses ~0.22 macro-F1 when deployed on a one-way tap, and that
visibility-matched retraining recovers it. Every number there is on generated
traffic. This experiment asks whether the same thing happens on **real captured
traffic with real labels**.

Corpus
------
Corrected CICFlowMeter re-extraction of CIC-IDS2017 (Huang, Bois & Marchioro,
Zenodo 22016274, CC-BY-4.0) - not the original CSVs, which have documented
label and extractor defects.

Conditions
----------
  A  FULL       every feature, trained and tested with both directions
  B  DEPLOYED   every feature, trained on full, tested with the unobservable
                features zeroed  (what happens if you deploy the paper's model)
  C  MATCHED    forward-observable features only, trained and tested that way
  D  SAMPLED    same as C, with 1:16 flow sampling

The enrichment rung from exp01 is not testable here - the corpus carries no
threat-intel features. That is fine: exp01 found enrichment cost ~0 and
*direction* was the expensive rung, so this corpus tests the rung that mattered.

Pre-registered predictions (written before the first run)
---------------------------------------------------------
  S1  B collapses relative to A on real data too.
  S2  C recovers most of the gap (within 0.10 macro-F1 of A).
  S3  The drop is at least half the synthetic study's 0.22 macro-F1.
  S4  Classes whose discriminative signal is backward-derived - anything where
      the victim's *response* carries the information - collapse hardest.

Run:  python experiments/exp03_cicids_ablation.py
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

from sklearn.metrics import classification_report, f1_score  # noqa: E402
from xgboost import XGBClassifier  # noqa: E402

from ekagra.ingest.replay import (  # noqa: E402
    BACKWARD_DERIVED, BIDIRECTIONAL_AGGREGATE, CICIDS2017, FORWARD_OBSERVABLE,
    column_audit, load_subsampled,
)

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

BENIGN_KEEP = 0.30   # subsample benign flows; all attack flows are kept
TRAIN_FRACTION = 0.70
SEED = 0


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


def main(argv=None) -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--path", default=None, help="override corpus path")
    ap.add_argument("--benign-keep", type=float, default=BENIGN_KEEP)
    args = ap.parse_args(argv)

    t0 = time.time()
    print("=" * 78)
    print("EKAGRA  ·  Experiment 03  ·  Visibility ablation on CIC-IDS2017 (real traffic)")
    print("=" * 78)

    ds = CICIDS2017(path=Path(args.path) if args.path else CICIDS2017.path)
    if not Path(ds.path).exists():
        sys.exit(f"\nDataset not found at {ds.path}\n"
                 f"  curl -L -o {ds.path} {ds.ZENODO_URL if hasattr(ds,'ZENODO_URL') else ''}\n")

    print("\n[1/5] Loading corpus ...")
    df = load_subsampled(Path(ds.path), args.benign_keep)
    ds._df = df

    print("\n[2/5] Column audit ...")
    audit = column_audit(df)
    counts = audit["class"].value_counts()
    for k, v in counts.items():
        print(f"      {k:<26s} {v:>3d}")
    unclassified = audit[audit["class"] == "UNCLASSIFIED"]["column"].tolist()
    if unclassified:
        print(f"      !! UNCLASSIFIED (excluded from all conditions): {unclassified}")
    audit.to_csv(RESULTS / "exp03_column_audit.csv", index=False)

    full_cols = [c for c in FORWARD_OBSERVABLE + BACKWARD_DERIVED + BIDIRECTIONAL_AGGREGATE
                 if c in df.columns]
    fwd_cols = [c for c in FORWARD_OBSERVABLE if c in df.columns]
    print(f"      full-visibility features : {len(full_cols)}")
    print(f"      forward-observable       : {len(fwd_cols)}")

    labels = sorted(df["Label"].unique())
    print(f"\n      {len(labels)} classes:")
    vc = df["Label"].value_counts()
    for lab in labels:
        note = ""
        if lab.endswith("- Attempted"):
            note = "  (attack that did not succeed)"
        if vc[lab] < 100:
            note += "  [very low support]"
        print(f"        {lab:<34s} {vc[lab]:>9,}{note}")

    # The corrected corpus separates "X - Attempted" from "X" - unsuccessful
    # attempts that the original CIC-IDS2017 labelled as full attacks. We keep
    # the distinction rather than merging it back, because merging would undo
    # part of the correction we chose this corpus for. The cost is several
    # very small classes that drag multi-class macro-F1 down; that is why
    # **binary F1 is the headline metric** and macro-F1 is reported alongside.
    n_attempted = sum(vc[l] for l in labels if l.endswith("- Attempted"))
    if n_attempted:
        print(f"      {n_attempted:,} flows are 'Attempted' variants "
              f"(kept separate, see comment in source)")

    print("\n[3/5] Temporal split ...")
    cutoff = df["Timestamp"].quantile(TRAIN_FRACTION)
    tr = (df["Timestamp"] <= cutoff).to_numpy()
    te = ~tr
    print(f"      cutoff {cutoff}   {tr.sum():,} train / {te.sum():,} test")

    # The label space is defined by the TRAINING set only. A temporal split on
    # this corpus genuinely leaves whole attack families in the test period -
    # Botnet, DDoS and Portscan all run on the Friday - and a model cannot be
    # asked to name a class it has never seen. Encoding them anyway also breaks
    # XGBoost, which requires contiguous class indices.
    #
    # Multi-class F1 is therefore computed over the classes the model could
    # have learned. Those test flows are NOT dropped from the binary metric:
    # an unseen botnet flow predicted as "DoS Hulk" is still correctly flagged
    # as an attack, which is what a deployed sensor is judged on. That is the
    # second reason binary F1 is the headline number here.
    train_labels = sorted(set(df.loc[tr, "Label"]))
    idx = {c: i for i, c in enumerate(train_labels)}
    benign_i = idx["BENIGN"]

    unseen = sorted(set(df.loc[te, "Label"]) - set(train_labels))
    n_unseen = int(df.loc[te, "Label"].isin(unseen).sum())
    if unseen:
        print(f"      {len(train_labels)} classes learnable; {len(unseen)} appear "
              f"only in test (temporal split, expected):")
        print(f"        {unseen}")
        print(f"        {n_unseen:,} test flows "
              f"({100*n_unseen/te.sum():.1f}%) belong to them - excluded from "
              f"multi-class F1, retained in binary F1.")

    y_tr = df.loc[tr, "Label"].map(idx).to_numpy()
    te_lab = df.loc[te, "Label"]
    te_known = te_lab.isin(train_labels).to_numpy()
    y_te = te_lab.map(idx).fillna(-1).astype(int).to_numpy()
    y_bin_te = (te_lab != "BENIGN").astype(int).to_numpy()

    print("\n[4/5] Training and evaluating ...")
    Xfull = to_matrix(df, full_cols)
    Xfwd = to_matrix(df, fwd_cols)

    # Deployment ablation: zero what a one-way sensor could not compute.
    keep = set(FORWARD_OBSERVABLE)
    mask = np.array([c in keep for c in full_cols])
    Xabl = Xfull.copy()
    Xabl[:, ~mask] = 0.0
    print(f"      zeroed {int((~mask).sum())} of {len(full_cols)} features for the "
          f"deployment condition")

    def evaluate(model, X_test, y_true_multi, y_true_bin, known_mask):
        pred = model.predict(X_test)
        # Multi-class: only over rows whose class was learnable.
        macro = f1_score(y_true_multi[known_mask], pred[known_mask],
                         average="macro", zero_division=0)
        per = f1_score(y_true_multi[known_mask], pred[known_mask], average=None,
                       labels=list(range(len(train_labels))), zero_division=0)
        # Binary: every test row, including the unseen attack families.
        pb = (pred != benign_i).astype(int)
        binf = f1_score(y_true_bin, pb, average="macro", zero_division=0)
        return macro, binf, dict(zip(train_labels, (float(v) for v in per))), pred

    rows = []

    m_full = fit(Xfull[tr], y_tr, len(train_labels))
    a_macro, a_bin, a_per, _ = evaluate(m_full, Xfull[te], y_te, y_bin_te, te_known)
    print(f"\n      A  FULL      macro-F1 {a_macro:.4f}   binary-F1 {a_bin:.4f}")
    rows.append({"condition": "A_FULL", "macro_f1": a_macro, "binary_f1": a_bin, **a_per})

    b_macro, b_bin, b_per, _ = evaluate(m_full, Xabl[te], y_te, y_bin_te, te_known)
    print(f"      B  DEPLOYED  macro-F1 {b_macro:.4f}   binary-F1 {b_bin:.4f}   "
          f"({b_bin - a_bin:+.4f} binary vs A)")
    rows.append({"condition": "B_DEPLOYED", "macro_f1": b_macro, "binary_f1": b_bin, **b_per})

    m_fwd = fit(Xfwd[tr], y_tr, len(train_labels))
    c_macro, c_bin, c_per, c_pred = evaluate(m_fwd, Xfwd[te], y_te, y_bin_te, te_known)
    print(f"      C  MATCHED   macro-F1 {c_macro:.4f}   binary-F1 {c_bin:.4f}   "
          f"({c_bin - a_bin:+.4f} binary vs A)")
    rows.append({"condition": "C_MATCHED", "macro_f1": c_macro, "binary_f1": c_bin, **c_per})

    rng = np.random.default_rng(7)
    samp = rng.integers(0, 16, size=len(df)) == 0
    tr_s, te_s = tr & samp, te & samp
    if tr_s.sum() > 1000 and te_s.sum() > 200:
        # The 1:16 sample does not necessarily contain every training class,
        # so this condition needs its own contiguous label space rather than
        # reusing the full one.
        s_labels = sorted(set(df.loc[tr_s, "Label"]))
        sidx = {c: i for i, c in enumerate(s_labels)}
        y_tr_s = df.loc[tr_s, "Label"].map(sidx).to_numpy()
        te_s_lab = df.loc[te_s, "Label"]
        m_s = fit(Xfwd[tr_s], y_tr_s, len(s_labels))
        pred_s = m_s.predict(Xfwd[te_s])
        known_s = te_s_lab.isin(s_labels).to_numpy()
        y_te_s = te_s_lab.map(sidx).fillna(-1).astype(int).to_numpy()
        d_macro = f1_score(y_te_s[known_s], pred_s[known_s], average="macro",
                           zero_division=0)
        d_bin = f1_score((te_s_lab != "BENIGN").astype(int).to_numpy(),
                         (pred_s != sidx["BENIGN"]).astype(int),
                         average="macro", zero_division=0)
        d_per = {}
        print(f"      D  SAMPLED   macro-F1 {d_macro:.4f}   binary-F1 {d_bin:.4f}   "
              f"(1:16 flow sampling, {tr_s.sum():,} train)")
        rows.append({"condition": "D_SAMPLED_1in16", "macro_f1": d_macro,
                     "binary_f1": d_bin, **d_per})

    print("\n      Per-class F1, condition C (visibility-matched):")
    print(classification_report(y_te[te_known], c_pred[te_known],
                                labels=list(range(len(train_labels))),
                                target_names=train_labels, zero_division=0, digits=3))

    res = pd.DataFrame(rows)
    res.to_csv(RESULTS / "exp03_cicids_ablation.csv", index=False)

    print("\n[5/5] Pre-registered predictions ...")
    s1 = b_bin < a_bin
    s2 = (a_bin - c_bin) < 0.10
    s3 = (a_bin - b_bin) >= 0.11
    collapse = sorted(((a_per[l] - b_per[l], l) for l in train_labels), reverse=True)[:5]
    s4_note = ", ".join(f"{l} ({d:+.3f})" for d, l in collapse if d > 0.05)

    for k, ok, d in [("S1", s1, "B collapses relative to A"),
                     ("S2", s2, f"C recovers to within 0.10 of A "
                                f"({a_bin - c_bin:+.4f})"),
                     ("S3", s3, f"drop >= half the synthetic 0.22 "
                                f"({a_bin - b_bin:.4f})")]:
        print(f"      {k}  {'HOLDS ' if ok else 'FAILS '}  {d}")
    print(f"      S4  classes collapsing hardest: {s4_note or 'none above 0.05'}")

    print("\n" + "=" * 78)
    print("HEADLINE  (real traffic)")
    print("=" * 78)
    print(f"  Naive deployment cost       : {b_bin - a_bin:+.4f} binary-F1  "
          f"({a_bin:.3f} -> {b_bin:.3f})")
    print(f"  Recovered by matched retrain : {c_bin - b_bin:+.4f} binary-F1  "
          f"({b_bin:.3f} -> {c_bin:.3f})")
    print(f"  Residual vs full visibility  : {c_bin - a_bin:+.4f} binary-F1")

    (RESULTS / "exp03_verdicts.json").write_text(json.dumps({
        "corpus": "CIC-IDS2017 corrected CICFlowMeter (Zenodo 22016274)",
        "n_flows_used": int(len(df)), "benign_keep_rate": args.benign_keep,
        "n_full_features": len(full_cols), "n_forward_features": len(fwd_cols),
        "classes_absent_from_training": unseen,
        "n_test_flows_in_unseen_classes": n_unseen,
        "n_learnable_classes": len(train_labels),
        "binary_f1": {"A_FULL": a_bin, "B_DEPLOYED": b_bin, "C_MATCHED": c_bin},
        "macro_f1": {"A_FULL": a_macro, "B_DEPLOYED": b_macro, "C_MATCHED": c_macro},
        "verdicts": {"S1": bool(s1), "S2": bool(s2), "S3": bool(s3)},
        "hardest_collapse": [{"label": l, "drop": d} for d, l in collapse],
    }, indent=2, default=float))
    print("\n  wrote results/exp03_cicids_ablation.csv and exp03_verdicts.json")
    print(f"  total runtime {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()

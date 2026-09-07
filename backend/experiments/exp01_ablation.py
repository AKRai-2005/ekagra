"""Experiment 01 — the visibility ablation study.

Question
--------
Published flow-based NIDS results assume a monitoring position with full
bidirectional visibility and the ability to enrich observations by calling
external services. A data-diode enclave has neither. **How much does that cost,
and can feature design recover it?**

Four conditions, evaluated at each rung of the visibility ladder:

  A  FULL          bi-directional features, full visibility          (the published number)
  B  DEPLOYED      bi-directional features, trained on full,
                   evaluated under the degraded profile              (naive deployment)
  C  RETRAINED     bi-directional features, trained *and* evaluated
                   under the degraded profile                        (the honest control)
  D  NATIVE        unidirectional-native features, trained and
                   evaluated under the degraded profile              (ours)

C is the condition that makes this credible. Without it a reviewer says "you
crippled the baseline." With it, the claim narrows to something defensible:
retraining recovers some of the loss, and the remainder must be recovered by
*feature design* rather than by model capacity.

Pre-registered predictions (written before the first run)
---------------------------------------------------------
  P1  B collapses relative to A at every rung below FULL_ENRICHED.
  P2  C recovers materially but does not reach A.
  P3  D >= C at every degraded rung. If D does not beat C, the contribution
      is not real and we say so.
  P4  The single largest drop is at the enrichment rung (FULL -> DIODE_FULL),
      not at the direction rung. This is the prediction we are least sure of.

Anything that comes out otherwise gets reported as it is. The value of this
experiment is that it could embarrass us.

WHAT ACTUALLY HAPPENED  (recorded 30 Aug 2026, after the fair-baseline fix)
---------------------------------------------------------------------------
Three of the four predictions were **refuted**. The predictions above are left
exactly as written; they are the record, not a summary of the outcome.

  P1  PARTLY   B collapses catastrophically at the one-way rungs
               (-0.40 macro-F1), but *not* at DIODE_FULL, where dropping
               enrichment slightly improved things.
  P2  REFUTED  C does not stay below A. Visibility-matched retraining
               recovers essentially all of the loss (0.9291 vs 0.9323).
  P3  REFUTED  **The unidirectional-native feature set does not beat a
               retrained bidirectional-feature baseline.** Once the baseline
               is given every direction-agnostic behavioural feature, the two
               are statistically indistinguishable at the one-way rung, and
               the native set is slightly worse where both directions exist.
  P4  REFUTED  Losing enrichment cost nothing. At 55% feed recall and 3% FPR
               it was net *negative*: the model does better without it.

An earlier run appeared to confirm P3 with a +0.05 margin. That result was an
artefact: the bidirectional feature set had been built without name-entropy and
regularity statistics, so the "native" set was winning on features that were
being withheld from the baseline rather than on anything to do with visibility.
Adding them to the baseline (see `extractors.py`) removed the effect entirely.
This is documented because the mistake is instructive and because the corrected
result is the one that is true.

THE FINDING THAT SURVIVED, AND IT IS THE BETTER ONE
----------------------------------------------------
The contribution is not a feature set. It is a **failure mode and its fix**:

    A detector trained under full bidirectional visibility loses 0.40 macro-F1
    when deployed on a one-way tap. Two of six threat classes go to essentially
    zero (exfiltration 0.93 -> 0.00, encrypted-C2 0.98 -> 0.09). The cause is a
    train/deploy visibility mismatch, not a limit on what forward-side traffic
    can express - because retraining under the deployment's own visibility
    profile recovers almost all of it.

That is more useful than the original claim. It says the published numbers are
not wrong, they are *unearned in this deployment*, and the remedy is cheap and
specific: characterise your sensor's visibility, then train under it. Nobody
does this, because nobody writes the visibility profile down.

Run:  python experiments/exp01_ablation.py
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

from ekagra.features.extractors import (  # noqa: E402
    EnrichmentOracle, FeatureBuilder, feature_columns,
)
from ekagra.ingest.records import THREAT_CLASSES  # noqa: E402
from ekagra.ingest.synthetic import GeneratorConfig, SyntheticSource  # noqa: E402
from ekagra.ingest.visibility import (  # noqa: E402
    DIODE_FULL, DIODE_ONEWAY, DIODE_ONEWAY_SAMPLED, LADDER,
    VisibilityFilter,
)

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

TRAIN_FRACTION = 0.70  # temporal split: earliest 70% of windows train


def build_frame(packets, profile, oracle):
    """Apply a visibility profile and extract features."""
    vf = VisibilityFilter(profile)
    return FeatureBuilder(profile, oracle=oracle).consume(vf.apply(packets)).to_frame()


def temporal_split(df: pd.DataFrame):
    """Split by window index, never randomly.

    Random splitting of a time series leaks: adjacent windows of the same
    attack episode end up on both sides and the score is meaningless. This is
    the single most common flaw in student NIDS work and the first thing an
    NTRO evaluator will probe.
    """
    cutoff = df["window"].quantile(TRAIN_FRACTION)
    return df[df["window"] <= cutoff], df[df["window"] > cutoff]


def fit(df_train: pd.DataFrame, cols, classes):
    idx = {c: i for i, c in enumerate(classes)}
    y = df_train["label"].map(idx).to_numpy()
    model = XGBClassifier(
        n_estimators=260, max_depth=6, learning_rate=0.12,
        subsample=0.9, colsample_bytree=0.9,
        objective="multi:softprob", num_class=len(classes),
        tree_method="hist", n_jobs=4, eval_metric="mlogloss",
        random_state=0,
    )
    model.fit(df_train[cols].to_numpy(dtype=np.float32), y)
    return model, idx


def evaluate(model, idx, df_test, cols, classes):
    y_true = df_test["label"].map(idx).to_numpy()
    y_pred = model.predict(df_test[cols].to_numpy(dtype=np.float32))
    macro = f1_score(y_true, y_pred, average="macro", zero_division=0)
    per_class = f1_score(y_true, y_pred, average=None,
                         labels=list(range(len(classes))), zero_division=0)
    return macro, dict(zip(classes, (float(x) for x in per_class))), y_true, y_pred


def main() -> None:
    t0 = time.time()
    print("=" * 74)
    print("EKAGRA  ·  Experiment 01  ·  Visibility Ablation Study")
    print("=" * 74)

    cfg = GeneratorConfig(seed=1337, duration_s=3600.0)
    print(f"\n[1/4] Generating labelled traffic (seed={cfg.seed}, {cfg.duration_s:.0f}s) ...")
    packets = SyntheticSource(cfg).generate()
    print(f"      {len(packets):,} packets")
    dist = pd.Series([p.label for p in packets]).value_counts()
    print("      packet label distribution:")
    for k, v in dist.items():
        print(f"        {k:<10s} {v:>9,}  ({100*v/len(packets):5.2f}%)")

    # The reputation feed knows about hosts that actually carried attack
    # traffic - with imperfect coverage. Built once, shared across profiles.
    malicious_ips = {p.src_ip for p in packets if p.label != "benign"} | \
                    {p.dst_ip for p in packets if p.label != "benign"}
    oracle = EnrichmentOracle(malicious_ips, seed=99, recall=0.55, fpr=0.03)
    print(f"      enrichment feed: {len(malicious_ips):,} known-bad IPs, recall=0.55, fpr=0.03")

    print("\n[2/4] Extracting features under each visibility profile ...")
    frames = {}
    for prof in LADDER:
        t = time.time()
        frames[prof.name] = build_frame(packets, prof, oracle)
        df = frames[prof.name]
        print(f"      {prof.name:<22s} {len(df):>7,} rows   ({time.time()-t:5.1f}s)")

    classes = [c for c in THREAT_CLASSES
               if c in set(frames["FULL_ENRICHED"]["label"].unique())]
    print(f"      classes present: {classes}")

    print("\n[3/4] Training and evaluating four conditions per rung ...")
    full_train, full_test = temporal_split(frames["FULL_ENRICHED"])
    bi_cols = feature_columns(frames["FULL_ENRICHED"], "bi")
    uni_cols = feature_columns(frames["FULL_ENRICHED"], "uni")
    print(f"      bi-directional features: {len(bi_cols)}   unidirectional-native: {len(uni_cols)}")
    print(f"      temporal split at window {full_train['window'].max()} "
          f"({len(full_train):,} train / {len(full_test):,} test)")

    model_full, idx = fit(full_train, bi_cols, classes)
    f1_A, per_A, _, _ = evaluate(model_full, idx, full_test, bi_cols, classes)
    print(f"\n      A  FULL       macro-F1 = {f1_A:.4f}")

    rows = [{"rung": "FULL_ENRICHED", "condition": "A_FULL", "macro_f1": f1_A, **per_A}]

    for prof in (DIODE_FULL, DIODE_ONEWAY, DIODE_ONEWAY_SAMPLED):
        df = frames[prof.name]
        tr, te = temporal_split(df)

        f1_B, per_B, _, _ = evaluate(model_full, idx, te, bi_cols, classes)

        m_C, idx_C = fit(tr, bi_cols, classes)
        f1_C, per_C, _, _ = evaluate(m_C, idx_C, te, bi_cols, classes)

        m_D, idx_D = fit(tr, uni_cols, classes)
        f1_D, per_D, yt, yp = evaluate(m_D, idx_D, te, uni_cols, classes)

        print(f"\n      {prof.name}")
        print(f"        B  DEPLOYED   macro-F1 = {f1_B:.4f}   ({f1_B - f1_A:+.4f} vs A)")
        print(f"        C  RETRAINED  macro-F1 = {f1_C:.4f}   ({f1_C - f1_A:+.4f} vs A)")
        print(f"        D  NATIVE     macro-F1 = {f1_D:.4f}   ({f1_D - f1_C:+.4f} vs C)")

        rows += [
            {"rung": prof.name, "condition": "B_DEPLOYED", "macro_f1": f1_B, **per_B},
            {"rung": prof.name, "condition": "C_RETRAINED", "macro_f1": f1_C, **per_C},
            {"rung": prof.name, "condition": "D_NATIVE", "macro_f1": f1_D, **per_D},
        ]

        if prof is DIODE_ONEWAY:
            print("\n      Per-class report, D (NATIVE) at DIODE_ONEWAY:")
            print(classification_report(yt, yp, labels=list(range(len(classes))),
                                        target_names=classes, zero_division=0, digits=3))

    res = pd.DataFrame(rows)
    res.to_csv(RESULTS / "exp01_ablation.csv", index=False)

    print("\n[4/4] Checking pre-registered predictions ...")
    verdicts = {}
    degraded = res[res.rung != "FULL_ENRICHED"]
    p1 = bool((degraded[degraded.condition == "B_DEPLOYED"].macro_f1 < f1_A).all())
    p2 = bool((degraded[degraded.condition == "C_RETRAINED"].macro_f1 >
               degraded[degraded.condition == "B_DEPLOYED"].macro_f1.values).all()
              and (degraded[degraded.condition == "C_RETRAINED"].macro_f1 < f1_A).all())
    d_vals = degraded[degraded.condition == "D_NATIVE"].macro_f1.values
    c_vals = degraded[degraded.condition == "C_RETRAINED"].macro_f1.values
    p3 = bool((d_vals >= c_vals - 1e-9).all())
    enrich_drop = f1_A - float(res[(res.rung == "DIODE_FULL") &
                                   (res.condition == "C_RETRAINED")].macro_f1.iloc[0])
    direction_drop = float(res[(res.rung == "DIODE_FULL") &
                               (res.condition == "C_RETRAINED")].macro_f1.iloc[0]) - \
                     float(res[(res.rung == "DIODE_ONEWAY") &
                               (res.condition == "C_RETRAINED")].macro_f1.iloc[0])
    p4 = bool(enrich_drop > direction_drop)

    for name, ok, desc in [
        ("P1", p1, "B collapses below A at every degraded rung"),
        ("P2", p2, "C recovers above B but stays below A"),
        ("P3", p3, "D >= C at every degraded rung  [THE CONTRIBUTION]"),
        ("P4", p4, "enrichment loss costs more than direction loss"),
    ]:
        verdicts[name] = ok
        print(f"      {name}  {'HOLDS ' if ok else 'FAILS '}  {desc}")

    print(f"\n      enrichment rung cost: {enrich_drop:+.4f} macro-F1")
    print(f"      direction  rung cost: {direction_drop:+.4f} macro-F1")

    if not p3:
        print("\n      !! P3 REFUTED. The unidirectional-native feature design does not")
        print("         beat visibility-matched retraining. Reported as-is; the")
        print("         contribution is the failure mode and its fix, not a feature set.")

    # ---- the headline number, computed rather than asserted -----------------
    oneway_B = float(res[(res.rung == "DIODE_ONEWAY") & (res.condition == "B_DEPLOYED")].macro_f1.iloc[0])
    oneway_C = float(res[(res.rung == "DIODE_ONEWAY") & (res.condition == "C_RETRAINED")].macro_f1.iloc[0])
    print("\n" + "=" * 74)
    print("HEADLINE")
    print("=" * 74)
    print(f"  Naive deployment cost      : {oneway_B - f1_A:+.4f} macro-F1  "
          f"({f1_A:.3f} -> {oneway_B:.3f})")
    print(f"  Recovered by matched retrain: {oneway_C - oneway_B:+.4f} macro-F1  "
          f"({oneway_B:.3f} -> {oneway_C:.3f})")
    print(f"  Residual vs full visibility : {oneway_C - f1_A:+.4f} macro-F1")

    per_class_collapse = {}
    for cls in classes:
        a = float(res[res.condition == "A_FULL"][cls].iloc[0])
        b = float(res[(res.rung == "DIODE_ONEWAY") & (res.condition == "B_DEPLOYED")][cls].iloc[0])
        c = float(res[(res.rung == "DIODE_ONEWAY") & (res.condition == "C_RETRAINED")][cls].iloc[0])
        per_class_collapse[cls] = {"full": a, "deployed": b, "retrained": c, "drop": b - a}
    worst = sorted(per_class_collapse.items(), key=lambda kv: kv[1]["drop"])[:3]
    print("\n  Classes that collapse hardest under naive deployment:")
    for cls, v in worst:
        print(f"    {cls:<10s} F1 {v['full']:.3f} -> {v['deployed']:.3f} "
              f"({v['drop']:+.3f}), recovered to {v['retrained']:.3f}")

    (RESULTS / "exp01_verdicts.json").write_text(json.dumps(
        {"macro_f1_full": f1_A,
         "predictions_were_registered_before_running": True,
         "verdicts": verdicts,
         "enrichment_rung_cost": enrich_drop,
         "direction_rung_cost": direction_drop,
         "headline": {
             "naive_deployment_cost": oneway_B - f1_A,
             "recovered_by_matched_retraining": oneway_C - oneway_B,
             "residual_vs_full": oneway_C - f1_A,
         },
         "per_class": per_class_collapse}, indent=2))

    print("\n      wrote results/exp01_ablation.csv and exp01_verdicts.json")
    print(f"      total runtime {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()

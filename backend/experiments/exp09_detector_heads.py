"""Experiment 09 — do independent heads beat one multiclass model?

Every experiment before this used a single XGBoost softmax over all classes.
`detect/base.py` argues that is the wrong decomposition, mainly because a
softmax cannot say a host is *both* scanning and exfiltrating. This measures
whether that argument is worth anything on this data, instead of asserting it.

The measurement that matters
----------------------------
Single-label ground truth cannot answer the question, because it forces exactly
the exclusivity under test. So the labels here are **multi-label**: for each
(window, host) cell, the set of attack classes with traffic in it. Co-occurrence
is then a property of the data rather than an assumption.

Pre-registered predictions (written before the first run)
---------------------------------------------------------
  Y1  Co-occurrence is real: more than 1% of attack cells carry >= 2 classes.
      If it is near zero, the multi-label argument is theoretical on this data
      and the heads are justified only by the other three reasons.
  Y2  On co-occurring cells, the head ensemble recovers more of the true label
      set than the softmax can (which is capped at one label by construction).
  Y3  The two knowingly-handicapped heads - dga and encrypted - score clearly
      below the other four, because their discriminative features are absent
      from the host-window set rather than because the classes are hard.
  Y4  Each head's highest-gain feature is one its stated rationale names. A head
      that scores well on unrelated features is a warning, not a success.

WHAT THE FIRST RUN SHOWED  (recorded before adding the controls)
-----------------------------------------------------------------
The multiclass baseline beat the heads on **every class**, several of them
catastrophically (scan 0.012 vs 0.746, exfil 0.000 vs 0.818). Three confounds
could each produce that, and the first run separated none of them:

  decomposition   maybe independent binary heads really are worse here
  starvation      each head saw 6 of 16 features; multiclass saw all 16
  threshold       a fixed 0.5 cut on 13 positives predicts all-negative,
                  which is an F1 of exactly 0.000 regardless of the model

So this run adds two controls. Heads are additionally fitted with the **full**
feature set, isolating starvation from decomposition; and every comparison is
reported at **average precision** (threshold-free) alongside F1 at a threshold
tuned per head on a validation slice. If the heads still lose on AP with full
features, the decomposition argument in `detect/base.py` is simply wrong and
gets rewritten.

Run:  python experiments/exp09_detector_heads.py
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sklearn.metrics import average_precision_score, f1_score
from xgboost import XGBClassifier  # noqa: E402

from ekagra.detect.base import HeadEnsemble  # noqa: E402
from ekagra.detect.heads import build_heads  # noqa: E402
from ekagra.features.host_window import HOST_WINDOW_FEATURES, WINDOW_S  # noqa: E402
from ekagra.features.protocol import PROTOCOL_FEATURES  # noqa: E402

# The packet path can supply DNS query names and TLS fingerprints, which the
# sixteen protocol-agnostic aggregates deliberately ignore. Both groups are
# offered to every head; FEATURES on each head remains documentation of what it
# is *meant* to key on, not a training restriction (see exp09's own finding).
ALL_FEATURES = list(HOST_WINDOW_FEATURES) + list(PROTOCOL_FEATURES)
from ekagra.features.streaming_host_window import StreamingHostWindow
from ekagra.ingest.flow_assembler import ACTIVE_TIMEOUT_S, IDLE_TIMEOUT_S, FlowAssembler  # noqa: E402
from ekagra.ingest.synthetic import GeneratorConfig, SyntheticSource  # noqa: E402
from ekagra.ingest.visibility import DIODE_ONEWAY, VisibilityFilter  # noqa: E402

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
SEED = 0
LATENESS = 15.0
THREAT_CLASSES = ("ddos", "scan", "beacon", "exfil", "dga", "encrypted")


def multilabel_truth(packets):
    """For each (window, host): the SET of attack classes present.

    This is the whole point of the experiment. Collapsing to a single majority
    label - as every earlier experiment did - builds the exclusivity assumption
    into the ground truth, and then a softmax cannot be shown to be wrong.
    """
    t0 = min(p.ts for p in packets)
    sets = defaultdict(set)
    for p in packets:
        if p.label == "benign":
            continue
        w = int((p.ts - t0) // WINDOW_S)
        sets[(w, p.src_ip)].add(p.label)
        sets[(w, p.dst_ip)].add(p.label)
    return sets


def run_sensor(packets):
    fa = FlowAssembler(idle_timeout=IDLE_TIMEOUT_S, active_timeout=ACTIVE_TIMEOUT_S)
    ex = StreamingHostWindow(window_s=WINDOW_S, t0=0.0, allowed_lateness_s=LATENESS)
    t0 = packets[0].ts
    rows = []
    for p in packets:
        for rec in fa.push(p):
            rows.extend(ex.push(replace(rec, ts=rec.ts - t0)))
    for rec in fa.flush():
        rows.extend(ex.push(replace(rec, ts=rec.ts - t0)))
    rows.extend(ex.flush())
    return rows


def main() -> None:
    t_all = time.time()
    print("=" * 78)
    print("EKAGRA  ·  Experiment 09  ·  Independent heads vs one multiclass model")
    print("=" * 78)

    print("\n[1/5] Sensor run ...")
    packets = SyntheticSource(GeneratorConfig(seed=23, duration_s=3600.0)).generate()
    observed = list(VisibilityFilter(DIODE_ONEWAY).apply(packets))
    truth = multilabel_truth(observed)
    rows = run_sensor(observed)
    print(f"      {len(observed):,} packets -> {len(rows):,} (window, host) cells")

    label_sets = [truth.get((int(r["window"]), r["host"]), set()) for r in rows]
    Y = {c: np.array([c in s for s in label_sets], dtype=int) for c in THREAT_CLASSES}
    X = np.array([[float(r.get(f, 0.0)) for f in ALL_FEATURES] for r in rows],
                 dtype=np.float32)
    win = np.array([int(r["window"]) for r in rows])

    print("\n[2/5] Co-occurrence in the ground truth ...")
    sizes = Counter(len(s) for s in label_sets)
    attack_cells = sum(v for k, v in sizes.items() if k >= 1)
    multi = sum(v for k, v in sizes.items() if k >= 2)
    print(f"      cells with 0 classes {sizes.get(0,0):,} | "
          f"1 class {sizes.get(1,0):,} | 2+ classes {multi:,}")
    frac_multi = multi / max(1, attack_cells)
    print(f"      {100*frac_multi:.2f}% of attack cells carry more than one class")
    pairs = Counter()
    for s in label_sets:
        if len(s) >= 2:
            for a in sorted(s):
                for b in sorted(s):
                    if a < b:
                        pairs[(a, b)] += 1
    for (a, b), n in pairs.most_common(5):
        print(f"        {a} + {b}: {n:,}")

    # Three-way split: the per-head threshold must be tuned somewhere that is
    # neither training nor test, or the F1 comparison is rigged.
    c1, c2 = np.quantile(win, [0.60, 0.70])
    tr, va, te = win <= c1, (win > c1) & (win <= c2), win > c2
    print(f"\n[3/5] Temporal split  train {tr.sum():,} | val {va.sum():,} | "
          f"test {te.sum():,}")

    print("\n[4/5] Fitting heads (declared subsets and full features) "
          "plus a multiclass baseline ...")
    # Starved variant: each head restricted to its declared subset. Retained
    # because it is the finding, not because it is the design.
    ens = HeadEnsemble(build_heads(restrict_features=True), ALL_FEATURES)
    ens.fit(X[tr], {c: Y[c][tr] for c in THREAT_CLASSES})

    # The shipped configuration: same heads, full feature set.
    full = HeadEnsemble(build_heads(), ALL_FEATURES)
    full.fit(X[tr], {c: Y[c][tr] for c in THREAT_CLASSES})

    def tuned_threshold(head, mask):
        """Pick the F1-maximising cut on the validation slice."""
        p = head.score(X[mask], ALL_FEATURES)
        yt = Y[head.threat_class][mask]
        if yt.sum() == 0:
            return 0.5
        best, best_f = 0.5, -1.0
        for t in np.unique(np.round(np.quantile(p, np.linspace(0.5, 0.999, 40)), 6)):
            f = f1_score(yt, (p >= t).astype(int), zero_division=0)
            if f > best_f:
                best, best_f = float(t), f
        return best

    for h in ens.heads:
        h.threshold = tuned_threshold(h, va)
    for h in full.heads:
        h.threshold = tuned_threshold(h, va)

    # Multiclass baseline: collapse the label set to one label, which is what a
    # softmax requires. Ties broken by rarity so it gets the friendliest
    # possible version of the collapse.
    freq = {c: int(Y[c].sum()) for c in THREAT_CLASSES}
    order = sorted(THREAT_CLASSES, key=lambda c: freq[c])
    def collapse(s):
        for c in order:
            if c in s:
                return c
        return "benign"
    single = np.array([collapse(s) for s in label_sets])
    mc_classes = ["benign"] + list(THREAT_CLASSES)
    midx = {c: i for i, c in enumerate(mc_classes)}
    ymc = np.array([midx[c] for c in single])
    mc = XGBClassifier(n_estimators=180, max_depth=5, learning_rate=0.15,
                       subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                       objective="multi:softprob", num_class=len(mc_classes),
                       n_jobs=4, eval_metric="mlogloss", random_state=SEED)
    mc.fit(X[tr], ymc[tr])
    mc_pred = mc.predict(X[te])

    mc_proba = mc.predict_proba(X[te])
    print("\n      average precision (threshold-free) and F1 at a tuned cut")
    print(f"      {'head':<12s} {'support':>8s} | {'AP sub':>7s} {'AP full':>7s} "
          f"{'AP mc':>7s} | {'F1 sub':>7s} {'F1 full':>7s} {'F1 mc':>7s}  top feature")
    per_head = {}
    for h, hf in zip(ens.heads, full.heads):
        c = h.threat_class
        yt = Y[c][te]
        p_sub = h.score(X[te], ALL_FEATURES)
        p_full = hf.score(X[te], ALL_FEATURES)
        p_mc = mc_proba[:, midx[c]]
        ap_sub = average_precision_score(yt, p_sub) if yt.sum() else float("nan")
        ap_full = average_precision_score(yt, p_full) if yt.sum() else float("nan")
        ap_mc = average_precision_score(yt, p_mc) if yt.sum() else float("nan")
        f_sub = f1_score(yt, (p_sub >= h.threshold).astype(int), zero_division=0)
        f_full = f1_score(yt, (p_full >= hf.threshold).astype(int), zero_division=0)
        f_mc = f1_score(yt, (mc_pred == midx[c]).astype(int), zero_division=0)
        gains = sorted(h._gain.items(), key=lambda kv: -kv[1])
        top = gains[0][0] if gains else "-"
        flag = " [handicapped]" if h.HANDICAPPED else ""
        print(f"      {h.name:<12s} {int(yt.sum()):>8,} | {ap_sub:>7.3f} {ap_full:>7.3f} "
              f"{ap_mc:>7.3f} | {f_sub:>7.3f} {f_full:>7.3f} {f_mc:>7.3f}  {top}{flag}")
        per_head[h.name] = {
            "threat_class": c, "support": int(yt.sum()),
            "ap_subset": ap_sub, "ap_full": ap_full, "ap_multiclass": ap_mc,
            "f1_subset": f_sub, "f1_full": f_full, "f1_multiclass": f_mc,
            "threshold_subset": h.threshold, "threshold_full": hf.threshold,
            "top_feature": top, "handicapped": bool(h.HANDICAPPED)}

    print("\n[5/5] Multi-label recovery on co-occurring cells ...")
    multi_mask = te & np.array([len(s) >= 2 for s in label_sets])
    n_multi = int(multi_mask.sum())
    if n_multi:
        preds = full.predict(X[multi_mask])
        got_heads = got_mc = need = 0
        mc_multi = mc.predict(X[multi_mask])
        for j, i in enumerate(np.flatnonzero(multi_mask)):
            true_set = label_sets[i]
            need += len(true_set)
            got_heads += sum(1 for c in true_set if preds[c][j])
            got_mc += 1 if mc_classes[mc_multi[j]] in true_set else 0
        print(f"      {n_multi:,} co-occurring test cells, {need:,} true labels")
        print(f"      heads recovered      {got_heads:,}/{need:,} "
              f"({100*got_heads/need:.1f}%)")
        print(f"      multiclass recovered {got_mc:,}/{need:,} "
              f"({100*got_mc/need:.1f}%)  - capped at 1 label per cell by design")
    else:
        got_heads = got_mc = need = 0
        print("      no co-occurring cells in the test split")

    print("\n" + "=" * 78)
    print("PRE-REGISTERED PREDICTIONS")
    print("=" * 78)
    y1 = frac_multi > 0.01
    y2 = (got_heads > got_mc) if need else False
    hand = [h for h in per_head.values() if h["handicapped"]]
    fine = [h for h in per_head.values() if not h["handicapped"]]
    y3 = (max(h["ap_subset"] for h in hand) < min(h["ap_subset"] for h in fine)) \
        if hand and fine else False
    y4 = all(h.declares(per_head[h.name]["top_feature"]) for h in ens.heads)

    # The controls: which of the three explanations actually holds?
    import statistics as _st
    ap_sub = _st.mean(h["ap_subset"] for h in per_head.values())
    ap_full = _st.mean(h["ap_full"] for h in per_head.values())
    ap_mc = _st.mean(h["ap_multiclass"] for h in per_head.values())
    print()
    print(f"  mean AP  subset-heads {ap_sub:.3f} | full-feature heads {ap_full:.3f} "
          f"| multiclass {ap_mc:.3f}")
    starvation = ap_full - ap_sub
    decomposition = ap_full - ap_mc
    print(f"  cost of feature starvation : {starvation:+.3f} AP")
    print(f"  cost of decomposition      : {decomposition:+.3f} AP "
          f"(full-feature heads vs multiclass)")
    for k, ok, d in [
        ("Y1", y1, f"co-occurrence is real ({100*frac_multi:.2f}% of attack cells)"),
        ("Y2", y2, f"heads recover more labels on co-occurring cells "
                   f"({got_heads} vs {got_mc} of {need})"),
        ("Y3", y3, f"handicapped heads score below the rest on AP "
                   f"(worst normal {min((h['ap_subset'] for h in fine), default=0):.3f}, "
                   f"best handicapped {max((h['ap_subset'] for h in hand), default=0):.3f})"),
        ("Y4", y4, "each head's top feature is one it declared")]:
        print(f"  {k}  {'HOLDS ' if ok else 'FAILS '}  {d}")

    (RESULTS / "exp09_verdicts.json").write_text(json.dumps({
        "cells": len(rows), "test_cells": int(te.sum()),
        "cooccurrence_fraction": frac_multi,
        "cooccurring_pairs": {f"{a}+{b}": n for (a, b), n in pairs.most_common(10)},
        "per_head": per_head,
        "mean_ap": {"subset_heads": ap_sub, "full_feature_heads": ap_full,
                    "multiclass": ap_mc},
        "cost_of_starvation_ap": starvation,
        "cost_of_decomposition_ap": decomposition,
        "multilabel_recovery": {"true_labels": need, "heads": got_heads,
                                "multiclass": got_mc, "cells": n_multi},
        "verdicts": {"Y1": bool(y1), "Y2": bool(y2), "Y3": bool(y3), "Y4": bool(y4)},
    }, indent=2, default=float))
    print("\n  wrote results/exp09_verdicts.json")
    print(f"  total runtime {time.time()-t_all:.1f}s")


if __name__ == "__main__":
    main()

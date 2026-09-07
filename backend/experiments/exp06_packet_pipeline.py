"""Experiment 06 — the full packet pipeline, and what out-of-order flows cost.

What this closes
----------------
Experiments 03-05 all start from flow records. CIC-IDS2017 ships them
pre-assembled; a diode enclave does not. This runs the whole chain a real
sensor would:

    packets -> visibility filter -> flow assembler -> streaming host-window
            -> detector

The problem this exposes
------------------------
A flow assembler emits a flow when it *expires*, not when it starts. A flow
beginning at t=10s and idling out at t=70s is emitted at t=70s but belongs to
the window containing t=10s. So the windowed aggregator receives records out of
order with respect to their own start times.

`StreamingHostWindow` handles this with `allowed_lateness_s`, keeping several
windows open at once. Setting it too low silently discards flows; setting it
too high raises end-to-end latency for no benefit. This experiment measures the
trade-off rather than guessing at it.

Data
----
The synthetic generator, because it emits **packets** with ground-truth labels.
CIC-IDS2017's freely-available form is flow records, so it cannot exercise an
assembler at all. That makes this a test of the *mechanism*, not a second
validation of the exp04 result - and the distinction is stated rather than
blurred.

Pre-registered predictions (written before the first run)
---------------------------------------------------------
  V1  At `allowed_lateness_s = 0`, a material fraction of flows (>5%) is
      dropped as late. If not, the out-of-order problem is smaller than the
      module docstrings claim and those should be toned down.
  V2  At lateness >= the assembler idle timeout (15s), loss falls below 1%.
  V3  With adequate lateness, detector F1 comes within 0.01 of an
      oracle-ordered run (identical flows, fed sorted by start time).
  V4  End-to-end packet throughput > 100,000 packets/sec single-threaded.

Run:  python experiments/exp06_packet_pipeline.py
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sklearn.metrics import f1_score  # noqa: E402
from xgboost import XGBClassifier  # noqa: E402

from ekagra.features.host_window import HOST_WINDOW_FEATURES, WINDOW_S  # noqa: E402
from ekagra.features.streaming_host_window import StreamingHostWindow
from ekagra.ingest.flow_assembler import (  # noqa: E402
    ACTIVE_TIMEOUT_S, IDLE_TIMEOUT_S, FlowAssembler,
)
from ekagra.ingest.records import THREAT_CLASSES  # noqa: E402
from ekagra.ingest.synthetic import GeneratorConfig, SyntheticSource  # noqa: E402
from ekagra.ingest.visibility import DIODE_ONEWAY, VisibilityFilter  # noqa: E402

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
SEED = 0
LATENESS_GRID = [0.0, 5.0, 15.0, 30.0, 60.0, 120.0]
TRAIN_FRACTION = 0.70


def ground_truth_labels(packets, window_s=WINDOW_S):
    """Label each (window, host) cell from the packet-level ground truth.

    A cell is malicious if any attack packet involving that host falls in it -
    the same rule exp01 uses, so a low-rate beacon cannot hide inside a busy
    host's window.
    """
    t0 = min(p.ts for p in packets)
    counts = defaultdict(lambda: defaultdict(int))
    for p in packets:
        w = int((p.ts - t0) // window_s)
        counts[(w, p.src_ip)][p.label] += 1
        counts[(w, p.dst_ip)][p.label] += 1
    out = {}
    for key, c in counts.items():
        attack = {k: v for k, v in c.items() if k != "benign"}
        out[key] = max(attack.items(), key=lambda kv: kv[1])[0] if attack else "benign"
    return out


def run_pipeline(packets, lateness, assemble_only=False, oracle_order=False):
    """packets -> flows -> host-window rows. Returns rows + combined stats."""
    fa = FlowAssembler(idle_timeout=IDLE_TIMEOUT_S, active_timeout=ACTIVE_TIMEOUT_S)
    ex = StreamingHostWindow(window_s=WINDOW_S, t0=0.0,
                             allowed_lateness_s=lateness)
    t0 = packets[0].ts
    rows = []

    t_start = time.perf_counter()
    if oracle_order:
        # Assemble everything first, then feed sorted by flow start. This is
        # not deployable - it needs the whole capture - but it isolates the
        # cost of out-of-order arrival from every other effect.
        flows = []
        for p in packets:
            flows.extend(fa.push(p))
        flows.extend(fa.flush())
        for rec in sorted(flows, key=lambda r: r.ts):
            rows.extend(ex.push(replace(rec, ts=rec.ts - t0)))
    else:
        for p in packets:
            for rec in fa.push(p):
                rows.extend(ex.push(replace(rec, ts=rec.ts - t0)))
        for rec in fa.flush():
            rows.extend(ex.push(replace(rec, ts=rec.ts - t0)))
    rows.extend(ex.flush())
    elapsed = time.perf_counter() - t_start

    stats = {**fa.stats(), **ex.stats()}
    stats["wall_s"] = elapsed
    stats["packets_per_s"] = len(packets) / max(1e-9, elapsed)
    return pd.DataFrame(rows), stats


def train_eval(rows: pd.DataFrame, labels: dict, name: str):
    if rows.empty:
        print(f"      {name:<34s} no rows")
        return 0.0
    df = rows.copy()
    df["label"] = [labels.get((int(w), h), "benign")
                   for w, h in zip(df["window"], df["host"])]
    classes = [c for c in THREAT_CLASSES if c in set(df["label"])]
    idx = {c: i for i, c in enumerate(classes)}

    cutoff = df["window"].quantile(TRAIN_FRACTION)
    tr = (df["window"] <= cutoff).to_numpy()
    te = ~tr
    if te.sum() < 50 or len(classes) < 2:
        print(f"      {name:<34s} insufficient test data")
        return 0.0

    X = df[list(HOST_WINDOW_FEATURES)].to_numpy(dtype=np.float32)
    y = df["label"].map(idx).to_numpy()
    tr_classes = sorted(set(y[tr]))
    remap = {c: i for i, c in enumerate(tr_classes)}
    y_tr = np.array([remap[v] for v in y[tr]])
    benign_i = remap.get(idx.get("benign", -1), -1)

    m = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.15,
                      subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                      objective="multi:softprob", num_class=len(tr_classes),
                      n_jobs=4, eval_metric="mlogloss", random_state=SEED)
    m.fit(X[tr], y_tr)
    pred = m.predict(X[te])
    y_bin = (df["label"].to_numpy()[te] != "benign").astype(int)
    binf = f1_score(y_bin, (pred != benign_i).astype(int),
                    average="macro", zero_division=0)
    print(f"      {name:<34s} binary-F1 {binf:.4f}   ({len(df):,} cells)")
    return binf


def main() -> None:
    t_all = time.time()
    print("=" * 78)
    print("EKAGRA  ·  Experiment 06  ·  Packet -> flow -> features, end to end")
    print("=" * 78)

    print("\n[1/4] Generating packets and applying the one-way tap ...")
    packets = SyntheticSource(GeneratorConfig(seed=11, duration_s=3600.0)).generate()
    observed = list(VisibilityFilter(DIODE_ONEWAY).apply(packets))
    print(f"      {len(packets):,} packets generated, "
          f"{len(observed):,} observed on a one-way tap "
          f"({100*len(observed)/len(packets):.1f}%)")
    labels = ground_truth_labels(observed)
    print(f"      {len(labels):,} (window, host) cells labelled from ground truth")

    print("\n[2/4] Lateness sweep ...")
    print(f"      assembler: idle {IDLE_TIMEOUT_S:.0f}s, active {ACTIVE_TIMEOUT_S:.0f}s")
    print(f"      {'lateness':>9s} {'flows kept':>12s} {'dropped late':>13s} "
          f"{'loss':>7s} {'cells':>9s} {'total latency':>14s}")
    sweep = []
    frames = {}
    for lat in LATENESS_GRID:
        rows, st = run_pipeline(observed, lat)
        total = st["flows"] + st["dropped_late"]
        loss = st["dropped_late"] / max(1, total)
        sweep.append({"lateness_s": lat, "flows_kept": st["flows"],
                      "dropped_late": st["dropped_late"], "loss_frac": loss,
                      "cells": len(rows), "latency_s": st["latency_s"],
                      "packets_per_s": st["packets_per_s"]})
        frames[lat] = rows
        print(f"      {lat:>8.0f}s {st['flows']:>12,} {st['dropped_late']:>13,} "
              f"{100*loss:>6.2f}% {len(rows):>9,} {st['latency_s']:>13.0f}s")
    sw = pd.DataFrame(sweep)
    sw.to_csv(RESULTS / "exp06_lateness_sweep.csv", index=False)

    print("\n[3/4] Assembler behaviour ...")
    _, st_ref = run_pipeline(observed, 60.0)
    for k in ("packets", "flows_emitted", "closed_by_flags", "closed_by_idle",
              "closed_by_active", "evicted_flows"):
        print(f"      {k:<20s} {st_ref[k]:>12,}")
    print(f"      throughput           {st_ref['packets_per_s']:>12,.0f} packets/s")

    print("\n[4/4] Detector, realistic order vs oracle order ...")
    f1_by_lat = {}
    for lat in (0.0, 15.0, 60.0):
        f1_by_lat[lat] = train_eval(frames[lat], labels, f"lateness {lat:.0f}s")
    oracle_rows, oracle_st = run_pipeline(observed, 0.0, oracle_order=True)
    f1_oracle = train_eval(oracle_rows, labels, "oracle order (not deployable)")

    print("\n" + "=" * 78)
    print("PRE-REGISTERED PREDICTIONS")
    print("=" * 78)
    loss0 = float(sw[sw.lateness_s == 0.0].loss_frac.iloc[0])
    loss15 = float(sw[sw.lateness_s == 15.0].loss_frac.iloc[0])
    v1 = loss0 > 0.05
    v2 = loss15 < 0.01
    v3 = abs(f1_by_lat[60.0] - f1_oracle) < 0.01
    v4 = st_ref["packets_per_s"] > 100_000
    for k, ok, d in [
        ("V1", v1, f"lateness=0 drops >5% of flows ({100*loss0:.2f}%)"),
        ("V2", v2, f"lateness=15s drops <1% ({100*loss15:.2f}%)"),
        ("V3", v3, f"F1 at 60s within 0.01 of oracle order "
                   f"({f1_by_lat[60.0]:.4f} vs {f1_oracle:.4f})"),
        ("V4", v4, f"throughput > 100k packets/s "
                   f"({st_ref['packets_per_s']:,.0f})")]:
        print(f"  {k}  {'HOLDS ' if ok else 'FAILS '}  {d}")

    print("\n" + "=" * 78)
    print("HEADLINE")
    print("=" * 78)
    print("  end-to-end: packets -> flows -> host-window features")
    print(f"    throughput          {st_ref['packets_per_s']:>12,.0f} packets/s")
    print(f"    flows assembled     {st_ref['flows_emitted']:>12,}")
    print(f"    lateness needed     {'15s' if v2 else 'see sweep':>12s}  "
          f"for <1% flow loss")
    print(f"    total latency       {WINDOW_S + 15.0:>12.0f}s  "
          f"(window + lateness budget)")
    print(f"    F1 cost of realistic ordering vs oracle: "
          f"{f1_by_lat[60.0] - f1_oracle:+.4f}")

    (RESULTS / "exp06_verdicts.json").write_text(json.dumps({
        "packets_generated": len(packets), "packets_observed": len(observed),
        "assembler": {k: st_ref[k] for k in
                      ("flows_emitted", "closed_by_flags", "closed_by_idle",
                       "closed_by_active", "evicted_flows", "packets_per_s")},
        "lateness_sweep": sweep,
        "f1_by_lateness": {str(k): v for k, v in f1_by_lat.items()},
        "f1_oracle_order": f1_oracle,
        "verdicts": {"V1": bool(v1), "V2": bool(v2), "V3": bool(v3), "V4": bool(v4)},
        "note": "synthetic packets - CIC-IDS2017 ships flow records and cannot "
                "exercise an assembler. This tests the mechanism, not the exp04 result.",
    }, indent=2, default=float))
    print("\n  wrote results/exp06_verdicts.json and exp06_lateness_sweep.csv")
    print(f"  total runtime {time.time()-t_all:.1f}s")


if __name__ == "__main__":
    main()

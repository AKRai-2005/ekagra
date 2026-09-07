"""Experiment 05 — does the streaming sketch version match the batch one?

Why this matters more than it looks
-----------------------------------
Experiment 04's result rests entirely on 16 host-window features. Those were
computed with a pandas `groupby` over the whole capture - a batch operation
that cannot run on a live link. The problem statement is explicit that the
pipeline must be streaming with bounded latency.

So the exp04 result is only meaningful if the same features can be produced
incrementally in bounded memory. This experiment checks that, and measures what
the approximation costs.

Three questions
---------------
  1. Do the streaming features agree with the exact ones, per feature?
  2. Does the downstream detector lose accuracy when trained on them?
  3. What throughput and memory does the streaming extractor actually achieve?

One feature is expected to disagree, by design
----------------------------------------------
`hw_src_bytes_vs_baseline` is defined differently in the two implementations:

  batch      EWM over the sequence of windows in which the host appeared,
             skipping windows where it was silent
  streaming  time-decayed counter, which decays across silent gaps

The streaming definition is the more defensible one - a host silent for an hour
should not carry a hot baseline - but it is genuinely a different quantity, and
we report the disagreement rather than tuning one to match the other.

Pre-registered predictions (written before the first run)
---------------------------------------------------------
  U1  Every feature except `hw_src_bytes_vs_baseline` correlates > 0.99 with
      its exact counterpart. Most hosts touch few peers per window, so the
      sparse-exact path should dominate and error should be near zero.
  U2  Binary F1 from streaming features is within 0.01 of the batch version.
  U3  Sustained throughput > 50,000 flows/sec single-threaded.
  U4  Zero host evictions at max_hosts=50,000 on this corpus, and tracked-host
      count stays bounded.

Run:  python experiments/exp05_streaming_equivalence.py
"""

from __future__ import annotations

import json
import sys
import time
import tracemalloc
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
from ekagra.features.streaming_host_window import (  # noqa: E402
    FlowRecord, StreamingHostWindow,
)
from ekagra.ingest.replay import CICIDS2017, FORWARD_OBSERVABLE, load_subsampled  # noqa: E402

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
SEED = 0
TRAIN_FRACTION = 0.70
MAX_HOSTS = 50_000

SRC_FEATURES = [c for c in HOST_WINDOW_FEATURES if c.startswith("hw_src_")]
DST_FEATURES = [c for c in HOST_WINDOW_FEATURES if c.startswith("hw_dst_")]


def stream_features(df: pd.DataFrame, trace: bool = False) -> tuple[pd.DataFrame, dict, float]:
    """Run the streaming extractor over the flows in timestamp order.

    `trace` enables tracemalloc, which costs ~2-3x in wall time. Throughput is
    therefore measured on an untraced pass and memory on a traced one - quoting
    a throughput number measured under tracemalloc would understate it badly.
    """
    t0 = df["Timestamp"].min()
    ts = (df["Timestamp"] - t0).dt.total_seconds().to_numpy()
    src = df["Src IP"].to_numpy()
    dst = df["Dst IP"].to_numpy()
    dport = pd.to_numeric(df["Dst Port"], errors="coerce").fillna(0).astype(np.int64).to_numpy()
    pk = pd.to_numeric(df["Total Fwd Packet"], errors="coerce").fillna(0.0).to_numpy()
    by = pd.to_numeric(df["Total Length of Fwd Packet"], errors="coerce").fillna(0.0).to_numpy()

    ex = StreamingHostWindow(window_s=WINDOW_S, max_hosts=MAX_HOSTS, t0=0.0)
    rows = []
    if trace:
        tracemalloc.start()
    t_start = time.perf_counter()
    for i in range(len(ts)):
        out = ex.push(FlowRecord(ts[i], src[i], dst[i], int(dport[i]),
                                 float(pk[i]), float(by[i])))
        if out:
            rows.extend(out)
    rows.extend(ex.flush())
    elapsed = time.perf_counter() - t_start
    peak = 0
    if trace:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    stats = ex.stats()
    stats["peak_traced_mb"] = peak / 1e6
    stats["throughput_flows_per_s"] = len(ts) / max(1e-9, elapsed)
    stats["wall_s"] = elapsed
    return pd.DataFrame(rows), stats, elapsed


def measure_memory(df: pd.DataFrame) -> float:
    """Peak traced memory of the extractor alone, emitted rows discarded."""
    t0 = df["Timestamp"].min()
    ts = (df["Timestamp"] - t0).dt.total_seconds().to_numpy()
    src = df["Src IP"].to_numpy()
    dst = df["Dst IP"].to_numpy()
    dport = pd.to_numeric(df["Dst Port"], errors="coerce").fillna(0).astype(np.int64).to_numpy()
    pk = pd.to_numeric(df["Total Fwd Packet"], errors="coerce").fillna(0.0).to_numpy()
    by = pd.to_numeric(df["Total Length of Fwd Packet"], errors="coerce").fillna(0.0).to_numpy()

    ex = StreamingHostWindow(window_s=WINDOW_S, max_hosts=MAX_HOSTS, t0=0.0)
    tracemalloc.start()
    for i in range(len(ts)):
        ex.push(FlowRecord(ts[i], src[i], dst[i], int(dport[i]),
                           float(pk[i]), float(by[i])))   # rows discarded
    ex.flush()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1e6


def join_stream(df: pd.DataFrame, emitted: pd.DataFrame) -> pd.DataFrame:
    """Attach streaming features to flows, mirroring the batch join exactly."""
    out = df.copy()
    t0 = out["Timestamp"].min()
    out["window"] = (((out["Timestamp"] - t0).dt.total_seconds()) // WINDOW_S).astype(np.int64)

    s = emitted[["window", "host"] + SRC_FEATURES].rename(columns={"host": "Src IP"})
    d = emitted[["window", "host"] + DST_FEATURES].rename(columns={"host": "Dst IP"})
    out = out.merge(s, on=["window", "Src IP"], how="left")
    out = out.merge(d, on=["window", "Dst IP"], how="left")
    out[HOST_WINDOW_FEATURES] = (out[HOST_WINDOW_FEATURES]
                                 .replace([np.inf, -np.inf], np.nan).fillna(0.0))
    return out


def to_matrix(df, cols):
    x = df[list(cols)].apply(pd.to_numeric, errors="coerce")
    return x.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)


def main() -> None:
    t_all = time.time()
    print("=" * 78)
    print("EKAGRA  ·  Experiment 05  ·  Streaming vs batch host-window features")
    print("=" * 78)

    ds = CICIDS2017()
    if not Path(ds.path).exists():
        sys.exit(f"corpus not found at {ds.path}")

    print("\n[1/5] Loading corpus ...")
    df = load_subsampled(Path(ds.path), 0.30)

    print("\n[2/5] Batch (pandas groupby) reference ...")
    t = time.perf_counter()
    batch = add_host_window_features(df, window_s=WINDOW_S)
    batch_s = time.perf_counter() - t
    print(f"      {batch_s:.1f}s   ({len(df)/batch_s:,.0f} flows/s)")

    print("\n[3/5] Streaming (single pass, bounded memory) ...")
    emitted, stats, stream_s = stream_features(df, trace=False)
    print(f"      {stream_s:.1f}s   ({stats['throughput_flows_per_s']:,.0f} flows/s, untraced)")
    # Memory is measured on a separate pass that discards the emitted rows.
    # Two reasons: tracemalloc costs ~2-3x wall time so it must not contaminate
    # the throughput figure, and accumulating 132k output rows in a list
    # measures the *sink*, not the sensor. A real deployment hands each row
    # to the alert bus and forgets it.
    stats["peak_traced_mb"] = measure_memory(df)
    print(f"      emitted {len(emitted):,} (window, host) rows over "
          f"{stats['windows']:,} windows")
    print(f"      peak traced memory {stats['peak_traced_mb']:.2f} MB "
          f"(sensor state only)   evicted hosts {stats['evicted_hosts']:,}")
    print(f"      distinct hosts seen {stats['baseline_entries']:,}")
    print(f"      latency = window length = {stats['latency_s']:.0f}s")

    stream = join_stream(df, emitted)

    # ------------------------------------------------------- per-feature check
    print("\n[4/5] Per-feature agreement ...")
    agree = []
    for c in HOST_WINDOW_FEATURES:
        a = batch[c].to_numpy(dtype=np.float64)
        b = stream[c].to_numpy(dtype=np.float64)
        if np.std(a) < 1e-12 and np.std(b) < 1e-12:
            r = 1.0
        else:
            r = float(np.corrcoef(a, b)[0, 1]) if np.std(a) > 0 and np.std(b) > 0 else 0.0
        denom = np.maximum(np.abs(a), 1.0)
        mre = float(np.mean(np.abs(a - b) / denom))
        exact = float(np.mean(np.isclose(a, b, rtol=1e-6, atol=1e-9)))
        agree.append({"feature": c, "pearson_r": r, "mean_rel_err": mre,
                      "frac_bitwise_equal": exact})
    ag = pd.DataFrame(agree).sort_values("pearson_r")
    print(f"      {'feature':<32s} {'r':>8s} {'mean_rel_err':>14s} {'exact':>8s}")
    for _, row in ag.iterrows():
        flag = "  <- differs by design" if row.feature == "hw_src_bytes_vs_baseline" else ""
        print(f"      {row.feature:<32s} {row.pearson_r:>8.4f} "
              f"{row.mean_rel_err:>14.5f} {row.frac_bitwise_equal:>8.3f}{flag}")
    ag.to_csv(RESULTS / "exp05_feature_agreement.csv", index=False)

    # ---------------------------------------------------------- downstream F1
    print("\n[5/5] Downstream detector, batch vs streaming features ...")
    wq = batch["window"].quantile(TRAIN_FRACTION)
    cutoff_w = int(np.floor(wq))
    tr = (batch["window"] <= cutoff_w).to_numpy()
    te = ~tr
    train_labels = sorted(set(batch.loc[tr, "Label"]))
    idx = {c: i for i, c in enumerate(train_labels)}
    benign_i = idx["BENIGN"]
    y_tr = batch.loc[tr, "Label"].map(idx).to_numpy()
    te_lab = batch.loc[te, "Label"]
    y_bin_te = (te_lab != "BENIGN").astype(int).to_numpy()
    print(f"      split at window {cutoff_w}: {tr.sum():,} train / {te.sum():,} test")

    fwd_cols = [c for c in FORWARD_OBSERVABLE if c in df.columns]

    def run(frame, cols, name):
        X = to_matrix(frame, cols)
        m = XGBClassifier(n_estimators=250, max_depth=7, learning_rate=0.15,
                          subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                          objective="multi:softprob", num_class=len(train_labels),
                          n_jobs=4, eval_metric="mlogloss", random_state=SEED)
        m.fit(X[tr], y_tr)
        pred = m.predict(X[te])
        binf = f1_score(y_bin_te, (pred != benign_i).astype(int),
                        average="macro", zero_division=0)
        print(f"      {name:<34s} binary-F1 {binf:.4f}")
        return binf

    hw_batch = run(batch, list(HOST_WINDOW_FEATURES), "G  host-window only  (batch)")
    hw_strm = run(stream, list(HOST_WINDOW_FEATURES), "G' host-window only  (streaming)")
    e_batch = run(batch, fwd_cols + HOST_WINDOW_FEATURES, "E  forward + host-window (batch)")
    e_strm = run(stream, fwd_cols + HOST_WINDOW_FEATURES, "E' forward + host-window (streaming)")

    # ------------------------------------------------------------------ verdict
    print("\n" + "=" * 78)
    print("PRE-REGISTERED PREDICTIONS")
    print("=" * 78)
    others = ag[ag.feature != "hw_src_bytes_vs_baseline"]
    u1 = bool((others.pearson_r > 0.99).all())
    u2 = abs(e_strm - e_batch) < 0.01 and abs(hw_strm - hw_batch) < 0.01
    u3 = stats["throughput_flows_per_s"] > 50_000
    u4 = stats["evicted_hosts"] == 0
    worst = others.iloc[0]
    for k, ok, d in [
        ("U1", u1, f"all features except the baseline correlate > 0.99 "
                   f"(worst: {worst.feature} r={worst.pearson_r:.4f})"),
        ("U2", u2, f"downstream F1 within 0.01 "
                   f"(E {e_strm - e_batch:+.4f}, G {hw_strm - hw_batch:+.4f})"),
        ("U3", u3, f"throughput > 50k flows/s "
                   f"({stats['throughput_flows_per_s']:,.0f})"),
        ("U4", u4, f"no host evictions at max_hosts={MAX_HOSTS:,} "
                   f"({stats['evicted_hosts']:,})")]:
        print(f"  {k}  {'HOLDS ' if ok else 'FAILS '}  {d}")

    print("\n" + "=" * 78)
    print("HEADLINE")
    print("=" * 78)
    print(f"  batch (groupby, cannot deploy)  {batch_s:>8.1f}s   "
          f"{len(df)/batch_s:>10,.0f} flows/s")
    print(f"  streaming (single pass)         {stream_s:>8.1f}s   "
          f"{stats['throughput_flows_per_s']:>10,.0f} flows/s")
    print(f"  peak traced memory              {stats['peak_traced_mb']:>8.2f} MB "
          f"for {len(df):,} flows / {stats['baseline_entries']:,} hosts")
    print(f"  detector F1, batch features     {e_batch:.4f}")
    print(f"  detector F1, streaming features {e_strm:.4f}   ({e_strm - e_batch:+.4f})")

    (RESULTS / "exp05_verdicts.json").write_text(json.dumps({
        "stats": stats,
        "batch_wall_s": batch_s,
        "binary_f1": {"G_batch": hw_batch, "G_streaming": hw_strm,
                      "E_batch": e_batch, "E_streaming": e_strm},
        "verdicts": {"U1": bool(u1), "U2": bool(u2), "U3": bool(u3), "U4": bool(u4)},
        "feature_agreement": agree,
        "known_definitional_difference": "hw_src_bytes_vs_baseline",
    }, indent=2, default=float))
    print("\n  wrote results/exp05_verdicts.json and exp05_feature_agreement.csv")
    print(f"  total runtime {time.time()-t_all:.1f}s")


if __name__ == "__main__":
    main()

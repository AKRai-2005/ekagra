"""Experiment 07 — does sharding by host actually reach line rate?

The claim under test
--------------------
Experiment 06 measured 47,968 packets/s single-threaded and the write-up said
the pipeline "shards cleanly by hash(host) with no cross-talk, so four workers
clear 1 Gbps". That was an assertion, not a measurement. This measures it.

Building it also corrected the claim. `hash(host)` is **not** a partition of the
work, because a flow touches two hosts and updates state for both. What is true
is a two-stage decomposition, each stage partitioning cleanly on its own key:

    packets --hash(src)--> assemble + source-role features --> flows
    flows   --hash(dst)--> destination-role features

`hash(src)` refines `hash(5-tuple)` on a one-way tap, so stages 1-2 fuse with no
shuffle. Only the destination stage needs a repartition. Flows are therefore
consumed twice, and the cost model is not free linear speedup.

Line rate, defined
------------------
"1 Gbps" is meaningless without a packet size. At the 700-byte average this
generator produces, 1 Gbps is about **178,000 packets/s**. That is the number to
beat, and it is stated rather than left vague so the result cannot be quietly
graded against an easier target.

Pre-registered predictions (written before the first run)
---------------------------------------------------------
  W1  Sharded and single-process output agree exactly on every shared
      (window, host) cell. Any value mismatch means the partitioning is wrong.
  W2  Key-set agreement > 99.9%. Exact agreement is not expected: each shard
      runs its own watermark, so which marginal records fall outside the
      lateness budget depends on shard traffic.
  W3  4 shards exceed 100,000 packets/s.
  W4  8 shards exceed 178,000 packets/s, i.e. 1 Gbps at 700-byte packets.
  W5  Scaling efficiency at 4 shards > 0.6.

Run:  python experiments/exp07_sharded_throughput.py
"""

from __future__ import annotations

import json
import math
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.ingest.synthetic import GeneratorConfig, SyntheticSource  # noqa: E402
from ekagra.ingest.visibility import DIODE_ONEWAY, VisibilityFilter  # noqa: E402
from ekagra.pipeline.sharded import run_sharded, run_single  # noqa: E402

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

SHARD_GRID = [1, 2, 4, 6, 8, 12]
AVG_PACKET_BYTES = 700.0
LINE_RATE_PPS = 1e9 / 8.0 / AVG_PACKET_BYTES   # ~178,571 pkt/s for 1 Gbps


def compare(a_rows, b_rows):
    a = {(r["window"], r["host"]): r for r in a_rows}
    b = {(r["window"], r["host"]): r for r in b_rows}
    shared = set(a) & set(b)
    union = set(a) | set(b)
    mismatch = 0
    worst = 0.0
    worst_f = ""
    for k in shared:
        for f, va in a[k].items():
            if f in ("window", "host"):
                continue
            vb = b[k].get(f, 0.0)
            if not math.isclose(va, vb, rel_tol=1e-9, abs_tol=1e-12):
                mismatch += 1
                if abs(va - vb) > worst:
                    worst, worst_f = abs(va - vb), f
    return {
        "n_single": len(a), "n_sharded": len(b),
        "shared": len(shared), "key_agreement": len(shared) / max(1, len(union)),
        "value_mismatches": mismatch, "worst_abs_diff": worst,
        "worst_feature": worst_f,
    }


def main() -> None:
    t_all = time.time()
    print("=" * 78)
    print("EKAGRA  ·  Experiment 07  ·  Sharded throughput")
    print("=" * 78)

    print("\n[1/4] Generating workload ...")
    packets = SyntheticSource(GeneratorConfig(seed=31, duration_s=3600.0)).generate()
    observed = list(VisibilityFilter(DIODE_ONEWAY).apply(packets))
    print(f"      {len(observed):,} packets observed on the one-way tap")
    print(f"      line rate target: {LINE_RATE_PPS:,.0f} pkt/s "
          f"(1 Gbps at {AVG_PACKET_BYTES:.0f}-byte packets)")

    print("\n[2/4] Single-process reference ...")
    t = time.perf_counter()
    single_rows, _ = run_single(observed)
    single_s = time.perf_counter() - t
    single_pps = len(observed) / single_s
    print(f"      {single_s:.1f}s   {single_pps:,.0f} packets/s   "
          f"{len(single_rows):,} cells")

    print("\n[3/4] Sharded, warm pool ...")
    print(f"      {'shards':>7s} {'wall':>8s} {'pkt/s':>12s} {'speedup':>9s} "
          f"{'eff':>6s} {'cells':>10s} {'line rate':>11s}")
    rows = []
    detail = {}
    for n in SHARD_GRID:
        if n == 1:
            wall, pps, out = single_s, single_pps, single_rows
        else:
            # Warm pool: worker startup (spawn on Windows) is a one-off cost a
            # real deployment pays once, not per batch. Measuring it inside the
            # timed region would understate steady-state throughput.
            with ProcessPoolExecutor(max_workers=n) as pool:
                run_sharded(observed[:2000], n_shards=n, executor=pool)  # warm up
                t = time.perf_counter()
                out, st = run_sharded(observed, n_shards=n, executor=pool)
                wall = time.perf_counter() - t
            pps = len(observed) / wall
        speedup = single_s / wall
        eff = speedup / n
        ok = "YES" if pps >= LINE_RATE_PPS else "no"
        print(f"      {n:>7d} {wall:>7.1f}s {pps:>12,.0f} {speedup:>8.2f}x "
              f"{eff:>6.2f} {len(out):>10,} {ok:>11s}")
        rows.append({"shards": n, "wall_s": wall, "packets_per_s": pps,
                     "speedup": speedup, "efficiency": eff, "cells": len(out),
                     "meets_line_rate": pps >= LINE_RATE_PPS})
        if n in (2, 4, 8):
            detail[n] = compare(single_rows, out)

    df = pd.DataFrame(rows)
    df.to_csv(RESULTS / "exp07_sharded_throughput.csv", index=False)

    print("\n[4/4] Correctness vs single-process ...")
    for n, c in detail.items():
        print(f"      shards={n}: value mismatches {c['value_mismatches']}, "
              f"key agreement {100*c['key_agreement']:.4f}% "
              f"({c['n_single']:,} vs {c['n_sharded']:,} cells)")

    best = df.loc[df.packets_per_s.idxmax()]
    any_mismatch = any(c["value_mismatches"] for c in detail.values())
    min_key_agree = min(c["key_agreement"] for c in detail.values())
    pps4 = float(df[df.shards == 4].packets_per_s.iloc[0])
    pps8 = float(df[df.shards == 8].packets_per_s.iloc[0])
    eff4 = float(df[df.shards == 4].efficiency.iloc[0])

    print("\n" + "=" * 78)
    print("PRE-REGISTERED PREDICTIONS")
    print("=" * 78)
    w1 = not any_mismatch
    w2 = min_key_agree > 0.999
    w3 = pps4 > 100_000
    w4 = pps8 > LINE_RATE_PPS
    w5 = eff4 > 0.6
    for k, ok, d in [
        ("W1", w1, "sharded values identical to single-process on shared cells"),
        ("W2", w2, f"key agreement > 99.9% (min {100*min_key_agree:.4f}%)"),
        ("W3", w3, f"4 shards > 100k pkt/s ({pps4:,.0f})"),
        ("W4", w4, f"8 shards > {LINE_RATE_PPS:,.0f} pkt/s = 1 Gbps ({pps8:,.0f})"),
        ("W5", w5, f"efficiency at 4 shards > 0.6 ({eff4:.2f})")]:
        print(f"  {k}  {'HOLDS ' if ok else 'FAILS '}  {d}")

    print("\n" + "=" * 78)
    print("HEADLINE")
    print("=" * 78)
    print(f"  single process        {single_pps:>12,.0f} pkt/s  "
          f"({single_pps*AVG_PACKET_BYTES*8/1e6:>6.0f} Mbps)")
    print(f"  best sharded ({int(best.shards):>2d})     {best.packets_per_s:>12,.0f} pkt/s  "
          f"({best.packets_per_s*AVG_PACKET_BYTES*8/1e6:>6.0f} Mbps)  "
          f"{best.speedup:.2f}x")
    print(f"  1 Gbps needs          {LINE_RATE_PPS:>12,.0f} pkt/s")
    print(f"  -> line rate {'REACHED' if best.packets_per_s >= LINE_RATE_PPS else 'NOT reached'}")

    (RESULTS / "exp07_verdicts.json").write_text(json.dumps({
        "packets": len(observed),
        "avg_packet_bytes": AVG_PACKET_BYTES,
        "line_rate_pps_1gbps": LINE_RATE_PPS,
        "single_pps": single_pps,
        "scaling": rows,
        "correctness": {str(k): v for k, v in detail.items()},
        "verdicts": {"W1": bool(w1), "W2": bool(w2), "W3": bool(w3),
                     "W4": bool(w4), "W5": bool(w5)},
    }, indent=2, default=float))
    print("\n  wrote results/exp07_sharded_throughput.csv and exp07_verdicts.json")
    print(f"  total runtime {time.time()-t_all:.1f}s")


if __name__ == "__main__":
    main()

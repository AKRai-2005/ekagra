"""Host-window aggregate features — what a purpose-built one-way sensor computes.

Why this exists
---------------
Experiment 03 found that on real traffic, retraining under a one-way visibility
profile recovers only about a third of the loss. But that condition was
handicapped: it used the 35 forward-observable features **CICFlowMeter happens
to emit**, and CICFlowMeter was never designed for a one-way tap.

A sensor built for that position would not stop at per-flow statistics. It would
maintain per-host state across a time window and compute the things that
actually survive losing the reverse channel:

    fan-out cardinality        replaces RST-rate for scan detection
    source-IP entropy          replaces half-open detection for floods
    peer concentration         replaces round-trip regularity for beaconing
    flow-arrival periodicity   same
    volume vs host baseline    replaces the out:in byte ratio for exfiltration

Those are exactly the features the synthetic pipeline had and CICFlowMeter does
not. This module computes them from the flow records, so condition C can be
re-run with a fair feature set and the true recoverability can be located rather
than guessed at.

What this still cannot answer
-----------------------------
Three of the synthetic pipeline's forward-side features need packet-level data
that the flow CSV does not carry:

    TTL diversity              spoofed-source indicator
    DNS query-name entropy     DGA / tunnelling
    TLS client fingerprint     malware in encrypted sessions

So this raises the **lower bound** on recoverability. It does not settle it.
Saying so is the point; the alternative is a 50 GB PCAP download whose only
freely-available processed form is dominated by payload bytes we are forbidden
to use under the PS's no-decryption constraint.

Causality
---------
Window aggregates are computed over flows **within the same window**, which
means the sensor emits at window close and carries `window_s` seconds of
latency. That is how a real windowed sensor behaves and it is stated rather than
hidden. The per-host baseline is strictly causal - it only ever sees earlier
windows. Nothing here touches the label.
"""

from __future__ import annotations

from typing import List

import numpy as np
import pandas as pd

WINDOW_S = 60.0
BASELINE_HALF_LIFE_WINDOWS = 5.0

# Emitted feature names, prefixed so an experiment can select them cleanly.
HOST_WINDOW_FEATURES: List[str] = [
    # source-side: what this host is doing
    "hw_src_n_flows", "hw_src_n_peers", "hw_src_n_dports",
    "hw_src_fanout_per_flow", "hw_src_peer_concentration",
    "hw_src_fwd_pkts", "hw_src_fwd_bytes",
    "hw_src_iat_cv", "hw_src_iat_mean",
    "hw_src_bytes_vs_baseline",
    # destination-side: what is being done to this host
    "hw_dst_n_flows", "hw_dst_n_srcs", "hw_dst_src_entropy",
    "hw_dst_fwd_pkts", "hw_dst_fwd_bytes",
    "hw_dst_flows_per_src",
]


def _entropy_from_counts(counts: np.ndarray) -> float:
    total = counts.sum()
    if total <= 0:
        return 0.0
    p = counts / total
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum())


def _cv(x: pd.Series) -> float:
    """Coefficient of variation of flow inter-arrival times. Low = periodic."""
    if len(x) < 3:
        return 0.0
    d = np.diff(np.sort(x.to_numpy(dtype=np.float64)))
    m = d.mean()
    return float(d.std() / m) if m > 1e-9 else 0.0


def add_host_window_features(
    df: pd.DataFrame,
    window_s: float = WINDOW_S,
    ts_col: str = "Timestamp",
    src_col: str = "Src IP",
    dst_col: str = "Dst IP",
    dport_col: str = "Dst Port",
    pkts_col: str = "Total Fwd Packet",
    bytes_col: str = "Total Length of Fwd Packet",
) -> pd.DataFrame:
    """Attach host-window aggregates to each flow.

    Returns a copy of `df` with the `hw_*` columns added and a `window` column.
    Only forward-direction quantities are used, so every feature here is
    computable by a one-way sensor.
    """
    out = df.copy()
    t0 = out[ts_col].min()
    epoch = (out[ts_col] - t0).dt.total_seconds()
    out["window"] = (epoch // window_s).astype(np.int64)
    out["_t"] = epoch

    pk = pd.to_numeric(out[pkts_col], errors="coerce").fillna(0.0)
    by = pd.to_numeric(out[bytes_col], errors="coerce").fillna(0.0)
    out["_pk"], out["_by"] = pk, by

    # ---------------------------------------------------------------- source
    g = out.groupby(["window", src_col], sort=False)
    src = g.agg(
        hw_src_n_flows=("_t", "size"),
        hw_src_n_peers=(dst_col, "nunique"),
        hw_src_n_dports=(dport_col, "nunique"),
        hw_src_fwd_pkts=("_pk", "sum"),
        hw_src_fwd_bytes=("_by", "sum"),
        hw_src_iat_cv=("_t", _cv),
        hw_src_iat_mean=("_t", lambda x: float(np.diff(np.sort(x)).mean())
                         if len(x) > 1 else 0.0),
    ).reset_index()
    src["hw_src_fanout_per_flow"] = src.hw_src_n_peers / src.hw_src_n_flows.clip(lower=1)

    # peer concentration: share of this host's flows going to its top peer
    pc = (out.groupby(["window", src_col, dst_col], sort=False).size()
          .rename("n").reset_index())
    top = pc.groupby(["window", src_col], sort=False)["n"].max().rename("_top").reset_index()
    tot = pc.groupby(["window", src_col], sort=False)["n"].sum().rename("_tot").reset_index()
    conc = top.merge(tot, on=["window", src_col])
    conc["hw_src_peer_concentration"] = conc._top / conc._tot.clip(lower=1)
    src = src.merge(conc[["window", src_col, "hw_src_peer_concentration"]],
                    on=["window", src_col], how="left")

    # ----------------------------------------------------- causal host baseline
    # Exponentially decayed mean of this host's outbound bytes over EARLIER
    # windows only. Shifted by one window so the current value never sees itself.
    src = src.sort_values(["window"]).reset_index(drop=True)
    alpha = 1.0 - 0.5 ** (1.0 / BASELINE_HALF_LIFE_WINDOWS)
    base = (src.groupby(src_col, sort=False)["hw_src_fwd_bytes"]
            .transform(lambda s: s.shift(1).ewm(alpha=alpha, adjust=False).mean()))
    src["hw_src_bytes_vs_baseline"] = src.hw_src_fwd_bytes / (base.fillna(0.0) + 1.0)

    # ----------------------------------------------------------- destination
    gd = out.groupby(["window", dst_col], sort=False)
    dst = gd.agg(
        hw_dst_n_flows=("_t", "size"),
        hw_dst_n_srcs=(src_col, "nunique"),
        hw_dst_fwd_pkts=("_pk", "sum"),
        hw_dst_fwd_bytes=("_by", "sum"),
    ).reset_index()
    dst["hw_dst_flows_per_src"] = dst.hw_dst_n_flows / dst.hw_dst_n_srcs.clip(lower=1)

    # Source-IP entropy at the destination: high under a spoofed-source flood,
    # low when one chatty host dominates. This is the feature that replaces
    # half-open detection once the reverse channel is gone.
    sc = (out.groupby(["window", dst_col, src_col], sort=False).size()
          .rename("n").reset_index())
    ent = (sc.groupby(["window", dst_col], sort=False)["n"]
           .apply(lambda s: _entropy_from_counts(s.to_numpy()))
           .rename("hw_dst_src_entropy").reset_index())
    dst = dst.merge(ent, on=["window", dst_col], how="left")

    # ------------------------------------------------------------------ join
    out = out.merge(src, on=["window", src_col], how="left")
    out = out.merge(dst, on=["window", dst_col], how="left")

    for c in HOST_WINDOW_FEATURES:
        if c not in out.columns:
            out[c] = 0.0
    out[HOST_WINDOW_FEATURES] = (out[HOST_WINDOW_FEATURES]
                                 .replace([np.inf, -np.inf], np.nan).fillna(0.0))
    return out.drop(columns=["_t", "_pk", "_by"])

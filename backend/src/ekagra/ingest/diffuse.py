"""Make a real corpus's attacks low-rate and temporally diffuse.

Why this exists
---------------
Experiment 04 found that on CIC-IDS2017 a sensor keeping windowed host state
loses essentially nothing when the reverse traffic direction is taken away, and
that 16 host-window aggregates alone beat all 103 full-visibility features. That
is the project's headline claim, and it has an obvious way of being wrong:
CIC-IDS2017's attacks are **bursty**. A DDoS or a port scan puts hundreds of
flows into a single 60-second window on a single host, so a per-cell aggregate
sees an overwhelming signal. Nothing in that result tells us what happens when
an attack is deliberately slow.

That matters because the deployment this project targets - a critical-infra
enclave watched through a one-way tap - is exactly where low-and-slow behaviour
is expected: scans paced to stay under threshold alarms, beacons at minutes to
hours, exfiltration in small chunks. If host-window aggregates only work on
bursts, the architecture claim needs narrowing.

The manipulation
----------------
Rather than generate traffic, this rearranges the real corpus. Two knobs, and
nothing else is touched:

  1. **Temporal diffusion.** Attack flows are re-timed so that a campaign puts
     `flows_per_cell` flows into a (host, window) cell instead of its original
     burst. Spreading the same flows over more windows is precisely what a slow
     scanner does.

  2. **Host blending.** Each attack campaign is re-homed onto a source IP that
     also carries benign traffic, modelling a compromised internal host rather
     than CIC-IDS2017's dedicated external attacker addresses. Without this the
     attacker's cells contain nothing but attack flows, so the aggregate stays
     trivially separable no matter how slow the attack is, and the density knob
     measures nothing.

Per-flow features are **not modified**. Packet sizes, inter-arrival statistics
and flag counts stay exactly as measured. Only a flow's timestamp and its source
address change.

What this can and cannot support
--------------------------------
It can settle a structural question: host-window features are computed per
(host, window) cell, so every flow in a cell receives the *same* aggregate
vector. When attack flows are a minority inside their own cell, those features
cannot separate them from their benign neighbours - no matter how good the
model. This transform makes that regime reachable and measurable.

It cannot tell us the crossover density in a real network, and it flatters the
per-flow conditions: a genuine low-and-slow adversary would likely also make
individual flows less distinctive, whereas here each attack flow keeps the
full discriminative power it had inside its original burst. Read the per-flow
numbers as an optimistic bound, and read comparisons **across densities within
this experiment**, never against experiment 04's absolute figures - the
manipulation also destroys the campaign ordering that produced exp04's
test-only classes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Tuple

import numpy as np
import pandas as pd

BENIGN_LABEL = "BENIGN"


@dataclass
class DiffusionConfig:
    """One point on the density sweep."""

    flows_per_cell: float
    """Target attack flows per (source host, window) cell. CIC-IDS2017's own
    bursts run to hundreds; 1.0 means every attack flow sits alone in its cell,
    surrounded by whatever benign traffic that host was already producing."""

    window_s: float = 60.0
    blend_hosts: bool = True
    """Re-home campaigns onto hosts that also carry benign traffic. Off, the
    density knob measures nothing - see the module docstring."""

    min_host_windows: int = 20
    """A blend target must appear in at least this many distinct windows, so an
    attack spread across the capture lands on a host that was actually active."""

    hide_in_traffic: bool = True
    """Place attack flows in windows where the host was already busy, weighting
    by its benign flow count, instead of picking windows uniformly.

    This turned out to matter more than the density knob. Benign traffic is
    concentrated in business hours, so a uniformly-placed attack flow usually
    lands in a window where the host did nothing else - it ends up *alone* in
    its cell rather than hidden in it, and the host-window aggregate still
    reports "this machine did something unusual", which is a real detection.
    Weighting by activity models the adversary who deliberately runs inside the
    victim's own noise, and is the only way to reach a genuinely diluted cell.

    Off, the sweep measures diffusion alone; on, it measures diffusion plus
    evasion. Both are worth knowing and the two are reported separately."""

    seed: int = 0


def _window_index(ts: pd.Series, window_s: float) -> np.ndarray:
    t0 = ts.min()
    return np.floor((ts - t0).dt.total_seconds() / window_s).to_numpy(dtype=np.int64)


def _blend_pool(df: pd.DataFrame, cfg: DiffusionConfig, win: np.ndarray) -> np.ndarray:
    """Benign source hosts active across enough of the capture to host a slow
    campaign. Picking a host that only ever appears in three windows would make
    the diffusion impossible to realise."""
    benign = df["Label"] == BENIGN_LABEL
    sub = pd.DataFrame({"src": df.loc[benign, "Src IP"].to_numpy(),
                        "w": win[benign.to_numpy()]})
    spread = sub.groupby("src")["w"].nunique()
    pool = spread[spread >= cfg.min_host_windows].index.to_numpy()
    if len(pool) == 0:                       # pragma: no cover - tiny inputs only
        pool = spread.sort_values().tail(8).index.to_numpy()
    return pool


def _activity(df: pd.DataFrame, win: np.ndarray, n_windows: int) -> Dict[str, np.ndarray]:
    """Benign flows per window, per host - the noise an attack can hide in."""
    benign = (df["Label"] == BENIGN_LABEL).to_numpy()
    sub = pd.DataFrame({"src": df.loc[benign, "Src IP"].to_numpy(),
                        "w": win[benign]})
    out: Dict[str, np.ndarray] = {}
    for src, grp in sub.groupby("src")["w"]:
        counts = np.zeros(n_windows, dtype=np.float64)
        idx, n = np.unique(grp.to_numpy(), return_counts=True)
        counts[idx] = n
        out[src] = counts
    return out


def _pick_windows(weights: np.ndarray, k: int, rng: np.random.Generator) -> np.ndarray:
    """Sample k distinct windows with probability proportional to `weights`.

    Gumbel top-k: adding Gumbel noise to log-weights and taking the k largest is
    equivalent to weighted sampling without replacement, and is O(n) rather than
    numpy's much slower exact routine - which matters because this runs per
    campaign per host with n in the thousands.
    """
    n = len(weights)
    if k >= n:
        return np.arange(n)
    # Every window stays reachable; a host with no benign traffic anywhere would
    # otherwise have an all-zero weight vector and no valid sample.
    w = weights + 1e-6
    keys = np.log(w) + rng.gumbel(size=n)
    return np.argpartition(-keys, k)[:k]


def diffuse_attacks(df: pd.DataFrame, cfg: DiffusionConfig
                    ) -> Tuple[pd.DataFrame, Dict]:
    """Return a copy of `df` with attacks re-timed and re-homed, plus statistics.

    Benign rows keep their real timestamps and addresses; the background remains
    the capture's own. Only attack rows move.
    """
    rng = np.random.default_rng(cfg.seed)
    out = df.copy()
    ts = out["Timestamp"]
    t0 = ts.min()
    win = _window_index(ts, cfg.window_s)
    n_windows = int(win.max()) + 1

    is_attack = (out["Label"] != BENIGN_LABEL).to_numpy()
    if not is_attack.any():
        raise ValueError("no attack rows to diffuse")

    pool = _blend_pool(out, cfg, win) if cfg.blend_hosts else None
    activity = _activity(out, win, n_windows) if cfg.hide_in_traffic else {}

    # A campaign is one attack class from one original source. Keeping that
    # grouping means a campaign moves as a unit onto one compromised host,
    # rather than scattering one attack across dozens of unrelated machines.
    camp = pd.DataFrame({
        "label": out.loc[is_attack, "Label"].to_numpy(),
        "src": out.loc[is_attack, "Src IP"].to_numpy(),
        "pos": np.flatnonzero(is_attack),
    })

    new_src = out["Src IP"].to_numpy().copy()
    new_ts = np.zeros(len(out), dtype=np.float64)
    new_ts[:] = np.nan

    host_assignments = 0
    starved = []
    for (label, src), grp in camp.groupby(["label", "src"], sort=True):
        pos = grp["pos"].to_numpy()
        n = len(pos)

        # Cells needed to hit the target density.
        k = max(1, math.ceil(n / max(cfg.flows_per_cell, 1e-9)))

        # One host offers only `n_windows` cells, so a large campaign cannot
        # reach a low density on a single machine - CIC-IDS2017's DDoS has more
        # flows than the capture has minutes. Spread it over as many compromised
        # hosts as the target requires. That is also what lateral movement looks
        # like, and the host count is reported so the reader can judge it.
        need = max(1, math.ceil(k / n_windows))
        if cfg.blend_hosts:
            n_hosts = min(need, len(pool))
            hosts = rng.choice(pool, size=n_hosts, replace=False)
        else:
            n_hosts, hosts = 1, np.array([src], dtype=object)
        host_assignments += n_hosts
        if n_hosts < need:
            starved.append({"label": label, "flows": n, "hosts_wanted": need,
                            "hosts_available": n_hosts})

        # Lay out k cell slots across the chosen hosts, then deal flows round
        # robin so occupancy stays within one flow of the target.
        per_host = min(math.ceil(k / n_hosts), n_windows)
        slots_h, slots_w = [], []
        for h in hosts:
            if cfg.hide_in_traffic:
                wins = _pick_windows(activity.get(h, np.zeros(n_windows)),
                                     per_host, rng)
            else:
                wins = rng.choice(n_windows, size=per_host, replace=False)
            slots_h.append(np.full(per_host, h, dtype=object))
            slots_w.append(wins)
        # Truncate to exactly k slots; numpy slicing past the end is a no-op, so
        # a pool too small to supply k simply yields fewer, denser cells - which
        # is the starvation recorded above.
        sh = np.concatenate(slots_h)[:k]
        sw = np.concatenate(slots_w)[:k]

        pick = np.arange(n) % len(sh)
        if cfg.blend_hosts:
            new_src[pos] = sh[pick]
        offset = rng.random(n) * cfg.window_s
        new_ts[pos] = sw[pick] * cfg.window_s + offset

    moved = ~np.isnan(new_ts)
    # The corpus carries datetime64[us]; to_timedelta yields [ns], and pandas 3
    # refuses the narrowing assignment rather than silently truncating.
    shifted = (t0 + pd.to_timedelta(new_ts[moved], unit="s"))
    out.loc[moved, "Timestamp"] = shifted.astype(out["Timestamp"].dtype)
    out["Src IP"] = new_src
    out = out.sort_values("Timestamp").reset_index(drop=True)

    stats = _stats(out, cfg)
    # Summed over campaigns, so this exceeds the pool size when campaigns
    # share hosts. It is an assignment count, not a distinct-host count.
    stats["host_assignments"] = host_assignments
    # A campaign that could not be spread thinly enough, because the blend pool
    # ran out. The requested density was then not reached, and saying so is the
    # difference between a limitation and a silent error.
    stats["starved_campaigns"] = starved
    stats["density_achieved"] = not starved
    return out, stats


def _stats(out: pd.DataFrame, cfg: DiffusionConfig) -> Dict:
    """What the manipulation actually achieved.

    `dilution` is the real explanatory variable: the mean share of a cell's
    flows that are attack flows, among cells containing any. The requested
    density is an input; this is what the corpus ended up with.
    """
    win = _window_index(out["Timestamp"], cfg.window_s)
    atk = (out["Label"] != BENIGN_LABEL).to_numpy()
    cells = pd.DataFrame({"src": out["Src IP"].to_numpy(), "w": win, "atk": atk})
    g = cells.groupby(["src", "w"])["atk"].agg(["sum", "count"])
    hot = g[g["sum"] > 0]
    return {
        "requested_flows_per_cell": cfg.flows_per_cell,
        "blend_hosts": cfg.blend_hosts,
        "attack_flows": int(atk.sum()),
        "attack_cells": int(len(hot)),
        "realised_flows_per_cell": float(hot["sum"].mean()) if len(hot) else 0.0,
        "median_flows_per_cell": float(hot["sum"].median()) if len(hot) else 0.0,
        "dilution": float((hot["sum"] / hot["count"]).mean()) if len(hot) else 0.0,
        "benign_per_attack_cell":
            float((hot["count"] - hot["sum"]).mean()) if len(hot) else 0.0,
        "hide_in_traffic": cfg.hide_in_traffic,
        "cells_total": int(len(g)),
        "windows": int(win.max()) + 1,
    }

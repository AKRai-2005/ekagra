"""Streaming host-window features — the version that could actually be deployed.

Why this exists
---------------
`host_window.py` computes the same 16 features with pandas `groupby`. That is a
batch computation over the whole capture, and the problem statement is explicit:

    "The pipeline must process traffic incrementally and raise alerts with
     bounded latency, not just produce an end-of-run report."

A groupby cannot run on a live link. This module does the same job in a single
pass with **bounded memory**, which is the difference between an experiment and
a sensor.

Design: exact while cheap, sketched when not
--------------------------------------------
The naive streaming design gives every host a HyperLogLog and a Count-Min
Sketch and eats kilobytes per host. But the distribution is extremely skewed:
in real traffic the overwhelming majority of hosts talk to a handful of peers
in any 60-second window, and for those an exact set is both smaller *and*
exactly accurate.

So every estimator here starts exact and **promotes to a sketch only when it
outgrows a threshold**:

    CardinalitySummary   exact set   -> HyperLogLog(p=10)   above 256 distinct
    FrequencySummary     exact dict  -> CMS + Misra-Gries   above 256 distinct

This is the standard sparse-representation trick (the same idea behind HLL++'s
sparse mode). It means the approximation error is *zero* for the hosts where
precision matters most and bounded for the heavy hitters where it does not —
a scanner touching 5,000 ports does not need its fan-out known to ±1.

Bounded memory, stated explicitly
---------------------------------
`max_hosts` caps how many hosts are tracked concurrently, with LRU eviction.
Eviction loses that host's in-window state; the count is reported rather than
hidden, because silently dropping hosts is exactly how a sensor lies about
coverage.

Latency and out-of-order input
------------------------------
Features are emitted at window close, so the sensor carries at least `window_s`
seconds of latency. That is inherent to windowed aggregation.

Behind a flow assembler there is a second term. A flow is *emitted* when it
expires, not when it starts, so records arrive out of order with respect to
their own start times. `allowed_lateness_s` keeps several windows open so those
records still land in the right window; total latency is therefore
`window_s + allowed_lateness_s`, and records older than that are dropped and
counted in `dropped_late`.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np

from .host_window import WINDOW_S
from .protocol import ProtocolCell, ProtocolProfiler
from .sketches import CountMinSketch, DecayedCounter, HyperLogLog

# Promotion thresholds. Below these an exact structure is smaller and exact.
SPARSE_CARDINALITY_MAX = 256
SPARSE_FREQUENCY_MAX = 256
MG_SLOTS = 16  # Misra-Gries slots retained for heavy-hitter (peer concentration)


class CardinalitySummary:
    """Distinct-count estimator: exact set, promoted to HLL when it grows."""

    __slots__ = ("_exact", "_hll")

    def __init__(self) -> None:
        self._exact: Optional[set] = set()
        self._hll: Optional[HyperLogLog] = None

    def add(self, item) -> None:
        if self._exact is not None:
            self._exact.add(item)
            if len(self._exact) > SPARSE_CARDINALITY_MAX:
                self._hll = HyperLogLog(10)
                for it in self._exact:
                    self._hll.add(it)
                self._exact = None
            return
        self._hll.add(item)

    def count(self) -> float:
        if self._exact is not None:
            return float(len(self._exact))
        return self._hll.count()

    @property
    def is_exact(self) -> bool:
        return self._exact is not None


class FrequencySummary:
    """Count distribution: exact dict, promoted to CMS + Misra-Gries.

    Supports the two things the features need - Shannon entropy of the count
    distribution, and the largest single count - in both modes.
    """

    __slots__ = ("_exact", "_cms", "_mg", "_total")

    def __init__(self) -> None:
        self._exact: Optional[Dict[object, int]] = {}
        self._cms: Optional[CountMinSketch] = None
        self._mg: Dict[object, int] = {}
        self._total = 0

    def add(self, item, count: int = 1) -> None:
        self._total += count
        if self._exact is not None:
            self._exact[item] = self._exact.get(item, 0) + count
            if len(self._exact) > SPARSE_FREQUENCY_MAX:
                self._cms = CountMinSketch(512, 3)
                for k, v in self._exact.items():
                    self._cms.add(k, v)
                    self._mg_offer(k, v)
                self._exact = None
            return
        self._cms.add(item, count)
        self._mg_offer(item, count)

    def _mg_offer(self, item, count: int) -> None:
        """Misra-Gries: keep MG_SLOTS candidate heavy hitters."""
        if item in self._mg:
            self._mg[item] += count
        elif len(self._mg) < MG_SLOTS:
            self._mg[item] = count
        else:
            # decrement all; drop any that hit zero
            for k in list(self._mg):
                self._mg[k] -= count
                if self._mg[k] <= 0:
                    del self._mg[k]

    @property
    def total(self) -> int:
        return self._total

    def entropy(self) -> float:
        if self._exact is not None:
            if not self._exact:
                return 0.0
            c = np.fromiter(self._exact.values(), dtype=np.float64,
                            count=len(self._exact))
            p = c / c.sum()
            return float(-(p * np.log2(p)).sum())
        return self._cms.entropy()

    def max_count(self) -> int:
        if self._exact is not None:
            return max(self._exact.values(), default=0)
        if not self._mg:
            return 0
        # MG gives the candidates; CMS gives a tight (never-under) estimate.
        return max(self._cms.estimate(k) for k in self._mg)

    def n_distinct(self) -> float:
        if self._exact is not None:
            return float(len(self._exact))
        # After promotion the distinct count is tracked separately by the
        # caller's CardinalitySummary; this is only a floor.
        return float(SPARSE_FREQUENCY_MAX)


class _Welford:
    """Streaming mean/variance of inter-arrival times.

    Flows arrive in timestamp order, so successive differences are the
    inter-arrival series directly - no sort needed, which is precisely why the
    batch version's `sort_values` is unnecessary work on a live stream.
    """

    __slots__ = ("_last_t", "_n", "_mean", "_m2")

    def __init__(self) -> None:
        self._last_t: Optional[float] = None
        self._n = 0
        self._mean = 0.0
        self._m2 = 0.0

    def observe(self, t: float) -> None:
        if self._last_t is not None:
            d = t - self._last_t
            self._n += 1
            delta = d - self._mean
            self._mean += delta / self._n
            self._m2 += delta * (d - self._mean)
        self._last_t = t

    @property
    def mean(self) -> float:
        return self._mean if self._n else 0.0

    @property
    def cv(self) -> float:
        if self._n < 2 or self._mean <= 1e-9:
            return 0.0
        # population std, to match the batch implementation's np.std default
        var = self._m2 / self._n
        return float(math.sqrt(max(0.0, var)) / self._mean)


@dataclass
class _HostWindow:
    """Per-host state inside one window. Both roles tracked."""

    # source role
    src_flows: int = 0
    src_pkts: float = 0.0
    src_bytes: float = 0.0
    src_peers: CardinalitySummary = field(default_factory=CardinalitySummary)
    src_dports: CardinalitySummary = field(default_factory=CardinalitySummary)
    src_peer_freq: FrequencySummary = field(default_factory=FrequencySummary)
    src_iat: _Welford = field(default_factory=_Welford)
    # DNS/TLS evidence for this host in this window. Empty unless the source is
    # packets - flow-record corpora carry none.
    proto: ProtocolCell = field(default_factory=ProtocolCell)

    # destination role
    dst_flows: int = 0
    dst_pkts: float = 0.0
    dst_bytes: float = 0.0
    dst_srcs: CardinalitySummary = field(default_factory=CardinalitySummary)
    dst_src_freq: FrequencySummary = field(default_factory=FrequencySummary)


@dataclass
class FlowRecord:
    """The minimum a one-way sensor needs per flow. All forward-side."""

    ts: float
    src: str
    dst: str
    dport: int
    fwd_pkts: float
    fwd_bytes: float

    # Protocol evidence, carried only when the source is packets. Flow-record
    # corpora leave these empty, and the protocol features are then zero -
    # stated rather than silently absent. See features/protocol.py.
    qnames: Tuple[str, ...] = ()
    tls_fps: Tuple[str, ...] = ()


class StreamingHostWindow:
    """Single-pass, bounded-memory host-window feature extractor.

    Usage:
        ex = StreamingHostWindow()
        for rec in flows_in_timestamp_order:
            for row in ex.push(rec):
                ...            # emitted at window close
        for row in ex.flush():
            ...
    """

    def __init__(self, window_s: float = WINDOW_S, max_hosts: int = 50_000,
                 baseline_half_life_windows: float = 5.0,
                 t0: Optional[float] = None,
                 allowed_lateness_s: float = 0.0,
                 roles: str = "both",
                 protocol: bool = True) -> None:
        """
        `allowed_lateness_s` becomes load-bearing once this runs behind a flow
        assembler.

        A flow starting at t=10s and expiring at t=70s is *emitted* at t=70s
        but belongs to the window containing t=10s. So records arrive out of
        order with respect to their own start times. The original version of
        this class assumed ordered input and, on seeing an out-of-order record,
        would close the current window and move the window pointer *backwards*
        - silently corrupting every aggregate after it.

        With a lateness budget, several windows stay open at once and a window
        closes only when the stream has advanced past its end plus the budget.
        Records older than that are dropped and counted in `dropped_late`,
        because a sensor that discards data without saying so is misreporting
        its own coverage.

        Set it to at least the assembler idle timeout; the active timeout is
        the safe upper bound. exp06 measures the loss at each value.
        """
        if roles not in ("both", "src", "dst"):
            raise ValueError("roles must be 'both', 'src' or 'dst'")
        self.window_s = window_s
        self.max_hosts = max_hosts
        self.t0 = t0
        self.allowed_lateness_s = allowed_lateness_s
        # Which half of the feature set this instance computes.
        #
        # This exists so the pipeline can be sharded. A flow touches two hosts,
        # so a single instance computing both roles cannot be partitioned by
        # host - the two updates belong on different shards. Splitting the
        # roles lets each stage partition cleanly on the host it owns.
        self.roles = roles
        # window index -> host -> state. Oldest window closes first.
        self._open: "OrderedDict[int, OrderedDict[str, _HostWindow]]" = OrderedDict()
        self._max_ts: float = float("-inf")
        # Cross-window, strictly causal: only ever updated at window close.
        self._baseline: Dict[str, DecayedCounter] = {}
        self._alpha_half_life = baseline_half_life_windows
        self.evicted_hosts = 0
        self.dropped_late = 0
        # Protocol features are emitted only when asked for. On a flow-record
        # corpus there is nothing to compute them from, and nine constant-zero
        # columns are worse than none.
        self.protocol = protocol
        self._proto = ProtocolProfiler() if protocol else None
        self.n_windows = 0
        self.n_flows = 0

    # ------------------------------------------------------------------ state
    def _host(self, table, name: str) -> _HostWindow:
        st = table.get(name)
        if st is None:
            if len(table) >= self.max_hosts:
                table.popitem(last=False)   # LRU eviction, per open window
                self.evicted_hosts += 1
            st = _HostWindow()
            table[name] = st
        else:
            table.move_to_end(name)
        return st

    # ------------------------------------------------------------------ ingest
    def push(self, rec: FlowRecord) -> List[dict]:
        if self.t0 is None:
            self.t0 = rec.ts
        rel = rec.ts - self.t0
        w = int(rel // self.window_s)

        if rec.ts > self._max_ts:
            self._max_ts = rec.ts

        emitted = self._advance()

        # A window is unrecoverable once the stream has moved past its end plus
        # the lateness budget and the window is no longer open.
        deadline = (w + 1) * self.window_s + self.allowed_lateness_s
        if (self._max_ts - self.t0) > deadline and w not in self._open:
            self.dropped_late += 1
            return emitted

        table = self._open.get(w)
        if table is None:
            table = OrderedDict()
            self._open[w] = table

        self.n_flows += 1

        if self.roles in ("both", "src"):
            s = self._host(table, rec.src)
            s.src_flows += 1
            s.src_pkts += rec.fwd_pkts
            s.src_bytes += rec.fwd_bytes
            s.src_peers.add(rec.dst)
            s.src_dports.add(rec.dport)
            s.src_peer_freq.add(rec.dst)
            s.src_iat.observe(rel)
            if self._proto is not None:
                for qn in rec.qnames:
                    self._proto.add(s.proto, qname=qn)
                for fp in rec.tls_fps:
                    self._proto.add(s.proto, tls_fp=fp)

        if self.roles in ("both", "dst"):
            d = self._host(table, rec.dst)
            d.dst_flows += 1
            d.dst_pkts += rec.fwd_pkts
            d.dst_bytes += rec.fwd_bytes
            d.dst_srcs.add(rec.src)
            d.dst_src_freq.add(rec.src)

        return emitted

    # ------------------------------------------------------------------ emit
    def _advance(self) -> List[dict]:
        """Close every window the watermark has passed, oldest first."""
        if not self._open:
            return []
        rel_max = self._max_ts - self.t0
        out: List[dict] = []
        for w in sorted(self._open.keys()):
            if rel_max <= (w + 1) * self.window_s + self.allowed_lateness_s:
                break
            out.extend(self._emit_window(w, self._open.pop(w)))
        return out

    def _emit_window(self, w: int, table) -> List[dict]:
        want_src = self.roles in ("both", "src")
        want_dst = self.roles in ("both", "dst")
        rows: List[dict] = []
        for host, st in table.items():
            row = {"window": w, "host": host}

            if want_src:
                base = self._baseline.get(host)
                base_val = base.value() if base is not None else 0.0
                n_peers = st.src_peers.count()
                total_peer = max(1, st.src_peer_freq.total)
                row.update({
                    "hw_src_n_flows": float(st.src_flows),
                    "hw_src_n_peers": n_peers,
                    "hw_src_n_dports": st.src_dports.count(),
                    "hw_src_fanout_per_flow": n_peers / max(1, st.src_flows),
                    "hw_src_peer_concentration": st.src_peer_freq.max_count() / total_peer,
                    "hw_src_fwd_pkts": st.src_pkts,
                    "hw_src_fwd_bytes": st.src_bytes,
                    "hw_src_iat_cv": st.src_iat.cv,
                    "hw_src_iat_mean": st.src_iat.mean,
                    "hw_src_bytes_vs_baseline": st.src_bytes / (base_val + 1.0),
                })
                # Protocol block. Scored against everything seen before this
                # window, then folded in - the same score-then-learn ordering
                # the causal baseline below uses, for the same reason.
                if self._proto is not None:
                    row.update(self._proto.features(st.proto))

                # Update the causal baseline AFTER emitting, so the value used
                # for this window never includes this window.
                if base is None:
                    base = DecayedCounter(half_life=self.window_s * self._alpha_half_life)
                    self._baseline[host] = base
                base.add((w + 1) * self.window_s, st.src_bytes)

            if want_dst:
                n_srcs = st.dst_srcs.count()
                row.update({
                    "hw_dst_n_flows": float(st.dst_flows),
                    "hw_dst_n_srcs": n_srcs,
                    "hw_dst_src_entropy": st.dst_src_freq.entropy(),
                    "hw_dst_fwd_pkts": st.dst_pkts,
                    "hw_dst_fwd_bytes": st.dst_bytes,
                    "hw_dst_flows_per_src": st.dst_flows / max(1.0, n_srcs),
                })

            rows.append(row)

        self.n_windows += 1
        return rows

    def flush(self) -> List[dict]:
        out: List[dict] = []
        for w in sorted(self._open.keys()):
            out.extend(self._emit_window(w, self._open[w]))
        self._open.clear()
        return out

    # ------------------------------------------------------------------ stats
    def stats(self) -> dict:
        return {
            "flows": self.n_flows,
            "windows": self.n_windows,
            "evicted_hosts": self.evicted_hosts,
            "dropped_late": self.dropped_late,
            "open_windows_now": len(self._open),
            "baseline_entries": len(self._baseline),
            "window_s": self.window_s,
            "allowed_lateness_s": self.allowed_lateness_s,
            "roles": self.roles,
            "latency_s": self.window_s + self.allowed_lateness_s,
        }


def run_stream(records: Iterable[FlowRecord],
               window_s: float = WINDOW_S,
               max_hosts: int = 50_000,
               allowed_lateness_s: float = 0.0) -> Tuple[List[dict], dict]:
    """Convenience: drive the extractor over an iterable, return rows + stats."""
    ex = StreamingHostWindow(window_s=window_s, max_hosts=max_hosts,
                             allowed_lateness_s=allowed_lateness_s)
    out: List[dict] = []
    for rec in records:
        out.extend(ex.push(rec))
    out.extend(ex.flush())
    return out, ex.stats()

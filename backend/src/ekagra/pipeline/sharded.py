"""Sharded pipeline — parallelism across processes, partitioned by host.

The claim this file had to make honest
--------------------------------------
Experiment 06 measured 47,968 packets/s single-threaded and the write-up said
the pipeline is "trivially shardable by hash(host) with no cross-talk". Building
it showed that was too casual in one specific way:

**A flow touches two hosts.** The host-window extractor updates state for the
source *and* the destination. So `hash(host)` is not a partition of the work -
each flow's two updates belong on two different shards. Sharding on `hash(src)`
alone leaves every host's destination-role state scattered across every shard.

What is true is that the work splits into two stages, each of which partitions
cleanly on a different key:

    packets  --partition by hash(5-tuple)-->  assemblers   (flow state is
                                                            per-5-tuple)
    flows    --partition by hash(src)     -->  src-role features
    flows    --partition by hash(dst)     -->  dst-role features

Stages 2 and 3 read the same flow records with different partition keys, so the
flows are consumed twice. There is still no cross-talk - no shard ever needs
another shard's state - but the cost model is "two passes over flows", not
"free linear speedup", and the measured numbers reflect that.

Why the assembler and the src-role stage are fused
--------------------------------------------------
On a one-way tap a flow's 5-tuple has a fixed source, so `hash(src)` is a
*refinement* of `hash(5-tuple)`: every packet of a flow lands on the same shard
under either key. That lets stage 1 and stage 2 run in one worker with no
shuffle between them. Only the dst-role stage needs a repartition, and it
repartitions flow records (362k) rather than packets (434k).

Determinism
-----------
Every shard is given the same `t0` and the same window size. Without that,
shards would disagree about window boundaries and the merged output would be
silently wrong - the same class of bug that produced a 91%-agreement result in
experiment 05.
"""

from __future__ import annotations

import heapq
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, List, Optional, Sequence, Tuple

from ..features.sketches import stable_hash
from ..features.streaming_host_window import (
    FlowRecord, StreamingHostWindow, WINDOW_S,
)
from ..ingest.flow_assembler import (
    ACTIVE_TIMEOUT_S, IDLE_TIMEOUT_S, FlowAssembler,
)
from ..ingest.records import Packet

# Compact wire formats. Packet/FlowRecord objects pickle slowly; tuples do not,
# and IPC cost is a first-order term in whether sharding pays for itself.
PacketTuple = Tuple[float, str, str, int, int, str, int, int]
# (start_ts, src, dst, dport, fwd_pkts, fwd_bytes, emit_ts)
#
# `emit_ts` - the stream time at which the assembler released the flow - is
# carried purely so the shuffle between stages can restore global emission
# order. Without it, concatenating shard outputs feeds stage 3 a sequence that
# runs 0..T for shard 0, then jumps back to 0 for shard 1, and the lateness
# budget discards most of it. That bug cost 17% of output rows and is exactly
# the kind of thing that looks like "sharding is lossy" rather than "the
# shuffle was unordered".
FlowTuple = Tuple[float, str, str, int, float, float, float]


def shard_of(key: str, n_shards: int) -> int:
    """Stable, process-independent shard assignment.

    `stable_hash`, not `hash()`: Python salts string hashing per process, so
    built-in hash would put the same host on different shards in different
    workers. That would not crash - it would quietly split one host's state
    across two shards and corrupt its features.
    """
    return stable_hash(key) % n_shards


def pack_packet(p: Packet) -> PacketTuple:
    return (p.ts, p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto,
            p.size, p.flags)


def _unpack_packet(t: PacketTuple, index: int = 0) -> Packet:
    return Packet(index=index, ts=t[0], src_ip=t[1], dst_ip=t[2], src_port=t[3],
                  dst_port=t[4], proto=t[5], size=t[6], flags=t[7], ttl=64,
                  direction=1)


# --------------------------------------------------------------------- stages

def stage_assemble_and_src(args) -> Tuple[List[dict], List[FlowTuple]]:
    """Stage 1+2: assemble flows, then compute source-role features.

    Fused because `hash(src)` refines `hash(5-tuple)` on a one-way tap, so no
    shuffle is needed between them.
    """
    packets, t0, window_s, lateness, idle_to, active_to, max_hosts = args

    fa = FlowAssembler(idle_timeout=idle_to, active_timeout=active_to)
    ex = StreamingHostWindow(window_s=window_s, t0=t0, max_hosts=max_hosts,
                             allowed_lateness_s=lateness, roles="src")
    rows: List[dict] = []
    flows: List[FlowTuple] = []

    def _emit(rec: FlowRecord, emit_ts: float) -> None:
        flows.append((rec.ts, rec.src, rec.dst, rec.dport,
                      rec.fwd_pkts, rec.fwd_bytes, emit_ts))
        rows.extend(ex.push(rec))

    now = t0
    for i, pt in enumerate(packets):
        now = pt[0]
        for rec in fa.push(_unpack_packet(pt, i)):
            _emit(rec, now)
    for rec in fa.flush():
        _emit(rec, now)
    rows.extend(ex.flush())

    return rows, flows


def stage_dst(args) -> List[dict]:
    """Stage 3: destination-role features, partitioned by hash(dst)."""
    flows, t0, window_s, lateness, max_hosts = args
    ex = StreamingHostWindow(window_s=window_s, t0=t0, max_hosts=max_hosts,
                             allowed_lateness_s=lateness, roles="dst")
    rows: List[dict] = []
    for ts, src, dst, dport, pk, by, _emit_ts in flows:
        rows.extend(ex.push(FlowRecord(ts, src, dst, dport, pk, by)))
    rows.extend(ex.flush())
    return rows


# ------------------------------------------------------------------ driver

def partition(items: Sequence, key_fn, n_shards: int) -> List[List]:
    out: List[List] = [[] for _ in range(n_shards)]
    for it in items:
        out[shard_of(key_fn(it), n_shards)].append(it)
    return out


def run_sharded(packets: Sequence[Packet],
                n_shards: int = 4,
                window_s: float = WINDOW_S,
                allowed_lateness_s: float = 15.0,
                idle_timeout: float = IDLE_TIMEOUT_S,
                active_timeout: float = ACTIVE_TIMEOUT_S,
                max_hosts_per_shard: int = 50_000,
                executor: Optional[ProcessPoolExecutor] = None,
                ) -> Tuple[List[dict], Dict]:
    """Run the full pipeline across `n_shards` worker processes.

    Returns merged (window, host) rows and timing stats. Rows carry `hw_src_*`
    and `hw_dst_*` from the two stages and are merged on (window, host) by the
    caller - see `merge_rows`.
    """
    if not packets:
        return [], {}
    timing = {}
    _t = time.perf_counter()
    t0 = min(p.ts for p in packets)

    tuples = [pack_packet(p) for p in packets]
    # hash(src) refines hash(5-tuple), so one partition serves both stages 1-2.
    parts = partition(tuples, lambda t: t[1], n_shards)
    timing["partition_s"] = time.perf_counter() - _t

    own_pool = executor is None
    ex = executor or ProcessPoolExecutor(max_workers=n_shards)
    try:
        _t = time.perf_counter()
        a_args = [(p, t0, window_s, allowed_lateness_s, idle_timeout,
                   active_timeout, max_hosts_per_shard) for p in parts]
        a_results = list(ex.map(stage_assemble_and_src, a_args))
        timing["stage_a_s"] = time.perf_counter() - _t

        _t = time.perf_counter()
        src_rows: List[dict] = []
        per_shard_flows: List[List[FlowTuple]] = []
        for rows, flows in a_results:
            src_rows.extend(rows)
            per_shard_flows.append(flows)

        # Restore global emission order before repartitioning. Each shard emits
        # in its own stream order, so a k-way merge on `emit_ts` reconstructs
        # the sequence a single-process run would have seen. This is what a real
        # shuffle does; concatenating instead silently destroys the ordering the
        # lateness budget depends on.
        all_flows: List[FlowTuple] = list(
            heapq.merge(*per_shard_flows, key=lambda f: f[6]))

        # Repartition on destination for the dst-role stage.
        d_parts = partition(all_flows, lambda f: f[2], n_shards)
        timing["shuffle_s"] = time.perf_counter() - _t

        _t = time.perf_counter()
        d_args = [(f, t0, window_s, allowed_lateness_s, max_hosts_per_shard)
                  for f in d_parts]
        dst_rows: List[dict] = []
        for rows in ex.map(stage_dst, d_args):
            dst_rows.extend(rows)
        timing["stage_b_s"] = time.perf_counter() - _t
    finally:
        if own_pool:
            ex.shutdown()

    _t = time.perf_counter()

    merged = merge_rows(src_rows, dst_rows)
    timing["merge_rows_s"] = time.perf_counter() - _t

    parallel_s = timing["stage_a_s"] + timing["stage_b_s"]
    serial_s = timing["partition_s"] + timing["shuffle_s"] + timing["merge_rows_s"]
    stats = {
        **timing,
        "parallel_s": parallel_s,
        "serial_s": serial_s,
        "serial_fraction": serial_s / max(1e-9, parallel_s + serial_s),
        "n_shards": n_shards,
        "packets": len(packets),
        "flows": len(all_flows),
        "src_rows": len(src_rows),
        "dst_rows": len(dst_rows),
        "packets_per_shard_max": max(len(p) for p in parts),
        "packets_per_shard_min": min(len(p) for p in parts),
        "flows_per_shard_max": max(len(p) for p in d_parts),
        "max_hosts_per_shard": max_hosts_per_shard,
        "total_host_capacity": max_hosts_per_shard * n_shards,
    }
    return merged, stats


def merge_rows(src_rows: List[dict], dst_rows: List[dict]) -> List[dict]:
    """Combine the two role halves on (window, host)."""
    merged: Dict[Tuple[int, str], dict] = {}
    for r in src_rows:
        merged[(r["window"], r["host"])] = dict(r)
    for r in dst_rows:
        k = (r["window"], r["host"])
        if k in merged:
            merged[k].update(r)
        else:
            merged[k] = dict(r)
    return list(merged.values())


def run_single(packets: Sequence[Packet],
               window_s: float = WINDOW_S,
               allowed_lateness_s: float = 15.0,
               idle_timeout: float = IDLE_TIMEOUT_S,
               active_timeout: float = ACTIVE_TIMEOUT_S,
               max_hosts: int = 50_000) -> Tuple[List[dict], Dict]:
    """Single-process reference, using the identical two-stage decomposition.

    This is the correctness oracle for the sharded run: same stages, same keys,
    one worker. If sharded output differs from this, the partitioning is wrong.

    **Match `max_hosts` to the sharded run\'s total capacity** when comparing.
    `max_hosts` is a per-instance budget, so N shards hold N times as many hosts
    as one process. Under eviction pressure the two runs then legitimately
    disagree - not because the partitioning is wrong, but because the sharded
    deployment has more memory. Comparing 50k against 4x50k measures the budget
    difference, not the sharding.
    """
    t0 = min(p.ts for p in packets)
    tuples = [pack_packet(p) for p in packets]
    src_rows, flows = stage_assemble_and_src(
        (tuples, t0, window_s, allowed_lateness_s, idle_timeout, active_timeout,
         max_hosts))
    dst_rows = stage_dst((flows, t0, window_s, allowed_lateness_s, max_hosts))
    return merge_rows(src_rows, dst_rows), {"n_shards": 1, "packets": len(packets),
                                            "flows": len(flows)}

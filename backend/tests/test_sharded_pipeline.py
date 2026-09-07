"""Sharding invariants.

Sharding is only worth anything if it produces the same answer. These tests pin
the properties that make that true, and the one place it is knowingly *not*
exactly true (per-shard watermarks).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.features.streaming_host_window import StreamingHostWindow  # noqa: E402
from ekagra.ingest.synthetic import GeneratorConfig, SyntheticSource  # noqa: E402
from ekagra.ingest.visibility import DIODE_ONEWAY, VisibilityFilter  # noqa: E402
from ekagra.pipeline.sharded import (  # noqa: E402
    merge_rows, pack_packet, partition, run_single, shard_of,
    stage_assemble_and_src, stage_dst,
)


@pytest.fixture(scope="module")
def observed():
    pkts = SyntheticSource(GeneratorConfig(seed=41, duration_s=300.0)).generate()
    return list(VisibilityFilter(DIODE_ONEWAY).apply(pkts))


def test_shard_assignment_is_process_independent():
    """A host must land on the same shard in every worker process.

    Built-in `hash()` is salted per process, so using it here would split one
    host's state across two shards - silently, and only in multi-process runs.
    """
    code = (
        "import sys; sys.path.insert(0, r'%s');"
        "from ekagra.pipeline.sharded import shard_of;"
        "print([shard_of('10.20.30.%%d' %% i, 8) for i in range(12)])"
        % str(ROOT / "src")
    )
    outs = set()
    for seed in ("0", "1", "999"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, env=env)
        assert r.returncode == 0, r.stderr
        outs.add(r.stdout.strip())
    assert len(outs) == 1, f"shard assignment varies with PYTHONHASHSEED: {outs}"


def test_partition_is_complete_and_disjoint():
    items = [f"host{i}" for i in range(500)]
    for n in (1, 3, 8):
        parts = partition(items, lambda x: x, n)
        assert sum(len(p) for p in parts) == len(items)
        flat = [x for p in parts for x in p]
        assert sorted(flat) == sorted(items)
        # a key must always land in exactly one shard
        for i, p in enumerate(parts):
            assert all(shard_of(x, n) == i for x in p)


def test_roles_split_reproduces_both():
    """src-only plus dst-only must reconstruct the combined feature set."""
    from ekagra.features.host_window import HOST_WINDOW_FEATURES, WINDOW_S
    from ekagra.features.streaming_host_window import FlowRecord

    recs = [FlowRecord(float(i) * 0.7, f"10.0.0.{i % 5}", f"10.0.1.{i % 7}",
                       80 + (i % 3), 1.0 + i % 4, 100.0 * (1 + i % 6))
            for i in range(600)]

    def run(roles):
        ex = StreamingHostWindow(window_s=WINDOW_S, t0=0.0,
                                 allowed_lateness_s=15.0, roles=roles)
        rows = []
        for r in recs:
            rows.extend(ex.push(r))
        rows.extend(ex.flush())
        return rows

    both = {(r["window"], r["host"]): r for r in run("both")}
    split = {(r["window"], r["host"]): r
             for r in merge_rows(run("src"), run("dst"))}

    assert set(both) == set(split)
    for k in both:
        for f in HOST_WINDOW_FEATURES:
            assert both[k].get(f, 0.0) == pytest.approx(split[k].get(f, 0.0)), \
                f"{f} differs at {k}"


N_SHARDS = 4
PER_SHARD_HOSTS = 50_000


def _shard_in_process(observed, n=N_SHARDS, max_hosts=PER_SHARD_HOSTS):
    import heapq
    tuples = [pack_packet(p) for p in observed]
    t0 = min(t[0] for t in tuples)
    src_rows, per_shard = [], []
    for p in partition(tuples, lambda t: t[1], n):
        rows, flows = stage_assemble_and_src(
            (p, t0, 60.0, 15.0, 15.0, 120.0, max_hosts))
        src_rows.extend(rows)
        per_shard.append(flows)
    all_flows = list(heapq.merge(*per_shard, key=lambda f: f[6]))
    dst_rows = []
    for p in partition(all_flows, lambda f: f[2], n):
        dst_rows.extend(stage_dst((p, t0, 60.0, 15.0, max_hosts)))
    return merge_rows(src_rows, dst_rows)


def test_sharded_matches_single_on_shared_cells(observed):
    """Sharded output must agree with the single-process run.

    `max_hosts` is matched deliberately: it is a *per-instance* budget, so N
    shards hold N times as many hosts as one process. Comparing the defaults
    would measure the memory difference, not the partitioning - which is
    exactly the trap this test fell into first (72% agreement, and the cause
    was 99,483 evictions in the single run and none in the sharded one).
    """
    single, _ = run_single(observed, max_hosts=N_SHARDS * PER_SHARD_HOSTS)
    sharded = _shard_in_process(observed)

    a = {(r["window"], r["host"]): r for r in single}
    b = {(r["window"], r["host"]): r for r in sharded}
    shared = set(a) & set(b)

    # Key sets agree to within a handful of cells: each shard runs its own
    # watermark, so which marginal records fall outside the lateness budget
    # depends on that shard's traffic. This is a known, bounded difference.
    agreement = len(shared) / len(set(a) | set(b))
    assert agreement > 0.999, f"key agreement only {agreement:.5f}"

    mismatches = 0
    for k in shared:
        for f, va in a[k].items():
            if f in ("window", "host"):
                continue
            if va != pytest.approx(b[k].get(f, 0.0), rel=1e-9, abs=1e-12):
                mismatches += 1
    assert mismatches / max(1, len(shared)) < 1e-3, \
        f"{mismatches} value mismatches across {len(shared)} shared cells"


def test_sharding_multiplies_host_capacity(observed):
    """Under eviction pressure, sharding retains more hosts - by design.

    `max_hosts` bounds one instance. Running N shards gives N times the total
    budget, so a workload that evicts heavily on one process may evict nothing
    when sharded. That is a real capacity difference and it must be visible in
    the numbers rather than mistaken for a correctness bug.
    """
    tight = 2_000
    single, _ = run_single(observed, max_hosts=tight)
    sharded = _shard_in_process(observed, n=N_SHARDS, max_hosts=tight)
    assert len(sharded) > len(single), (
        "with a tight per-instance budget, N shards should retain more cells "
        f"(single {len(single)}, sharded {len(sharded)})")


def test_flow_tuple_carries_emission_time(observed):
    """The shuffle between stages orders on emission time.

    Without it, concatenating shard outputs feeds stage 3 a sequence that jumps
    backwards in time at every shard boundary, and the lateness budget discards
    most of it - which cost 17% of output rows before this was fixed.
    """
    tuples = [pack_packet(p) for p in observed[:20_000]]
    t0 = min(t[0] for t in tuples)
    _, flows = stage_assemble_and_src(
        (tuples, t0, 60.0, 15.0, 15.0, 120.0, 50_000))
    assert flows and len(flows[0]) == 7, "flow tuple should carry emit_ts"
    emits = [f[6] for f in flows]
    assert emits == sorted(emits), "emission times should be non-decreasing"
    # start times are NOT sorted - that is the whole reason lateness exists
    starts = [f[0] for f in flows]
    assert starts != sorted(starts), "expected out-of-order flow start times"

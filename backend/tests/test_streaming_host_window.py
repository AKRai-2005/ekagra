"""The streaming extractor must agree with the batch one, and stay bounded.

Experiment 05 shows agreement on the real corpus. These tests pin the
properties that experiment cannot check, because the corpus never exercises
them: the sketch promotion path, and LRU eviction under host pressure.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.features.host_window import (  # noqa: E402
    HOST_WINDOW_FEATURES, WINDOW_S, add_host_window_features,
)
from ekagra.features.streaming_host_window import (  # noqa: E402
    SPARSE_CARDINALITY_MAX, SPARSE_FREQUENCY_MAX, CardinalitySummary, FlowRecord,
    FrequencySummary, StreamingHostWindow, _Welford,
)

SRC_F = [c for c in HOST_WINDOW_FEATURES if c.startswith("hw_src_")]
DST_F = [c for c in HOST_WINDOW_FEATURES if c.startswith("hw_dst_")]


def _synthetic(n=8000, n_src=30, n_dst=80, seed=0, duration=300.0):
    rng = np.random.default_rng(seed)
    ts = np.sort(rng.uniform(0, duration, n))
    ts = ts - ts[0]          # align origin with the batch min(), see below
    base = pd.Timestamp("2017-07-03 00:00:00")
    return pd.DataFrame({
        "Timestamp": [base + pd.Timedelta(seconds=float(x)) for x in ts],
        "Src IP": [f"10.0.0.{rng.integers(1, n_src)}" for _ in range(n)],
        "Dst IP": [f"10.0.1.{rng.integers(1, n_dst)}" for _ in range(n)],
        "Dst Port": rng.integers(1, 900, n),
        "Total Fwd Packet": rng.integers(1, 40, n),
        "Total Length of Fwd Packet": rng.integers(60, 4000, n),
    }), ts


def _run_stream(df, ts, **kw):
    ex = StreamingHostWindow(window_s=WINDOW_S, t0=0.0, **kw)
    rows = []
    for i in range(len(ts)):
        rows.extend(ex.push(FlowRecord(
            float(ts[i]), df["Src IP"].iat[i], df["Dst IP"].iat[i],
            int(df["Dst Port"].iat[i]), float(df["Total Fwd Packet"].iat[i]),
            float(df["Total Length of Fwd Packet"].iat[i]))))
    rows.extend(ex.flush())
    return pd.DataFrame(rows), ex


def _join(df, ts, emitted):
    out = df.copy()
    out["window"] = (ts // WINDOW_S).astype(int)
    out = out.merge(emitted[["window", "host"] + SRC_F].rename(columns={"host": "Src IP"}),
                    on=["window", "Src IP"], how="left")
    out = out.merge(emitted[["window", "host"] + DST_F].rename(columns={"host": "Dst IP"}),
                    on=["window", "Dst IP"], how="left")
    out[HOST_WINDOW_FEATURES] = out[HOST_WINDOW_FEATURES].fillna(0.0)
    return out


def test_streaming_matches_batch_exactly_in_sparse_mode():
    """With few peers per host, every estimator stays exact - so the two
    implementations must agree bit for bit, not merely correlate.

    The one exception is `hw_src_bytes_vs_baseline`, which is deliberately a
    different quantity in the two implementations (EWM over appearances vs
    time-decay across gaps). See the module docstring.
    """
    df, ts = _synthetic()
    batch = add_host_window_features(df, window_s=WINDOW_S)
    emitted, _ = _run_stream(df, ts)
    stream = _join(df, ts, emitted)

    for c in HOST_WINDOW_FEATURES:
        if c == "hw_src_bytes_vs_baseline":
            continue
        a = batch[c].to_numpy(dtype=np.float64)
        b = stream[c].to_numpy(dtype=np.float64)
        assert np.allclose(a, b, rtol=1e-9, atol=1e-12), (
            f"{c} diverges: max abs diff {np.max(np.abs(a - b))}")


def test_misaligned_time_origin_breaks_agreement():
    """Window alignment is load-bearing, and getting it wrong fails quietly.

    A harness bug that fed the stream timestamps relative to zero while the
    batch version used `min(Timestamp)` produced ~0.998 correlation and 91%
    agreement - close enough to look like sketch error rather than a bug. This
    test pins the failure mode: a shifted origin must produce *materially*
    different features, so the near-miss can never be mistaken for noise again.
    """
    df, ts = _synthetic(n=4000)
    batch = add_host_window_features(df, window_s=WINDOW_S)

    emitted_ok, _ = _run_stream(df, ts)
    aligned = _join(df, ts, emitted_ok)

    emitted_bad, _ = _run_stream(df, ts + 17.0)   # origin off by 17s
    misaligned = _join(df, ts, emitted_bad)

    col = "hw_src_n_flows"
    a = batch[col].to_numpy(dtype=np.float64)
    good = aligned[col].to_numpy(dtype=np.float64)
    bad = misaligned[col].to_numpy(dtype=np.float64)

    assert np.allclose(a, good, rtol=1e-9), "aligned stream should match batch"
    frac_equal = float(np.mean(np.isclose(a, bad, rtol=1e-6)))
    assert frac_equal < 0.95, (
        f"a 17s origin shift left {frac_equal:.1%} of values unchanged - the "
        f"test cannot distinguish misalignment from sketch error")


def test_cardinality_summary_promotes_and_stays_close():
    s = CardinalitySummary()
    for i in range(SPARSE_CARDINALITY_MAX):
        s.add(f"peer{i}")
    assert s.is_exact and s.count() == SPARSE_CARDINALITY_MAX

    for i in range(SPARSE_CARDINALITY_MAX, 20_000):
        s.add(f"peer{i}")
    assert not s.is_exact, "should have promoted to HLL"
    est = s.count()
    assert abs(est - 20_000) / 20_000 < 0.10, f"HLL estimate off: {est}"


def test_frequency_summary_promotes_and_tracks_heavy_hitter():
    f = FrequencySummary()
    # one dominant source plus a long tail that forces promotion
    for _ in range(5_000):
        f.add("heavy")
    for i in range(SPARSE_FREQUENCY_MAX * 4):
        f.add(f"tail{i}")
    assert f._exact is None, "should have promoted"
    assert f.max_count() >= 5_000 * 0.9, "heavy hitter lost after promotion"
    assert f.entropy() > 0.0


def test_frequency_summary_entropy_is_exact_while_sparse():
    f = FrequencySummary()
    for k in ("a", "b", "c", "d"):
        f.add(k, 25)
    assert f.entropy() == pytest.approx(2.0)      # 4 equal classes -> 2 bits
    assert f.max_count() == 25


def test_welford_matches_numpy():
    rng = np.random.default_rng(3)
    t = np.sort(rng.uniform(0, 100, 500))
    w = _Welford()
    for x in t:
        w.observe(float(x))
    d = np.diff(t)
    assert w.mean == pytest.approx(d.mean(), rel=1e-9)
    assert w.cv == pytest.approx(d.std() / d.mean(), rel=1e-9)


def test_eviction_is_bounded_and_counted():
    """The corpus never hits max_hosts, so the eviction path is only covered
    here. A sensor that silently drops hosts is lying about its coverage."""
    df, ts = _synthetic(n=6000, n_src=200, n_dst=400, seed=5)
    _, ex = _run_stream(df, ts, max_hosts=50)
    assert ex.evicted_hosts > 0, "expected eviction pressure at max_hosts=50"
    assert all(len(tbl) <= 50 for tbl in ex._open.values())


def test_baseline_is_causal():
    """The baseline used in window w must not include window w's own bytes."""
    base = pd.Timestamp("2017-07-03 00:00:00")
    ts = np.array([1.0, 2.0, 61.0, 62.0, 121.0])
    df = pd.DataFrame({
        "Timestamp": [base + pd.Timedelta(seconds=float(x)) for x in ts],
        "Src IP": ["10.0.0.1"] * 5,
        "Dst IP": ["10.0.1.1"] * 5,
        "Dst Port": [80] * 5,
        "Total Fwd Packet": [1] * 5,
        "Total Length of Fwd Packet": [1000] * 5,
    })
    emitted, _ = _run_stream(df, ts)
    first = emitted[emitted.window == 0].iloc[0]
    # First window has no prior history, so baseline is 0 and the ratio is
    # bytes/(0+1) - it must not divide by its own value (which would give ~1).
    assert first["hw_src_bytes_vs_baseline"] > 100, \
        "first window appears to include itself in its own baseline"


def test_emission_happens_at_window_close_not_at_end():
    """Rows must come out during the stream, not only on flush - otherwise it
    is batch processing wearing a streaming interface."""
    df, ts = _synthetic(n=4000, duration=600.0)
    ex = StreamingHostWindow(window_s=WINDOW_S, t0=0.0)
    mid_stream = 0
    for i in range(len(ts)):
        mid_stream += len(ex.push(FlowRecord(
            float(ts[i]), df["Src IP"].iat[i], df["Dst IP"].iat[i],
            int(df["Dst Port"].iat[i]), 1.0, 100.0)))
    at_flush = len(ex.flush())
    assert mid_stream > 0, "no rows emitted before flush - not streaming"
    assert mid_stream > at_flush, "most rows should be emitted mid-stream"

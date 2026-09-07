"""Reproducibility is a correctness property here, not a nicety.

The first version of this pipeline produced macro-F1 between 0.90 and 0.97
across identical invocations. The cause was Python's per-process string hash
salt reaching the sketches, the flow sampler and the reputation oracle. A
result you cannot reproduce is not a result, and "re-run it in front of me" is
a question an evaluator is entitled to ask.

These tests fail if that regression ever comes back.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.features.extractors import EnrichmentOracle, FeatureBuilder  # noqa: E402
from ekagra.features.sketches import CountMinSketch, HyperLogLog
from ekagra.ingest.synthetic import GeneratorConfig, SyntheticSource  # noqa: E402
from ekagra.ingest.visibility import DIODE_ONEWAY, FULL_ENRICHED, VisibilityFilter  # noqa: E402

def test_stable_hash_is_process_independent():
    """The hash must not depend on PYTHONHASHSEED.

    Run in a fresh interpreter with a different hash seed and compare.
    """
    code = (
        "import sys; sys.path.insert(0, r'%s');"
        "from ekagra.features.sketches import stable_hash;"
        "print(stable_hash('10.20.30.7'), stable_hash('google.com'))"
        % str(ROOT / "src")
    )
    outs = set()
    for seed in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, env=env)
        assert r.returncode == 0, r.stderr
        outs.add(r.stdout.strip())
    assert len(outs) == 1, f"stable_hash varies with PYTHONHASHSEED: {outs}"


def test_sketches_are_deterministic():
    items = [f"10.20.30.{i}" for i in range(200)]
    a, b = CountMinSketch(256, 3), CountMinSketch(256, 3)
    for it in items:
        a.add(it)
    for it in reversed(items):
        b.add(it)
    # Same multiset, same table - order of insertion must not matter.
    assert a._table == b.__getattribute__("_table")

    h1, h2 = HyperLogLog(10), HyperLogLog(10)
    for it in items:
        h1.add(it)
    for it in reversed(items):
        h2.add(it)
    assert h1.count() == pytest.approx(h2.count())


def test_enrichment_oracle_is_order_independent():
    """A reputation feed's answer must be a function of the IP, not of when
    it was asked. The original implementation drew from a shared RNG on first
    query, which made results depend on set-iteration order."""
    mal = {f"203.0.113.{i}" for i in range(50)}
    o1 = EnrichmentOracle(mal, seed=99)
    o2 = EnrichmentOracle(mal, seed=99)
    ips = [f"203.0.113.{i}" for i in range(50)] + [f"198.51.100.{i}" for i in range(50)]
    forward = [o1.reputation(ip) for ip in ips]
    backward = [o2.reputation(ip) for ip in reversed(ips)][::-1]
    assert forward == backward


def test_feature_extraction_is_bitwise_reproducible():
    """Two full extractions over the same traffic must agree exactly."""
    pkts = SyntheticSource(GeneratorConfig(seed=11, duration_s=180.0)).generate()
    mal = {p.src_ip for p in pkts if p.label != "benign"}
    frames = []
    for _ in range(2):
        oracle = EnrichmentOracle(mal, seed=99)
        vf = VisibilityFilter(FULL_ENRICHED)
        frames.append(FeatureBuilder(FULL_ENRICHED, oracle=oracle).consume(vf.apply(pkts)).to_frame())
    a, b = frames
    assert a.shape == b.shape
    assert a.equals(b), "feature extraction is not reproducible"


def test_visibility_filter_sampling_is_reproducible():
    pkts = SyntheticSource(GeneratorConfig(seed=12, duration_s=120.0)).generate()
    from ekagra.ingest.visibility import DIODE_ONEWAY_SAMPLED
    keep = [len(list(VisibilityFilter(DIODE_ONEWAY_SAMPLED).apply(pkts))) for _ in range(3)]
    assert len(set(keep)) == 1, f"flow sampling is not reproducible: {keep}"


def test_one_way_profile_removes_reverse_traffic():
    """Sanity: the ablation actually ablates."""
    pkts = SyntheticSource(GeneratorConfig(seed=13, duration_s=120.0)).generate()
    kept = list(VisibilityFilter(DIODE_ONEWAY).apply(pkts))
    assert 0 < len(kept) < len(pkts)
    assert all(p.direction == 1 for p in kept)

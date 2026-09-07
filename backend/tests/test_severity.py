"""Severity has to stay orthogonal to confidence, and stay ordered.

The failure mode this guards against is someone "simplifying" severity into
`class_weight * confidence` later. That reads as tidier and destroys the only
property that makes two numbers worth showing instead of one.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.detect.severity import (  # noqa: E402
    BANDS, STAGE_IMPACT, VOLUME_SATURATION, Severity, magnitude_for, severity,
)
from ekagra.ingest.records import THREAT_CLASSES  # noqa: E402


def test_every_threat_class_has_a_weight():
    """A class added to the detector without a weight would silently score
    zero, i.e. every alert of a brand-new class would read as 'info'."""
    for c in THREAT_CLASSES:
        assert c in STAGE_IMPACT, f"{c} has no severity weight"


def test_volume_magnitude_applies_only_where_volume_is_impact():
    """Measured, not assumed: per-cell volume for a scan, beacon or DDoS says
    nothing about how bad it is (296 / 444 / 74 median bytes), while for
    exfiltration it is the damage itself (2.26 MB). An earlier version gave
    every class a magnitude feature and half of them read the wrong side of the
    cell, returning a silent zero."""
    assert set(VOLUME_SATURATION) == {"exfil", "encrypted"}
    for c in ("scan", "beacon", "ddos", "dga"):
        mag, driver = magnitude_for(c, {"hw_src_fwd_bytes": 9e9})
        assert mag == 0.0 and driver == "", f"{c} should take its stage weight alone"


def test_severity_never_reads_confidence():
    """The signature does not accept it, so this pins the module surface: if
    someone adds a confidence parameter, this fails and they have to justify
    it against the module docstring."""
    import inspect
    params = set(inspect.signature(severity).parameters)
    assert params == {"threat_class", "features"}, params


def test_exfiltration_outranks_scanning_at_equal_evidence():
    """The ordering that matters for triage. A quiet exfiltration must outrank
    a loud port scan, which is exactly what class-times-confidence gets wrong."""
    loud_scan = severity("scan", {"hw_src_fwd_bytes": 9e9})
    quiet_exfil = severity("exfil", {"hw_src_fwd_bytes": 0.0})
    assert quiet_exfil.score > loud_scan.score
    assert quiet_exfil.level in ("high", "critical")
    assert loud_scan.level in ("low", "medium")


def test_magnitude_moves_severity_within_a_class_but_does_not_reorder_classes():
    lo = severity("exfil", {"hw_src_fwd_bytes": 0.0})
    hi = severity("exfil", {"hw_src_fwd_bytes": 4_000_000.0})
    assert hi.score > lo.score
    # ...but a maxed-out scan still never overtakes the quietest exfiltration.
    assert severity("scan", {"hw_src_fwd_bytes": 9e9}).score < lo.score


def test_benign_is_info_and_scores_zero():
    s = severity("benign", {"hw_src_n_flows": 500.0})
    assert s.level == "info" and s.score == 0.0


def test_absent_evidence_and_measured_zero_are_not_the_same_answer():
    """The distinction an earlier version collapsed, and the reason it matters:

    A host measured to have moved **zero bytes** is evidence, and it should pull
    an exfiltration down to its class floor. A feature that was **never
    computed** - which happens on the flow-only path - is not evidence, and must
    not pull anything anywhere. Absence of evidence is not evidence of absence,
    so the unmeasured case falls back to the class weight alone.
    """
    absent = severity("exfil", {})
    measured_zero = severity("exfil", {"hw_src_fwd_bytes": 0.0})

    assert absent.driver == "" and absent.magnitude == 0.0
    assert measured_zero.driver == "hw_src_fwd_bytes"
    assert absent.score > measured_zero.score,         "not measuring volume must not reduce severity the way measuring zero does"
    assert measured_zero.score == pytest.approx(1.0 * 0.6)


@pytest.mark.parametrize("bad", [float("nan"), None, "not-a-number"])
def test_unusable_feature_values_degrade_quietly(bad):
    mag, driver = magnitude_for("exfil", {"hw_src_fwd_bytes": bad})
    assert mag == 0.0 and driver == ""


def test_magnitude_is_clamped():
    mag, _ = magnitude_for("exfil", {"hw_src_fwd_bytes": 9e9})
    assert mag == 1.0


def test_volume_is_read_from_whichever_side_of_the_cell_carries_it():
    """The bug this module already shipped once: a scan alert fires on the host
    being scanned, whose hw_src_* counters are empty by construction."""
    src_side = magnitude_for("exfil", {"hw_src_fwd_bytes": 3_000_000.0})
    dst_side = magnitude_for("exfil", {"hw_dst_fwd_bytes": 3_000_000.0})
    assert src_side[0] == dst_side[0] > 0.0
    assert src_side[1] == "hw_src_fwd_bytes" and dst_side[1] == "hw_dst_fwd_bytes"


def test_an_established_beacon_is_not_filed_as_low():
    """The regression that exposed the wrong-side bug: beacons are low-volume by
    definition, so a volume-driven magnitude buried an established C2 channel."""
    assert severity("beacon", {"hw_src_fwd_bytes": 444.0}).level in ("medium", "high")


def test_bands_are_ordered_and_cover_zero():
    edges = [e for e, _ in BANDS]
    assert edges == sorted(edges, reverse=True), "bands must descend"
    assert edges[-1] == 0.0, "lowest band must catch a score of zero"


def test_result_is_reproducible_from_hashed_fields_alone():
    """Severity is deliberately not hashed into the evidence chain, which is
    only sound if it is a pure function of fields that ARE hashed."""
    feats = {"hw_src_fwd_bytes": 1_500_000.0}
    a = severity("exfil", feats)
    b = severity("exfil", dict(feats))
    assert a == b and isinstance(a, Severity)

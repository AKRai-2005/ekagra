"""Invariants for the CIC-IDS2017 visibility classification.

The whole real-data experiment rests on one judgement call: which columns a
one-way sensor could actually produce. If that classification is wrong, the
result is wrong in a way no amount of modelling fixes. These tests pin the
properties that must hold regardless of which corpus revision is loaded.

They run without the dataset present - the classification is static.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.ingest.replay import (  # noqa: E402
    BACKWARD_DERIVED, BIDIRECTIONAL_AGGREGATE, CICIDS2017, FORWARD_OBSERVABLE,
    META_COLUMNS, column_audit,
)

# The 108 columns of the corrected CICFlowMeter extraction, as shipped.
CORPUS_COLUMNS = (
    META_COLUMNS + FORWARD_OBSERVABLE + BACKWARD_DERIVED + BIDIRECTIONAL_AGGREGATE
)


def test_feature_classes_are_disjoint():
    """A column cannot be both forward-observable and backward-derived."""
    f, b, a = set(FORWARD_OBSERVABLE), set(BACKWARD_DERIVED), set(BIDIRECTIONAL_AGGREGATE)
    assert not (f & b), f"forward/backward overlap: {f & b}"
    assert not (f & a), f"forward/bidirectional overlap: {f & a}"
    assert not (b & a), f"backward/bidirectional overlap: {b & a}"


def test_no_backward_column_leaks_into_the_forward_set():
    """Nothing named Bwd/backward may sit in the forward-observable set.

    A naming check rather than a semantic one, but it catches the realistic
    failure: someone adds a feature to the wrong list during a refactor and the
    ablation silently stops ablating.
    """
    offenders = [c for c in FORWARD_OBSERVABLE
                 if "bwd" in c.lower() or "backward" in c.lower()]
    assert not offenders, f"backward features in the forward set: {offenders}"


def test_every_forward_column_is_actually_forward_named_or_neutral():
    """Forward-observable columns must be Fwd-prefixed or direction-neutral."""
    neutral = {"Src Port", "Dst Port", "Protocol"}
    for c in FORWARD_OBSERVABLE:
        assert c in neutral or "fwd" in c.lower(), (
            f"{c!r} is in the forward set but is neither Fwd-named nor "
            f"direction-neutral; classify it explicitly"
        )


def test_bidirectional_aggregates_are_not_treated_as_observable():
    """The subtle category: flow-level stats mix both directions.

    `Flow IAT Mean` is not a forward statistic with noise - on a one-way tap the
    sensor computes a different quantity. These must never be in the forward set.
    """
    for c in ("Flow Duration", "Flow IAT Mean", "Packet Length Mean",
              "SYN Flag Count", "Active Mean", "Idle Mean"):
        assert c in BIDIRECTIONAL_AGGREGATE, f"{c} must be bidirectional-aggregate"
        assert c not in FORWARD_OBSERVABLE


def test_ip_addresses_are_never_features():
    """Src/Dst IP must stay out of every feature set.

    The testbed uses fixed attacker addresses; a model handed the IPs memorises
    them and reports a meaningless near-perfect score.
    """
    for ip_col in ("Src IP", "Dst IP", "Flow ID"):
        assert ip_col not in FORWARD_OBSERVABLE
        assert ip_col not in BACKWARD_DERIVED
        assert ip_col not in BIDIRECTIONAL_AGGREGATE
        assert ip_col in META_COLUMNS


def test_column_audit_classifies_everything():
    df = pd.DataFrame(columns=CORPUS_COLUMNS)
    audit = column_audit(df)
    unclassified = audit[audit["class"] == "UNCLASSIFIED"]["column"].tolist()
    assert not unclassified, f"unclassified columns: {unclassified}"
    counts = audit["class"].value_counts().to_dict()
    assert counts.get("forward-observable", 0) == len(FORWARD_OBSERVABLE)
    assert counts.get("backward-derived", 0) == len(BACKWARD_DERIVED)


def test_oneway_is_a_strict_subset_of_full():
    ds = CICIDS2017()
    ds._df = pd.DataFrame(columns=CORPUS_COLUMNS)
    full = set(ds.feature_columns("full"))
    oneway = set(ds.feature_columns("oneway"))
    assert oneway < full, "one-way feature set must be a strict subset of full"
    assert len(full) - len(oneway) == len(BACKWARD_DERIVED) + len(BIDIRECTIONAL_AGGREGATE)


def test_ablation_zeroes_exactly_the_unobservable_columns():
    import numpy as np
    ds = CICIDS2017()
    ds._df = pd.DataFrame(columns=CORPUS_COLUMNS)
    cols = ds.feature_columns("full")
    X = np.ones((5, len(cols)), dtype=np.float32)
    Xa = ds.ablate_to_oneway(X, cols)
    for j, c in enumerate(cols):
        if c in FORWARD_OBSERVABLE:
            assert Xa[:, j].all(), f"{c} should have survived ablation"
        else:
            assert not Xa[:, j].any(), f"{c} should have been zeroed"


def test_missing_dataset_raises_actionable_error():
    ds = CICIDS2017(path=Path("does-not-exist.csv"))
    with pytest.raises(FileNotFoundError) as e:
        ds.load()
    assert "zenodo" in str(e.value).lower(), "error should say where to get the data"

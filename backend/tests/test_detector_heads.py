"""Detector-head invariants.

These pin the properties exp09 depends on, and the one that exp09 refuted so it
cannot quietly come back: `FEATURES` is documentation, not a training
restriction, unless a caller explicitly asks for the starved variant.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.detect.base import HeadEnsemble  # noqa: E402
from ekagra.detect.heads import ALL_HEADS, build_heads  # noqa: E402
from ekagra.features.host_window import HOST_WINDOW_FEATURES  # noqa: E402
from ekagra.features.protocol import PROTOCOL_FEATURES  # noqa: E402

# The vector a head sees on the packet path: the sixteen protocol-agnostic
# host-window aggregates, plus the DNS/TLS block that only packet input can
# supply. Flow-record corpora deliver the first group and zeros for the second.
FEATURES = list(HOST_WINDOW_FEATURES) + list(PROTOCOL_FEATURES)
CLASSES = ("ddos", "scan", "beacon", "exfil", "dga", "encrypted")


def toy(n=600, seed=0):
    """Separable-ish synthetic cells with deliberate label co-occurrence."""
    rng = np.random.default_rng(seed)
    X = rng.random((n, len(FEATURES))).astype(np.float32)
    Y = {}
    # each class keyed to a different feature so heads have something to find
    for i, c in enumerate(CLASSES):
        col = FEATURES.index(FEATURES[i * 2 % len(FEATURES)])
        X[:, col] += rng.random(n) * 0.1
        Y[c] = (X[:, col] > 0.75).astype(int)
    return X, Y


def test_every_declared_feature_exists():
    """A head declaring a feature the extractor does not produce would fail
    only at fit time, on whatever machine ran it next."""
    for cls in ALL_HEADS:
        for f in cls.FEATURES:
            assert f in FEATURES, f"{cls.__name__} declares unknown feature {f!r}"


def test_the_protocol_heads_actually_use_protocol_features():
    """The DGA and encrypted heads were shipped knowingly handicapped because
    the host-window set carried no DNS or TLS evidence. If a refactor ever
    disconnects them again, this fails rather than silently regressing the two
    detections the problem statement names most specifically."""
    by_name = {c.name: c for c in ALL_HEADS}
    dns = {"hw_src_qname_entropy", "hw_src_qname_bigram_rarity"}
    tls = {"hw_src_tls_fp_rarity", "hw_src_tls_fp_novel"}
    assert dns & set(by_name["dga"].FEATURES), "dga head lost its DNS features"
    assert tls & set(by_name["encrypted"].FEATURES), "encrypted head lost its TLS features"


def test_all_six_threat_classes_are_covered():
    got = {cls.threat_class for cls in ALL_HEADS}
    assert got == set(CLASSES), f"missing or extra heads: {got ^ set(CLASSES)}"


def test_heads_train_on_all_features_by_default():
    """The correction from exp09: restricting training to the declared subset
    cost 0.461 mean AP. Default must be unrestricted."""
    X, Y = toy()
    for h in build_heads():
        assert h.restrict_features is False
        h.fit(X, Y[h.threat_class], FEATURES)
        assert len(h._cols) == len(FEATURES), \
            "default head should train on the full feature set"


def test_restrict_features_reproduces_the_starved_variant():
    X, Y = toy()
    for h in build_heads(restrict_features=True):
        h.fit(X, Y[h.threat_class], FEATURES)
        assert h._cols == list(h.FEATURES)
        assert len(h._cols) < len(FEATURES)


def test_ensemble_can_fire_more_than_one_head_on_one_cell():
    """The structural claim a softmax cannot make. If this ever fails, the
    multi-label argument in base.py is gone."""
    X, Y = toy()
    # force two classes true on the same rows
    Y = dict(Y)
    Y["scan"] = Y["scan"].copy()
    Y["exfil"] = Y["scan"].copy()
    ens = HeadEnsemble(build_heads(), FEATURES).fit(X, Y)
    preds = ens.predict(X)
    both = np.logical_and(preds["scan"], preds["exfil"]).sum()
    assert both > 0, "no cell had two heads fire; multi-label output is not working"


def test_scores_are_probabilities():
    X, Y = toy()
    ens = HeadEnsemble(build_heads(), FEATURES).fit(X, Y)
    for c, p in ens.score(X).items():
        assert p.shape == (len(X),)
        assert (p >= 0).all() and (p <= 1).all(), f"{c} produced non-probabilities"


def test_fired_for_returns_every_head_sorted():
    X, Y = toy()
    ens = HeadEnsemble(build_heads(), FEATURES).fit(X, Y)
    scores = ens.fired_for(X, 0)
    assert len(scores) == len(ALL_HEADS)
    probs = [s.probability for s in scores]
    assert probs == sorted(probs, reverse=True)
    assert all(s.explain() for s in scores)


def test_declares_reflects_the_stated_mechanism():
    for h in build_heads():
        assert h.declares(h.FEATURES[0])
        assert not h.declares("not_a_real_feature")


def test_score_before_fit_is_an_error():
    h = build_heads()[0]
    with pytest.raises(RuntimeError):
        h.score(np.zeros((2, len(FEATURES)), dtype=np.float32), FEATURES)


def test_missing_labels_are_reported_not_silently_skipped():
    X, Y = toy()
    del Y["scan"]
    with pytest.raises(KeyError):
        HeadEnsemble(build_heads(), FEATURES).fit(X, Y)

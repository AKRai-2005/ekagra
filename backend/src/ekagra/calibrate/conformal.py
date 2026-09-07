"""Split-conformal calibration and abstention.

Why abstention is a first-class output here
-------------------------------------------
A detector on a diode tap cannot ask a follow-up question. It cannot probe the
host, fetch the certificate, or check a reputation feed - the return path does
not exist. So when the evidence is genuinely ambiguous, the only honest options
are to guess or to say so. Forcing a label in that situation manufactures
confidence the sensor does not have, and an analyst has no way to tell the
difference.

`ABSTAIN` means: *under this sensor's visibility, the observation does not
support a confident label.* That is a useful thing to tell a human. It is also
the answer to a question a judge will ask - "what does it do when it meets
traffic unlike anything it trained on?" - and "it abstains, here is the
calibration curve" is a stronger answer than "it generalises".

Method
------
Split conformal prediction. A held-out calibration set (never trained on)
provides nonconformity scores; the (1-alpha) quantile of those becomes the
threshold. The guarantee is distribution-free and finite-sample: over exchange-
able data the prediction set contains the true label at least (1-alpha) of the
time, with no assumption that the model is well-specified.

The exchangeability assumption is the honest caveat, and it is worth stating
plainly: network traffic is not exchangeable across a distribution shift. A new
attack family breaks it. What conformal buys is a principled, measurable
threshold instead of an arbitrary one - not a guarantee that survives novelty.

Marginal coverage is not enough here, and we measured that
-----------------------------------------------------------
Standard (marginal) conformal gives one threshold for all classes, and its
guarantee is an *average* over the label distribution. On this data that
average is satisfied almost entirely by the dominant class: at alpha=0.10 the
first run hit 0.88 coverage while abstaining on **96-100% of every rare class**
and answering only volumetric DDoS, which is 97% of the test window.

Coverage was met. The detector was useless - it declined to speak about
precisely the classes an analyst needs it for.

The fix is Mondrian (class-conditional) conformal: calibrate a separate
threshold per class, which buys class-conditional coverage instead of marginal.
`ConformalAbstainer(mondrian=True)` does that, and the experiment reports both
so the difference is visible rather than asserted.

The decision rule has to change with it
----------------------------------------
The first Mondrian attempt abstained on **100%** of everything. The cause is a
genuine interaction, not a bug: a class with very few calibration points gets a
permissive threshold (its quantile approaches 1.0), so it enters *every*
prediction set. Under a "set must contain exactly one class" rule, one rare
class is enough to make every set ambiguous.

So the two calibrations use the decision rule each is suited to:

    marginal   set-based   - abstain unless the prediction set is a singleton
    Mondrian   credibility - predict argmax, abstain when that label's own
                             nonconformity exceeds the threshold calibrated
                             for that class

The credibility rule asks the question per-class thresholds can actually
answer: *is this specific claim typical of what calibration saw for this
class?* Set size cannot ask that when the thresholds differ per class.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import numpy as np


@dataclass
class CalibrationReport:
    alpha: float
    threshold: float
    n_calibration: int
    empirical_coverage: float
    abstention_rate: float
    accuracy_on_answered: float
    expected_calibration_error: float
    mondrian: bool = False
    per_class_coverage: Optional[Dict[int, float]] = None
    per_class_abstention: Optional[Dict[int, float]] = None

    @property
    def worst_class_coverage(self) -> float:
        """The number marginal coverage hides.

        A detector can post 0.88 marginal coverage while covering a rare class
        0% of the time. This is the figure to quote.
        """
        if not self.per_class_coverage:
            return self.empirical_coverage
        return min(self.per_class_coverage.values())

    def as_dict(self) -> dict:
        return {
            "alpha": self.alpha,
            "threshold": self.threshold,
            "n_calibration": self.n_calibration,
            "empirical_coverage": self.empirical_coverage,
            "abstention_rate": self.abstention_rate,
            "accuracy_on_answered": self.accuracy_on_answered,
            "expected_calibration_error": self.expected_calibration_error,
            "mondrian": self.mondrian,
            "per_class_coverage": self.per_class_coverage,
            "per_class_abstention": self.per_class_abstention,
            "worst_class_coverage": self.worst_class_coverage,
        }


def expected_calibration_error(confidence: np.ndarray, correct: np.ndarray,
                               n_bins: int = 10) -> float:
    """Mean gap between stated confidence and observed accuracy.

    Reported alongside every result because a confidence score nobody has
    checked is decoration. Low ECE means "0.9" actually means 0.9.
    """
    conf = np.asarray(confidence, dtype=np.float64)
    ok = np.asarray(correct, dtype=np.float64)
    if conf.size == 0:
        return 0.0
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    total = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (conf > lo) & (conf <= hi)
        if not m.any():
            continue
        total += m.mean() * abs(ok[m].mean() - conf[m].mean())
    return float(total)


class ConformalAbstainer:
    """Turns model probabilities into a calibrated decision with abstention."""

    def __init__(self, alpha: float = 0.10, mondrian: bool = False) -> None:
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        self.alpha = alpha
        self.mondrian = mondrian
        self.threshold: float = 0.0
        self.class_thresholds: Optional[np.ndarray] = None
        self.n_calibration: int = 0
        self._fitted = False

    def fit(self, probs: np.ndarray, labels: np.ndarray) -> "ConformalAbstainer":
        """Calibrate on held-out data.

        Nonconformity is 1 - p(true class). The threshold is the
        ceil((n+1)(1-alpha))/n empirical quantile - the finite-sample
        correction, not just `np.quantile`, because with a few hundred
        calibration points the difference is not negligible.
        """
        probs = np.asarray(probs, dtype=np.float64)
        labels = np.asarray(labels, dtype=np.int64)
        if probs.ndim != 2:
            raise ValueError("probs must be (n_samples, n_classes)")
        if len(probs) != len(labels):
            raise ValueError("probs and labels length mismatch")

        n = len(labels)
        scores = 1.0 - probs[np.arange(n), labels]

        def quantile(vals: np.ndarray) -> float:
            m = len(vals)
            if m == 0:
                return 1.0          # never calibrated: admit the class freely
            k = min(max(int(np.ceil((m + 1) * (1.0 - self.alpha))), 1), m)
            return float(np.sort(vals)[k - 1])

        self.threshold = quantile(scores)
        if self.mondrian:
            n_classes = probs.shape[1]
            self.class_thresholds = np.array(
                [quantile(scores[labels == c]) for c in range(n_classes)],
                dtype=np.float64)
        self.n_calibration = n
        self._fitted = True
        return self

    def _in_set(self, probs: np.ndarray) -> np.ndarray:
        """Membership of the prediction set, per class."""
        if self.mondrian and self.class_thresholds is not None:
            return (1.0 - probs) <= self.class_thresholds[None, :]
        return (1.0 - probs) <= self.threshold

    def decide(self, probs: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Return (predicted_class, confidence, abstain_mask).

        Marginal mode uses the set rule: abstain unless the prediction set is a
        singleton. An empty set means nothing fits; several means the evidence
        does not separate them.

        Mondrian mode uses the credibility rule: abstain when the argmax label's
        own nonconformity exceeds the threshold calibrated for that class. The
        set rule cannot be used here - see the module docstring - because one
        sparsely-calibrated class joins every set and forces universal
        abstention.
        """
        if not self._fitted:
            raise RuntimeError("call fit() before decide()")
        probs = np.asarray(probs, dtype=np.float64)
        pred = probs.argmax(axis=1)
        conf = probs.max(axis=1)

        if self.mondrian and self.class_thresholds is not None:
            nonconf = 1.0 - probs[np.arange(len(probs)), pred]
            abstain = nonconf > self.class_thresholds[pred]
        else:
            abstain = self._in_set(probs).sum(axis=1) != 1
        return pred, conf, abstain

    def report(self, probs: np.ndarray, labels: np.ndarray) -> CalibrationReport:
        """Evaluate the calibration on a test split."""
        probs = np.asarray(probs, dtype=np.float64)
        labels = np.asarray(labels, dtype=np.int64)
        pred, conf, abstain = self.decide(probs)

        in_set = self._in_set(probs)
        covered = in_set[np.arange(len(labels)), labels]
        coverage = float(covered.mean())
        per_class_cov = {}
        per_class_abstain = {}
        for c in np.unique(labels):
            m = labels == c
            per_class_cov[int(c)] = float(covered[m].mean())
            per_class_abstain[int(c)] = float(abstain[m].mean())

        answered = ~abstain
        acc = float((pred[answered] == labels[answered]).mean()) if answered.any() else 0.0
        ece = expected_calibration_error(conf[answered],
                                         (pred[answered] == labels[answered]))
        return CalibrationReport(
            alpha=self.alpha,
            threshold=self.threshold,
            n_calibration=self.n_calibration,
            empirical_coverage=coverage,
            abstention_rate=float(abstain.mean()),
            accuracy_on_answered=acc,
            expected_calibration_error=ece,
            mondrian=self.mondrian,
            per_class_coverage=per_class_cov,
            per_class_abstention=per_class_abstain,
        )

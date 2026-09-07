"""Detector heads: one independent binary detector per threat class.

Why heads instead of one multiclass model
------------------------------------------
Every experiment up to now used a single XGBoost softmax over all classes. That
was expedient and it is wrong for this problem in four specific ways:

1. **A softmax forces mutual exclusivity.** A host cannot be simultaneously
   scanning and exfiltrating under a single-label model, because the
   probabilities are constrained to sum to one. Operationally a host absolutely
   can do both - a foothold scans, then ships data out - and that is precisely
   the sequence an analyst most wants flagged. Independent binary heads can say
   "yes" twice. `exp09` measures how often that matters on this data rather
   than asserting it.

2. **The classes are not the same kind of phenomenon.** A volumetric flood is a
   destination-side rate-and-dispersion signal. Beaconing is a periodicity
   signal on the source. Scanning is fan-out cardinality. Pooling them into one
   feature space makes them compete for model capacity and forces one decision
   boundary to serve six different geometries.

3. **Per-class operating points.** An analyst tolerates a different alert rate
   for "possible exfiltration" than for "port scan". A softmax has one
   threshold; heads have six. This is the same lesson the Mondrian calibration
   result taught - a single global threshold serves the dominant class and
   abandons the rest.

4. **Independent retraining.** A new DGA family needs the DGA head refitted,
   not the whole detector revalidated.

What exp09 did to the argument above
-------------------------------------
Two of those four reasons survived measurement and two did not. The numbers are
in `results/exp09_verdicts.json`; the summary is:

  reason 1 (multi-label)   **holds structurally, marginal in practice.** Heads
      recover 83% of true labels on co-occurring cells against the softmax's
      48% - and the softmax is capped near 50% by construction, so that gap is
      real. But co-occurrence is only **0.08%** of attack cells in this data,
      so the capability rarely gets used here.

  reason 2 (different geometries)  **refuted as stated.** Independent heads on
      the full feature set score mean AP 0.870 against the multiclass model's
      0.858 - a difference of +0.012, which is noise. Decomposition neither
      helps nor hurts detection quality.

  reasons 3 and 4 (per-class thresholds, independent retraining) stand: they
      are operational properties, not accuracy claims, and exp09 did not test
      them.

The feature-subset mistake, which was mine
-------------------------------------------
Each head originally *trained* on its declared feature subset. That cost
**0.461 mean AP** against the same heads trained on everything - by far the
largest effect in the experiment, and entirely self-inflicted. The subsets were
a statement about mechanism ("fan-out replaces RST-rate"), and turning a
statement about mechanism into a hard constraint on the model starved it.

So `FEATURES` is now **documentation and an explanation aid**, not a training
restriction. Heads train on everything by default; `restrict_features=True`
reproduces the starved variant, because the finding is worth keeping runnable.

The "handicapped heads" claim was also wrong
---------------------------------------------
`DgaHead` and `EncryptedHead` were marked as structurally handicapped, on the
grounds that query-name entropy and TLS-fingerprint rarity are absent from the
host-window feature set. Given the full feature set they reach AP 0.898 and
0.947 - **better than scan (0.756) and exfil (0.733)**. The behavioural shadow
in flow statistics turns out to be enough on this data. The `HANDICAPPED` note
is kept because the missing signal is a real architectural gap, but the
prediction that it would show up as poor performance did not survive.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

import numpy as np


@dataclass
class HeadScore:
    """One head's opinion about one (window, host) cell."""

    head: str
    threat_class: str
    probability: float
    fired: bool
    top_features: List[tuple]      # [(name, value, gain), ...]

    def explain(self) -> str:
        if not self.top_features:
            return f"{self.head}: p={self.probability:.3f}"
        bits = ", ".join(f"{n}={v:.3g}" for n, v, _ in self.top_features[:3])
        return f"{self.head}: p={self.probability:.3f} driven by {bits}"


class DetectorHead(ABC):
    """A binary detector for one threat class, over a declared feature subset."""

    name: str = "head"
    threat_class: str = "unknown"
    #: Features this head is permitted to use. Declared, not learned.
    FEATURES: Sequence[str] = ()
    #: One line on why those features and not others - shown in the console.
    RATIONALE: str = ""
    #: Set when the discriminative signal is known to be absent from FEATURES.
    HANDICAPPED: Optional[str] = None

    def __init__(self, threshold: float = 0.5,
                 restrict_features: bool = False) -> None:
        """
        `restrict_features=True` trains only on `FEATURES`. That is the variant
        exp09 measured as costing 0.461 mean AP, and it is retained so the
        result stays reproducible - not because it is a good idea.
        """
        self.threshold = threshold
        self.restrict_features = restrict_features
        self._model = None
        self._cols: List[str] = list(self.FEATURES) if restrict_features else []
        self._gain: Dict[str, float] = {}

    # ------------------------------------------------------------------ data
    def select(self, X: np.ndarray, all_features: Sequence[str]) -> np.ndarray:
        """Project the full feature matrix onto this head's subset."""
        idx = [list(all_features).index(f) for f in self._cols]
        return X[:, idx]

    # ------------------------------------------------------------------ model
    @abstractmethod
    def _build(self):
        """Return an unfitted estimator. Heads differ in what suits them."""

    def fit(self, X: np.ndarray, y_binary: np.ndarray,
            all_features: Sequence[str]) -> "DetectorHead":
        if not self.restrict_features:
            self._cols = list(all_features)
        Xs = self.select(X, all_features)
        self._model = self._build()
        self._model.fit(Xs, y_binary.astype(int))
        try:
            raw = self._model.get_booster().get_score(importance_type="gain")
            self._gain = {self._cols[int(k[1:])]: v for k, v in raw.items()
                          if k[1:].isdigit() and int(k[1:]) < len(self._cols)}
        except Exception:
            self._gain = {}
        return self

    def score(self, X: np.ndarray, all_features: Sequence[str]) -> np.ndarray:
        if self._model is None:
            raise RuntimeError(f"{self.name}: fit() before score()")
        return self._model.predict_proba(self.select(X, all_features))[:, 1]

    # ---------------------------------------------------------------- explain
    def declares(self, feature: str) -> bool:
        """Is this feature part of the head's stated mechanism?

        Used to check that a head relies on what its rationale claims. A head
        scoring well on features unrelated to its stated mechanism is a warning
        even when the score is good.
        """
        return feature in self.FEATURES

    def top_features(self, row: np.ndarray, all_features: Sequence[str],
                     k: int = 3) -> List[tuple]:
        """The head's highest-gain features, with this cell's values.

        Gain is global to the head, not per-row attribution - it says what the
        head relies on, not what drove this particular decision. That
        distinction is stated because conflating them is a common way to
        overclaim explainability.
        """
        vals = self.select(row.reshape(1, -1), all_features)[0]
        ranked = sorted(zip(self._cols, vals, (self._gain.get(c, 0.0) for c in self._cols)),
                        key=lambda t: -t[2])
        return [(n, float(v), float(g)) for n, v, g in ranked[:k]]

    def decide(self, X: np.ndarray, all_features: Sequence[str]) -> List[HeadScore]:
        probs = self.score(X, all_features)
        return [
            HeadScore(self.name, self.threat_class, float(p), bool(p >= self.threshold),
                      self.top_features(X[i], all_features))
            for i, p in enumerate(probs)
        ]

    def __repr__(self) -> str:
        mode = "declared subset" if self.restrict_features else "all features"
        return (f"<{self.name} -> {self.threat_class}, {len(self._cols)} "
                f"features ({mode})>")


class HeadEnsemble:
    """All six heads, scored independently and reported as a multi-label result."""

    def __init__(self, heads: Sequence[DetectorHead], all_features: Sequence[str]) -> None:
        self.heads = list(heads)
        self.all_features = list(all_features)

    def fit(self, X: np.ndarray, Y: Dict[str, np.ndarray]) -> "HeadEnsemble":
        """`Y` maps threat_class -> binary label vector (multi-label, not one-hot)."""
        for h in self.heads:
            if h.threat_class not in Y:
                raise KeyError(f"no labels for {h.threat_class}")
            h.fit(X, Y[h.threat_class], self.all_features)
        return self

    def score(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        return {h.threat_class: h.score(X, self.all_features) for h in self.heads}

    def predict(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        return {h.threat_class: (h.score(X, self.all_features) >= h.threshold)
                for h in self.heads}

    def fired_for(self, X: np.ndarray, i: int) -> List[HeadScore]:
        """Every head's opinion on one cell - the multi-label view."""
        row = X[i]
        out = []
        for h in self.heads:
            p = float(h.score(row.reshape(1, -1), self.all_features)[0])
            out.append(HeadScore(h.name, h.threat_class, p, p >= h.threshold,
                                 h.top_features(row, self.all_features)))
        return sorted(out, key=lambda s: -s.probability)

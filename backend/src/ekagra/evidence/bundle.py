"""Tamper-evident evidence bundles.

Why an alert needs one
----------------------
The problem statement says the diode enclave "preserves a clean chain of custody
for forensic use" and that the output is "labelled alerts, confidence scores,
and supporting evidence". A score on a dashboard is not supporting evidence. An
analyst acting on an alert - and later, anyone auditing that action - needs to
be able to ask three questions and get answers:

    What exactly did the sensor observe?      window, host, contributing flows
    What did the model do with it?            feature vector, model hash, decision
    Has any of this been altered since?       hash chain

The third is the one that is normally missing. An append-only log whose entries
each commit to the previous entry's digest makes deletion, reordering and
in-place edits all detectable, because every downstream digest changes.

Integrity vs authenticity - the distinction we do not blur
-----------------------------------------------------------
A bare hash chain proves **integrity relative to an anchor**: given a digest you
trust, you can tell whether the log leading to it was altered. It proves nothing
about *who* wrote it - anyone who rewrites the whole chain produces a valid one.

So each bundle also carries an HMAC-SHA256 over its canonical form, keyed by a
secret the enclave holds. Without that key an attacker with write access can
still corrupt the log, but cannot forge entries that verify. Key custody is a
deployment concern (HSM, sealed storage) and is explicitly **out of scope here**
- `EvidenceLog` takes a key and does not attempt to protect it.

Canonical form
--------------
Digests are only meaningful if two implementations agree on the bytes being
hashed. JSON is a poor canonical form across languages: key order, float
formatting and unicode escaping all vary. So the canonical form here is a fixed
field order joined by US-separator (0x1F), with every float rendered at fixed
precision. The browser console re-derives the same string in JavaScript and
recomputes the chain independently - which is the point of shipping a
verification path at all.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# Imported from the module rather than the package to keep this a leaf
# dependency - `detect/__init__` pulls in the heads, which this does not need.
from ..detect.severity import severity as compute_severity

SEP = "\x1f"
GENESIS = "0" * 64
FLOAT_FMT = "{:.6f}"

# Bundle fields in the exact order they are hashed. Changing this order, or
# adding a field anywhere but the end, invalidates every previously written
# log - so it is written down once, here, rather than implied by a dataclass.
CANONICAL_FIELDS: Tuple[str, ...] = (
    "seq", "alert_id", "ts", "window", "host", "threat_class",
    "score", "confidence", "decision", "model_hash", "feature_hash", "prev_hash",
)


def _norm_float(x: float) -> float:
    """Normalise values that two languages render differently.

    Negative zero is the one that actually bit us: Python formats -0.0 as
    "-0.000000" while JavaScript's toFixed(6) gives "0.000000", so a feature
    vector containing -0.0 - which a Shannon entropy of exactly zero produces,
    since -(0.0) is -0.0 - hashed to different digests in the sensor and in the
    browser verifier. The console reported tampering that had not happened.

    Non-finite values are normalised too: Python renders inf as "inf" and
    JavaScript as "Infinity". Features are inf-cleaned upstream, so this is
    defence in depth rather than an expected path.
    """
    x = float(x)
    if x != x or x in (float("inf"), float("-inf")):
        return 0.0
    return x + 0.0            # turns -0.0 into 0.0, leaves everything else


def _fmt(value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, float):
        return FLOAT_FMT.format(_norm_float(value))
    return str(value)


def canonical_features(features: Dict[str, float]) -> str:
    """Deterministic rendering of a feature vector.

    Sorted by name so dict insertion order cannot change the digest, and values
    at fixed precision so a float repr difference between Python and JavaScript
    cannot either.
    """
    return SEP.join(f"{k}={FLOAT_FMT.format(_norm_float(v))}"
                    for k, v in sorted(features.items()))


def feature_digest(features: Dict[str, float]) -> str:
    return hashlib.sha256(canonical_features(features).encode("utf-8")).hexdigest()


@dataclass
class EvidenceBundle:
    """One alert, with everything needed to re-examine or re-run it."""

    seq: int
    alert_id: str
    ts: float
    window: int
    host: str
    threat_class: str
    score: float
    confidence: float
    decision: str                  # ALERT | ABSTAIN
    model_hash: str
    feature_hash: str
    prev_hash: str

    # Carried but not hashed directly - the feature digest already commits to
    # the vector, and packet references are pointers into the capture rather
    # than content.
    features: Dict[str, float] = field(default_factory=dict)
    observed: Dict[str, object] = field(default_factory=dict)
    decision_path: List[str] = field(default_factory=list)

    # Severity is derived, not recorded: it is a pure function of
    # `threat_class` and `features`, both of which the digest above already
    # commits to. Hashing it would add a field that can never disagree with
    # the chain, and would invalidate every log written before it existed.
    severity: str = "info"
    severity_score: float = 0.0

    entry_hash: str = ""
    hmac: str = ""

    def canonical(self) -> str:
        return SEP.join(_fmt(getattr(self, f)) for f in CANONICAL_FIELDS)

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def compute_hmac(self, key: bytes) -> str:
        return hmac.new(key, self.canonical().encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceLog:
    """Append-only, hash-chained alert log."""

    def __init__(self, key: bytes = b"", model_hash: str = "") -> None:
        self.key = key
        self.model_hash = model_hash
        self.bundles: List[EvidenceBundle] = []

    @property
    def head(self) -> str:
        return self.bundles[-1].entry_hash if self.bundles else GENESIS

    def append(self, *, alert_id: str, ts: float, window: int, host: str,
               threat_class: str, score: float, confidence: float,
               decision: str, features: Dict[str, float],
               observed: Optional[Dict[str, object]] = None,
               decision_path: Optional[Sequence[str]] = None) -> EvidenceBundle:
        b = EvidenceBundle(
            seq=len(self.bundles),
            alert_id=alert_id,
            ts=float(ts),
            window=int(window),
            host=host,
            threat_class=threat_class,
            score=float(score),
            confidence=float(confidence),
            decision=decision,
            model_hash=self.model_hash,
            feature_hash=feature_digest(features),
            prev_hash=self.head,
            features={k: float(v) for k, v in features.items()},
            observed=dict(observed or {}),
            decision_path=list(decision_path or []),
        )
        sev = compute_severity(threat_class, b.features)
        b.severity, b.severity_score = sev.level, sev.score
        b.entry_hash = b.compute_hash()
        if self.key:
            b.hmac = b.compute_hmac(self.key)
        self.bundles.append(b)
        return b

    # ------------------------------------------------------------------ verify
    def verify(self, key: Optional[bytes] = None) -> List[str]:
        """Re-derive the chain. Returns a list of problems; empty means intact.

        Checks each entry's own digest, its link to the previous entry, the
        feature digest against the carried vector, and - when a key is supplied
        - the HMAC. Reordering and deletion surface as broken links; in-place
        edits surface as a digest mismatch on that entry and every one after it.
        """
        problems: List[str] = []
        key = self.key if key is None else key
        prev = GENESIS
        for b in self.bundles:
            if b.prev_hash != prev:
                problems.append(
                    f"seq {b.seq}: broken link (prev_hash {b.prev_hash[:12]}..., "
                    f"expected {prev[:12]}...)")
            recomputed = b.compute_hash()
            if recomputed != b.entry_hash:
                problems.append(
                    f"seq {b.seq}: entry altered (hash {b.entry_hash[:12]}..., "
                    f"recomputed {recomputed[:12]}...)")
            if b.features and feature_digest(b.features) != b.feature_hash:
                problems.append(f"seq {b.seq}: feature vector does not match its digest")
            if key and b.hmac:
                if not hmac.compare_digest(b.compute_hmac(key), b.hmac):
                    problems.append(f"seq {b.seq}: HMAC does not verify")
            # Carry the RECOMPUTED digest forward, not the stored one. Using the
            # stored value would let a single edited entry pass its damage no
            # further than itself: the next entry still links to the old hash and
            # verifies happily. Propagating the recomputation is what makes one
            # tampered record invalidate the whole tail, which is the property
            # this class exists to provide.
            prev = recomputed
        return problems

    # ------------------------------------------------------------------- io
    def write_jsonl(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for b in self.bundles:
                fh.write(json.dumps(b.to_dict(), sort_keys=True) + "\n")

    @classmethod
    def read_jsonl(cls, path: Path, key: bytes = b"") -> "EvidenceLog":
        log = cls(key=key)
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            log.bundles.append(EvidenceBundle(**json.loads(line)))
        if log.bundles:
            log.model_hash = log.bundles[0].model_hash
        return log

    def summary(self) -> dict:
        alerts = [b for b in self.bundles if b.decision == "ALERT"]
        abstains = [b for b in self.bundles if b.decision == "ABSTAIN"]
        by_class: Dict[str, int] = {}
        for b in alerts:
            by_class[b.threat_class] = by_class.get(b.threat_class, 0) + 1
        return {
            "entries": len(self.bundles),
            "alerts": len(alerts),
            "abstentions": len(abstains),
            "by_class": by_class,
            "head": self.head,
            "model_hash": self.model_hash,
        }


def model_digest(*parts: object) -> str:
    """Stable identifier for the scoring configuration.

    Hashes whatever identifies the model - feature names, hyperparameters,
    training corpus - so an alert can be tied to the exact configuration that
    produced it. Two runs with different features get different digests, which
    is what makes `model_hash` in a bundle worth anything.
    """
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode("utf-8"))
        h.update(SEP.encode("utf-8"))
    return h.hexdigest()

"""Feature extraction — two deliberately separate designs.

The unit of classification is a **(window, host)** record: everything observed
about one endpoint during one time window. This granularity supports all six
PS threat classes without contortion — scans and exfiltration are source-side
phenomena, volumetric floods are destination-side, and beaconing is a property
of a source/destination pair that shows up in the source's window.

Two feature sets are built from the same stream:

`BidirectionalFeatures`
    Reproduces the conventional published feature set — forward *and* reverse
    byte/packet counts, response ratios, half-open detection — plus active
    enrichment (IP reputation, domain age, ASN risk). This is what a team
    working from the literature will build.

`UnidirectionalFeatures`
    Designed under the assumption that reverse-direction packets and all active
    enrichment may be unavailable. Replaces each lost signal with a forward-side
    statistic: source dispersion, fan-out cardinality, TTL diversity, arrival
    periodicity, name entropy, per-host decayed baselines.

Both are computed under whichever `VisibilityProfile` is active. The experiment
is what happens to each as the profile degrades.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

import numpy as np
import pandas as pd

from ..ingest.records import ACK, FIN, FORWARD, PSH, RST, SYN, Packet
from ..ingest.visibility import VisibilityProfile
from .sketches import (CountMinSketch, DecayedCounter, HyperLogLog, shannon_entropy,
                       stable_hash)

WINDOW_S = 10.0

# Per-window per-host cap on retained samples. Streaming pipelines cannot keep
# unbounded per-key history; 512 is ample for the statistics we compute and
# makes worst-case memory explicit rather than emergent.
_SAMPLE_CAP = 512


class EnrichmentOracle:
    """Models an external threat-intelligence / reputation service.

    This is the capability a diode enclave **does not have**. Every lookup here
    would, in a real pipeline, be an outbound API call — to VirusTotal,
    AbuseIPDB, a WHOIS service, or a passive-DNS provider.

    Coverage is deliberately imperfect. A feed that flagged every malicious IP
    would make the enrichment ablation look far more dramatic than reality.
    Published measurements of commercial IP-reputation coverage vary widely;
    we use 55% recall with a 3% false-positive rate, which is within the range
    commonly reported and, importantly, is a parameter we state rather than
    hide. `experiments/exp01_ablation.py` reports sensitivity to it.
    """

    def __init__(self, malicious_ips: set[str], seed: int = 99,
                 recall: float = 0.55, fpr: float = 0.03) -> None:
        self._malicious = frozenset(malicious_ips)
        self._seed = seed
        self._recall = recall
        self._fpr = fpr

    def _uniforms(self, ip: str) -> tuple[float, float]:
        """Two independent uniforms derived deterministically from the IP.

        Deriving these from a hash rather than drawing from a shared RNG is a
        correctness fix, not a style choice: with a shared RNG, whether a given
        IP got flagged depended on *the order it was first queried in*, which
        varies with set-iteration order and made the whole experiment
        irreproducible across processes.

        A reputation feed's answer for an IP must be a function of the IP.
        """
        h1 = stable_hash(f"{self._seed}:{ip}:a")
        h2 = stable_hash(f"{self._seed}:{ip}:b")
        return ((h1 & 0xFFFFFFFF) / 0xFFFFFFFF, (h2 & 0xFFFFFFFF) / 0xFFFFFFFF)

    def reputation(self, ip: str) -> float:
        u_draw, u_val = self._uniforms(ip)
        if ip in self._malicious:
            return 0.6 + 0.4 * u_val if u_draw < self._recall else 0.0
        return 0.5 + 0.4 * u_val if u_draw < self._fpr else 0.0


@dataclass
class _HostWindow:
    """Accumulator for one (window, host) cell."""

    host: str
    window: int

    # Direction-of-flow counters. Under a one-way profile the bwd_* fields
    # stay at zero, which is precisely the degradation we want to measure.
    fwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_pkts: int = 0
    bwd_bytes: int = 0

    # Role counters, independent of flow direction.
    out_pkts: int = 0
    out_bytes: int = 0
    in_pkts: int = 0
    in_bytes: int = 0

    syn: int = 0
    ack: int = 0
    rst: int = 0
    fin: int = 0
    psh: int = 0

    peers_hll: HyperLogLog = field(default_factory=lambda: HyperLogLog(10))
    dports_hll: HyperLogLog = field(default_factory=lambda: HyperLogLog(10))
    src_cms: CountMinSketch = field(default_factory=lambda: CountMinSketch(512, 3))

    ttls: set = field(default_factory=set)
    peer_counts: dict = field(default_factory=lambda: defaultdict(int))
    ts_samples: List[float] = field(default_factory=list)
    size_samples: List[int] = field(default_factory=list)
    qnames: List[str] = field(default_factory=list)
    tls_fps: List[str] = field(default_factory=list)
    peers_seen: set = field(default_factory=set)
    label_counts: dict = field(default_factory=lambda: defaultdict(int))

    def observe(self, pkt: Packet, as_source: bool) -> None:
        if pkt.direction == FORWARD:
            self.fwd_pkts += 1
            self.fwd_bytes += pkt.size
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += pkt.size

        if as_source:
            self.out_pkts += 1
            self.out_bytes += pkt.size
            peer = pkt.dst_ip
            self.dports_hll.add(pkt.dst_port)
        else:
            self.in_pkts += 1
            self.in_bytes += pkt.size
            peer = pkt.src_ip
            self.src_cms.add(pkt.src_ip)

        self.peers_hll.add(peer)
        if len(self.peers_seen) < 4096:
            self.peers_seen.add(peer)
        # Bounded, like every other per-key structure here. An unbounded dict
        # under a spoofed-source flood is exactly the memory blow-up a
        # streaming design exists to avoid.
        if peer in self.peer_counts or len(self.peer_counts) < 2048:
            self.peer_counts[peer] += 1
        if len(self.ttls) < 64:
            self.ttls.add(pkt.ttl)

        f = pkt.flags
        self.syn += bool(f & SYN)
        self.ack += bool(f & ACK)
        self.rst += bool(f & RST)
        self.fin += bool(f & FIN)
        self.psh += bool(f & PSH)

        if len(self.ts_samples) < _SAMPLE_CAP:
            self.ts_samples.append(pkt.ts)
            self.size_samples.append(pkt.size)
        if pkt.dns_qname and len(self.qnames) < _SAMPLE_CAP:
            self.qnames.append(pkt.dns_qname)
        if pkt.tls_fp and len(self.tls_fps) < _SAMPLE_CAP:
            self.tls_fps.append(pkt.tls_fp)

        self.label_counts[pkt.label] += 1

    @property
    def label(self) -> str:
        """Majority non-benign label, else benign.

        A window is called malicious if any attack traffic is present, because
        an analyst would want the alert. Using a majority vote over *all*
        labels would let a low-rate beacon hide inside a busy host's window.
        """
        attack = {k: v for k, v in self.label_counts.items() if k != "benign"}
        if not attack:
            return "benign"
        return max(attack.items(), key=lambda kv: kv[1])[0]


def _cv(values: List[float]) -> float:
    """Coefficient of variation. Low CV of inter-arrivals => periodic."""
    if len(values) < 3:
        return 0.0
    a = np.asarray(values, dtype=np.float64)
    m = a.mean()
    return float(a.std() / m) if m > 1e-9 else 0.0


def _iats(ts: List[float]) -> List[float]:
    if len(ts) < 2:
        return []
    a = np.sort(np.asarray(ts, dtype=np.float64))
    return list(np.diff(a))


class FeatureBuilder:
    """Builds both feature sets in a single pass over the stream."""

    def __init__(self, profile: VisibilityProfile,
                 oracle: Optional[EnrichmentOracle] = None,
                 window_s: float = WINDOW_S,
                 monitored_prefix: str | None = "10.20.") -> None:
        """
        `monitored_prefix` scopes which endpoints become scored entities.

        This is not an optimisation, it is a correctness fix. Scoring *every*
        IP seen creates one entity per spoofed source during a flood — hundreds
        of thousands of single-packet "hosts" that no operator would ever
        defend, and which swamp the label distribution.

        A real deployment scores the assets it protects. External peers still
        contribute fully to a monitored host's features through the sketches;
        they simply are not rows themselves. Set to None to score everything.
        """
        self.profile = profile
        self.oracle = oracle
        self.window_s = window_s
        self.monitored_prefix = monitored_prefix
        self._cells: dict[tuple[int, str], _HostWindow] = {}
        self._host_baseline: dict[str, DecayedCounter] = defaultdict(
            lambda: DecayedCounter(half_life=300.0))
        self._fp_global: dict[str, int] = defaultdict(int)

    def consume(self, packets: Iterable[Packet]) -> "FeatureBuilder":
        w = self.window_s
        prefix = self.monitored_prefix
        cells = self._cells
        for pkt in packets:
            widx = int(pkt.ts // w)
            for host, as_src in ((pkt.src_ip, True), (pkt.dst_ip, False)):
                if prefix is not None and not host.startswith(prefix):
                    continue
                key = (widx, host)
                cell = cells.get(key)
                if cell is None:
                    cell = _HostWindow(host=host, window=widx)
                    cells[key] = cell
                cell.observe(pkt, as_source=as_src)
            self._host_baseline[pkt.src_ip].add(pkt.ts, pkt.size)
            if pkt.tls_fp:
                self._fp_global[pkt.tls_fp] += 1
        return self

    # ------------------------------------------------------------------ views
    def to_frame(self) -> pd.DataFrame:
        """Emit one row per (window, host) with **both** feature families.

        Columns are prefixed `bi_` and `uni_` so an experiment can select a
        feature family by prefix and there is no accidental leakage between
        the two designs.
        """
        total_fp = max(1, sum(self._fp_global.values()))
        rows = []
        # Explicit ordering. Row order reaches the model through XGBoost's
        # subsampling, so leaving it to dict insertion order would make results
        # depend on packet arrival order in ways that are hard to reason about.
        for (widx, host), c in sorted(self._cells.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            iats = _iats(c.ts_samples)
            sizes = np.asarray(c.size_samples, dtype=np.float64) if c.size_samples else np.zeros(1)
            n_peers = c.peers_hll.count()
            n_dports = c.dports_hll.count()
            top_peer_share = (max(c.peer_counts.values()) / sum(c.peer_counts.values())
                              if c.peer_counts else 0.0)

            qn_entropy = shannon_entropy(c.qnames) if c.qnames else 0.0
            qn_len = float(np.mean([len(q) for q in c.qnames])) if c.qnames else 0.0
            qn_max_label = float(max((max((len(p) for p in q.split(".")), default=0)
                                      for q in c.qnames), default=0))

            fp_rarity = 0.0
            if c.tls_fps:
                fp_rarity = float(np.mean([
                    1.0 - (self._fp_global.get(fp, 0) / total_fp) for fp in c.tls_fps]))

            baseline = self._host_baseline[host].value()
            out_vs_baseline = c.out_bytes / (baseline + 1.0)

            row = {
                "window": widx, "host": host, "label": c.label,

                # ---------------- bidirectional / published-convention set
                "bi_fwd_pkts": c.fwd_pkts,
                "bi_fwd_bytes": c.fwd_bytes,
                "bi_bwd_pkts": c.bwd_pkts,
                "bi_bwd_bytes": c.bwd_bytes,
                "bi_bwd_fwd_pkt_ratio": c.bwd_pkts / max(1, c.fwd_pkts),
                "bi_bwd_fwd_byte_ratio": c.bwd_bytes / max(1, c.fwd_bytes),
                "bi_out_in_byte_ratio": c.out_bytes / max(1, c.in_bytes),
                "bi_amplification": c.bwd_bytes / max(1, c.fwd_bytes),
                "bi_syn_without_ack": max(0, c.syn - c.ack) / max(1, c.syn),
                "bi_rst_rate": c.rst / max(1, c.fwd_pkts + c.bwd_pkts),
                "bi_fin_rate": c.fin / max(1, c.fwd_pkts + c.bwd_pkts),
                "bi_n_peers": n_peers,
                "bi_n_dports": n_dports,
                "bi_mean_size": float(sizes.mean()),
                "bi_std_size": float(sizes.std()),
                "bi_mean_iat": float(np.mean(iats)) if iats else 0.0,
                "bi_dns_count": len(c.qnames),
                "bi_dns_qname_len": qn_len,

                # --- direction-agnostic behavioural features, shared with the
                # native set by design.
                #
                # These are here so the baseline is *genuinely strong*. An
                # earlier version withheld name entropy and regularity
                # statistics from the bidirectional set, which made the native
                # set look better for a reason that had nothing to do with
                # visibility. That is exactly the kind of rigged comparison
                # this project exists to expose in other people's work, so the
                # baseline now gets every feature that does not require the
                # reverse channel.
                #
                # What remains bi-exclusive is only what genuinely needs the
                # return path: bwd_* counts, the ratios built from them,
                # half-open detection, RST/FIN rates, and enrichment.
                "bi_src_entropy": c.src_cms.entropy(),
                "bi_ttl_diversity": len(c.ttls),
                "bi_iat_cv": _cv(iats),
                "bi_size_cv": float(sizes.std() / sizes.mean()) if sizes.mean() > 0 else 0.0,
                "bi_qname_entropy": qn_entropy,
                "bi_qname_max_label": qn_max_label,
                "bi_dns_rate": len(c.qnames) / self.window_s,
                "bi_tls_fp_rarity": fp_rarity,
                "bi_peer_concentration": top_peer_share,
                "bi_fanout_per_pkt": n_peers / max(1, c.out_pkts),
                "bi_syn_rate": c.syn / self.window_s,
                "bi_out_vs_baseline": out_vs_baseline,
                "bi_out_pkts": c.out_pkts,
                "bi_out_bytes": c.out_bytes,
                "bi_in_pkts": c.in_pkts,
                "bi_in_bytes": c.in_bytes,

                # ---------------- unidirectional-native set
                "uni_fwd_pkts": c.fwd_pkts,
                "uni_fwd_bytes": c.fwd_bytes,
                "uni_out_pkts": c.out_pkts,
                "uni_out_bytes": c.out_bytes,
                "uni_in_pkts": c.in_pkts,
                "uni_in_bytes": c.in_bytes,
                # Source dispersion: replaces half-open detection for floods.
                "uni_src_entropy": c.src_cms.entropy(),
                "uni_src_total": c.src_cms.total,
                # Fan-out: replaces RST-rate for scan detection.
                "uni_n_peers": n_peers,
                "uni_n_dports": n_dports,
                "uni_peer_concentration": top_peer_share,
                "uni_fanout_per_pkt": n_peers / max(1, c.out_pkts),
                # TTL diversity: forward-side spoofing indicator. Genuine
                # signal that survives the loss of the return path.
                "uni_ttl_diversity": len(c.ttls),
                # Arrival regularity: replaces round-trip regularity for beacons.
                "uni_iat_cv": _cv(iats),
                "uni_iat_mean": float(np.mean(iats)) if iats else 0.0,
                "uni_iat_min": float(np.min(iats)) if iats else 0.0,
                # Size regularity: machine-generated traffic has low size CV.
                "uni_size_cv": float(sizes.std() / sizes.mean()) if sizes.mean() > 0 else 0.0,
                "uni_mean_size": float(sizes.mean()),
                # Name statistics: replaces NXDOMAIN rate for DGA/tunnelling.
                "uni_qname_entropy": qn_entropy,
                "uni_qname_len": qn_len,
                "uni_qname_max_label": qn_max_label,
                "uni_dns_rate": len(c.qnames) / self.window_s,
                # Fingerprint rarity: replaces server-side JA4S/certificate.
                "uni_tls_fp_rarity": fp_rarity,
                "uni_tls_count": len(c.tls_fps),
                # Per-host decayed baseline: replaces the out:in ratio for exfil.
                "uni_out_vs_baseline": out_vs_baseline,
                "uni_syn_rate": c.syn / self.window_s,
            }

            # ---------------- enrichment (available only above the diode rung)
            if self.profile.enrichment and self.oracle is not None:
                reps = [self.oracle.reputation(p) for p in c.peers_seen] or [0.0]
                row["bi_peer_rep_max"] = float(max(reps))
                row["bi_peer_rep_mean"] = float(np.mean(reps))
                row["bi_peer_rep_flagged"] = float(np.mean([r > 0.5 for r in reps]))
            else:
                row["bi_peer_rep_max"] = 0.0
                row["bi_peer_rep_mean"] = 0.0
                row["bi_peer_rep_flagged"] = 0.0

            rows.append(row)

        df = pd.DataFrame(rows)
        return df.replace([np.inf, -np.inf], 0.0).fillna(0.0)


def feature_columns(df: pd.DataFrame, family: str) -> List[str]:
    """Select a feature family by prefix: 'bi' or 'uni'."""
    if family not in ("bi", "uni"):
        raise ValueError("family must be 'bi' or 'uni'")
    return [c for c in df.columns if c.startswith(family + "_")]

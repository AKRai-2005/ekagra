"""The six detector heads named in the problem statement.

Each head's `FEATURES` list states the mechanism from `ARCHITECTURE.md` §4: the
forward-side statistic that replaces the reverse-channel signal a one-way tap
loses. It is **documentation and an explanation aid, not a training
restriction** - exp09 measured that training on the subset alone costs 0.461
mean AP, so heads train on the full feature set and `FEATURES` is used to check
that each head relies on what it claims to rely on.

Gradient-boosted trees throughout. On 16 tabular features with a few hundred
thousand rows they are the right tool, and using the same family across heads
keeps the comparison against the multiclass baseline about *decomposition*
rather than about model choice.
"""

from __future__ import annotations

from xgboost import XGBClassifier

from .base import DetectorHead

_COMMON = dict(n_estimators=180, max_depth=5, learning_rate=0.15,
               subsample=0.9, colsample_bytree=0.9, tree_method="hist",
               eval_metric="logloss", n_jobs=4, random_state=0)


class VolumetricHead(DetectorHead):
    """(a) Volumetric / protocol DDoS.

    A flood is a *destination-side* phenomenon: one victim, very many sources,
    each contributing almost nothing. The reverse-channel signal a bidirectional
    sensor would use is the SYN with no returning SYN-ACK - unobservable here.
    What survives is dispersion: source-IP entropy at the destination, and a
    flows-per-source ratio close to one.
    """

    name = "volumetric"
    threat_class = "ddos"
    RATIONALE = ("destination-side dispersion replaces half-open detection: "
                 "many sources, high source entropy, ~1 flow per source")
    FEATURES = ("hw_dst_n_flows", "hw_dst_n_srcs", "hw_dst_src_entropy",
                "hw_dst_fwd_pkts", "hw_dst_fwd_bytes", "hw_dst_flows_per_src")

    def _build(self):
        return XGBClassifier(**_COMMON)


class ScanHead(DetectorHead):
    """(e) Reconnaissance and port scanning.

    Fan-out cardinality replaces the RST-rate a bidirectional sensor would see
    from closed ports. A scanner is defined by touching many destinations or
    many ports while sending almost nothing to each.
    """

    name = "scan"
    threat_class = "scan"
    RATIONALE = ("source fan-out cardinality replaces RST-rate: many peers or "
                 "ports, minimal traffic per peer")
    FEATURES = ("hw_src_n_peers", "hw_src_n_dports", "hw_src_fanout_per_flow",
                "hw_src_n_flows", "hw_src_peer_concentration", "hw_src_fwd_pkts")

    def _build(self):
        return XGBClassifier(**_COMMON)


class BeaconHead(DetectorHead):
    """(b) Botnet C2 beaconing.

    Round-trip regularity is unavailable, so this head uses arrival regularity
    on the forward direction alone - a low coefficient of variation in flow
    inter-arrival times - combined with destination concentration.

    The hard part is not detecting periodicity, it is *benign* periodicity. NTP
    sync, telemetry heartbeats and health checks all beacon, and the traffic
    generator emits them deliberately for that reason. This head is expected to
    be the one with the most benign contamination.
    """

    name = "beacon"
    threat_class = "beacon"
    RATIONALE = ("forward-side arrival regularity plus destination "
                 "concentration replaces round-trip periodicity")
    FEATURES = ("hw_src_iat_cv", "hw_src_iat_mean", "hw_src_peer_concentration",
                "hw_src_n_peers", "hw_src_n_flows", "hw_src_fwd_bytes")

    def _build(self):
        return XGBClassifier(**_COMMON)


class ExfilHead(DetectorHead):
    """(f) Data exfiltration.

    The out:in byte ratio needs both directions. The forward-side substitute is
    absolute outbound volume measured against *this host's own* decayed
    baseline - which is why benign bulk downloads exist in the generator as the
    confuser, and why a per-host baseline rather than a global threshold is the
    only version of this that works.
    """

    name = "exfil"
    threat_class = "exfil"
    RATIONALE = ("outbound volume against a per-host causal baseline replaces "
                 "the out:in byte ratio")
    FEATURES = ("hw_src_fwd_bytes", "hw_src_bytes_vs_baseline",
                "hw_src_peer_concentration", "hw_src_n_peers",
                "hw_src_fwd_pkts", "hw_src_n_flows")

    def _build(self):
        return XGBClassifier(**_COMMON)


class DgaHead(DetectorHead):
    """(c) DGA domains and DNS tunnelling.

    Previously shipped knowingly handicapped: the discriminative signal is
    query-name entropy and the host-window set carried nothing about DNS, so
    this head saw only a flow-rate shadow of the behaviour.

    `features/protocol.py` now supplies the evidence the problem statement
    names - character entropy, query length, digit ratio and a causal bigram
    model for the "n-gram analysis" it asks for. On generated traffic these
    separate DGA cells from benign by 13x to 200x depending on the feature.

    **Only on the packet path.** Flow-record corpora such as CIC-IDS2017 carry
    no query names, so on those inputs the protocol block is zero and this head
    falls back to the same weak proxy it had before. That limit is a property
    of the corpus, not of the head.
    """

    name = "dga"
    threat_class = "dga"
    RATIONALE = ("query-name character entropy, length and bigram rarity, plus "
                 "the flow-rate shadow of DNS behaviour")
    HANDICAPPED = ("protocol features are packet-path only; on flow-record "
                   "corpora the DNS block is zero and this head degrades to a "
                   "flow-rate proxy")
    FEATURES = ("hw_src_qname_entropy", "hw_src_qname_len_mean",
                "hw_src_qname_len_max", "hw_src_qname_digit_ratio",
                "hw_src_qname_bigram_rarity", "hw_src_dns_count",
                "hw_src_n_flows", "hw_src_peer_concentration", "hw_src_n_peers",
                "hw_src_fwd_pkts", "hw_src_fwd_bytes", "hw_src_iat_mean")

    def _build(self):
        return XGBClassifier(**_COMMON)


class EncryptedHead(DetectorHead):
    """(d) Malware inside encrypted sessions - metadata only, never decrypted.

    Previously shipped knowingly handicapped. `features/protocol.py` now
    supplies client TLS fingerprint rarity and novelty, computed causally so a
    burst of unseen fingerprints cannot normalise itself. On generated traffic
    rarity separates malware cells from benign by about 20x.

    What is still missing, and named rather than implied: **packet-size and
    timing sequences**. The problem statement lists those beside fingerprints,
    and per-packet size sequences do not survive flow-level aggregation. The
    machine cadence in flow timing is the remaining proxy for them.

    Nothing here decrypts anything - a fingerprint is handshake metadata.
    """

    name = "encrypted"
    threat_class = "encrypted"
    RATIONALE = ("client TLS fingerprint rarity and novelty, plus the "
                 "machine-cadence shadow in flow timing")
    HANDICAPPED = ("packet-size sequences are still absent - they do not "
                   "survive flow aggregation; fingerprints are packet-path only")
    FEATURES = ("hw_src_tls_fp_rarity", "hw_src_tls_fp_novel", "hw_src_tls_count",
                "hw_src_iat_cv", "hw_src_iat_mean", "hw_src_fwd_bytes",
                "hw_src_n_peers", "hw_src_peer_concentration", "hw_src_n_flows")

    def _build(self):
        return XGBClassifier(**_COMMON)


ALL_HEADS = (VolumetricHead, ScanHead, BeaconHead, ExfilHead, DgaHead, EncryptedHead)


def build_heads(threshold: float = 0.5, restrict_features: bool = False):
    """One instance of each head.

    Thresholds are tuned per head downstream on a validation slice - a fixed
    0.5 cut on a class with 13 positives predicts all-negative, which is an F1
    of exactly zero regardless of how good the model is.

    `restrict_features=True` reproduces the starved variant from exp09.
    """
    return [cls(threshold=threshold, restrict_features=restrict_features)
            for cls in ALL_HEADS]

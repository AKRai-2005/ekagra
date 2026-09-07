"""Protocol-aware host-window features: DNS query names and TLS fingerprints.

Why this module exists separately
---------------------------------
Problem statement SIH26145 names six threat categories. Two of them are defined
by protocol evidence that the sixteen host-window aggregates deliberately do not
look at:

    (c) DGA domains and DNS tunnelling - "entropy and n-gram analysis of DNS
        query names, including anomalies in query length"
    (d) Malware in encrypted sessions - "JA3/JA3S or JA4 fingerprints,
        packet-size and timing patterns", without decryption

`host_window.py` is protocol-agnostic by design: it counts flows, peers, ports,
bytes and timing, and nothing above layer 4. That is what let it run unchanged
on CIC-IDS2017's flow records. The cost was that the DGA and encrypted-C2
detector heads were shipped **knowingly handicapped** - the features they
needed did not exist in the path that fed them.

This module supplies them, as a **separate feature group**.

Where the inputs come from
--------------------------
`Packet.dns_qname` and `Packet.tls_fp` are produced by `ingest/wire.py`, which
parses DNS messages and computes JA3 fingerprints from TLS ClientHellos, and by
`ingest/pcap.py`, which reads a real capture file and calls it. Until those
existed this module consumed fields our own generator invented, and the honest
description was "the right statistic over a source we do not derive". It now
runs on packet bytes.

Two things still hold. CIC-IDS2017 ships flow records with no query names and no
fingerprints, so on that corpus these nine features are legitimately zero - which
is why they remain a separate group. And there is no TCP reassembly, so a
ClientHello split across segments is not fingerprinted; `pcap.py` documents why.

Why separate rather than appended to the sixteen
------------------------------------------------
CIC-IDS2017 ships flow records with no query names and no TLS fingerprints, so
this evidence is only available on the packet path. Folding these into
`HOST_WINDOW_FEATURES` would change the feature vector every published result
in experiments 03, 04 and 05 was measured with, and would add nine
permanently-zero columns on the real corpus. Keeping them as their own group
means the flow-level results stand unchanged and the packet path gets strictly
more evidence.

Causality
---------
Both estimators are **score-then-learn**. A name is scored against the bigram
statistics of names seen *before* it, and a fingerprint's rarity is computed
from counts that exclude the current observation. Updating first would let a
DGA burst normalise itself - a beacon that queries a thousand novel domains
would make novel domains look common, and the feature would quietly go to zero
exactly when it mattered.

Bounded memory
--------------
The bigram table is 37x37 dense (lowercase alphanumerics, dot, other) - about
1,400 counters regardless of traffic. Fingerprint counts are capped and evicted
least-seen-first, so a spoofed flood of unique fingerprints cannot grow it
without limit.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List

# Emitted for the source side only: these describe what a host is *asking for*
# and *presenting*, which is an outbound-behaviour question. A one-way tap sees
# the client side of both, which is exactly the side that matters here.
PROTOCOL_FEATURES: List[str] = [
    # DNS - PS category (c)
    "hw_src_dns_count",
    "hw_src_qname_entropy",        # character Shannon entropy, the DGA signature
    "hw_src_qname_len_mean",
    "hw_src_qname_len_max",        # long labels are the tunnelling signature
    "hw_src_qname_digit_ratio",
    "hw_src_qname_bigram_rarity",  # the "n-gram analysis" the PS asks for
    # TLS - PS category (d)
    "hw_src_tls_count",
    "hw_src_tls_fp_rarity",
    "hw_src_tls_fp_novel",
]

_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789."
_IDX = {c: i for i, c in enumerate(_ALPHABET)}
_OTHER = len(_ALPHABET)
_N = _OTHER + 1


def _char_entropy(name: str) -> float:
    """Shannon entropy over the characters of one name.

    A DGA name like `x7f2qkzp9r.net` spreads its mass evenly; a real domain
    like `updates.microsoft.com` does not.
    """
    if not name:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in name:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(name)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _digit_ratio(name: str) -> float:
    if not name:
        return 0.0
    return sum(ch.isdigit() for ch in name) / len(name)


def _max_label(name: str) -> int:
    """Longest dot-separated label. DNS tunnelling stuffs data into one label."""
    return max((len(p) for p in name.split(".")), default=0)


class BigramModel:
    """Causal character-bigram model over observed query names.

    Scores a name by the mean surprisal of its bigrams under everything seen
    before it. Names built from transitions the network has never produced -
    which is what a DGA generates - score high.

    Dense 37x37 rather than a hash sketch: the alphabet is tiny and fixed, so
    exact counts cost about 1,400 integers and there is no collision to reason
    about.
    """

    def __init__(self, prior: float = 0.5) -> None:
        self.prior = prior
        self._counts = [[0] * _N for _ in range(_N)]
        self._row_totals = [0] * _N
        self.total = 0

    @staticmethod
    def _codes(name: str) -> List[int]:
        return [_IDX.get(ch, _OTHER) for ch in name.lower()]

    def score(self, name: str) -> float:
        """Mean negative log2 probability per bigram. Higher = more surprising."""
        codes = self._codes(name)
        if len(codes) < 2:
            return 0.0
        acc = 0.0
        for a, b in zip(codes, codes[1:]):
            num = self._counts[a][b] + self.prior
            den = self._row_totals[a] + self.prior * _N
            acc += -math.log2(num / den)
        return acc / (len(codes) - 1)

    def observe(self, name: str) -> None:
        codes = self._codes(name)
        for a, b in zip(codes, codes[1:]):
            self._counts[a][b] += 1
            self._row_totals[a] += 1
            self.total += 1


class FingerprintRarity:
    """Global TLS fingerprint frequency, with bounded memory.

    Rarity is `1 - count/total` computed *before* the current observation is
    counted, so a client presenting a fingerprint nobody has presented before
    scores 1.0 rather than diluting itself to zero.

    `max_entries` bounds the table; when it is full the least-seen entry is
    evicted, which is the right victim - a fingerprint seen once is the one we
    can most afford to forget, and evictions are counted rather than silent.
    """

    def __init__(self, max_entries: int = 20_000) -> None:
        self.max_entries = max_entries
        self._counts: "OrderedDict[str, int]" = OrderedDict()
        self.total = 0
        self.evicted = 0

    def rarity(self, fp: str) -> float:
        if self.total == 0:
            return 1.0
        return 1.0 - (self._counts.get(fp, 0) / self.total)

    def is_novel(self, fp: str) -> bool:
        return fp not in self._counts

    def observe(self, fp: str) -> None:
        if fp in self._counts:
            self._counts[fp] += 1
        else:
            if len(self._counts) >= self.max_entries:
                # Evict the least-seen entry, not the oldest: a rare
                # fingerprint carries less information than a common one.
                victim = min(self._counts, key=self._counts.get)
                del self._counts[victim]
                self.evicted += 1
            self._counts[fp] = 1
        self.total += 1


@dataclass
class ProtocolCell:
    """Per (host, window) accumulation of protocol evidence."""

    qnames: List[str] = field(default_factory=list)
    tls_fps: List[str] = field(default_factory=list)


class ProtocolProfiler:
    """Turns per-cell name and fingerprint samples into the feature block.

    Scoring is done at window close, in one pass, then the same evidence is
    folded into the models for later windows - preserving the score-then-learn
    ordering at window granularity, which is the granularity the rest of the
    sensor already reasons in.
    """

    def __init__(self, sample_cap: int = 64, max_fingerprints: int = 20_000) -> None:
        self.sample_cap = sample_cap
        self.bigrams = BigramModel()
        self.fingerprints = FingerprintRarity(max_fingerprints)

    def add(self, cell: ProtocolCell, qname: str = "", tls_fp: str = "") -> None:
        """Sample into a cell. Capped so one noisy host cannot dominate memory."""
        if qname and len(cell.qnames) < self.sample_cap:
            cell.qnames.append(qname)
        if tls_fp and len(cell.tls_fps) < self.sample_cap:
            cell.tls_fps.append(tls_fp)

    def features(self, cell: ProtocolCell) -> Dict[str, float]:
        """Score a closed cell, then learn from it."""
        qn, fps = cell.qnames, cell.tls_fps

        if qn:
            ent = sum(_char_entropy(q) for q in qn) / len(qn)
            len_mean = sum(len(q) for q in qn) / len(qn)
            len_max = float(max(_max_label(q) for q in qn))
            digits = sum(_digit_ratio(q) for q in qn) / len(qn)
            bigram = sum(self.bigrams.score(q) for q in qn) / len(qn)
        else:
            ent = len_mean = len_max = digits = bigram = 0.0

        if fps:
            rarity = sum(self.fingerprints.rarity(f) for f in fps) / len(fps)
            novel = sum(self.fingerprints.is_novel(f) for f in fps) / len(fps)
        else:
            rarity = novel = 0.0

        # Learn only after scoring. See the module docstring.
        for q in qn:
            self.bigrams.observe(q)
        for f in fps:
            self.fingerprints.observe(f)

        return {
            "hw_src_dns_count": float(len(qn)),
            "hw_src_qname_entropy": float(ent),
            "hw_src_qname_len_mean": float(len_mean),
            "hw_src_qname_len_max": float(len_max),
            "hw_src_qname_digit_ratio": float(digits),
            "hw_src_qname_bigram_rarity": float(bigram),
            "hw_src_tls_count": float(len(fps)),
            "hw_src_tls_fp_rarity": float(rarity),
            "hw_src_tls_fp_novel": float(novel),
        }

    @staticmethod
    def zeros() -> Dict[str, float]:
        """The feature block when no protocol evidence is available.

        Flow-record corpora such as CIC-IDS2017 carry no query names or
        fingerprints, so this is what they get - explicitly, rather than by
        omission.
        """
        return {k: 0.0 for k in PROTOCOL_FEATURES}

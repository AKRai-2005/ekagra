"""Packet -> flow assembly, for a one-way tap.

Why this is the last structural gap
-----------------------------------
`streaming_host_window.py` consumes flow records. CIC-IDS2017 ships them
pre-assembled, so experiment 05 could run without this. A real diode enclave
sees **packets**, and something has to turn them into flows before any of the
host-window machinery applies.

Three things make this non-trivial on a one-way tap
---------------------------------------------------
1. **Direction must be inferred, not read.** With both directions visible you
   orient a flow by which side sent the SYN. Seeing only one direction, the
   first packet observed for a 5-tuple *defines* the initiator. That is the
   honest interpretation and it is what a diode sensor must do.

2. **Termination is often unobservable.** A FIN or RST from the far side never
   arrives. So expiry is driven by timeouts, and the timeout policy is a real
   design decision rather than a detail - it determines how flows are cut, and
   therefore every downstream count.

3. **Flows are emitted late.** A flow starting at t=10s and expiring at t=70s
   is emitted at t=70s but *belongs to* the window containing t=10s. Records
   therefore arrive out of order with respect to their own start times, and a
   windowed aggregator that assumes ordered input will silently drop them.
   `StreamingHostWindow` handles this with an explicit lateness budget; see
   `allowed_lateness_s` there. Ignoring the problem is the easy bug here, and
   it costs real detections.

Timeout policy
--------------
`idle_timeout` 15s and `active_timeout` 120s, matching common NetFlow practice
and close to CICFlowMeter's 120s activity timeout - chosen so flows are cut the
way the corpus that validated the features cuts them. Both are constructor
arguments because the right values are deployment-specific, and quoting a
number without saying it is tunable would be dishonest.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from ..features.streaming_host_window import FlowRecord
from .records import FIN, RST, Packet

IDLE_TIMEOUT_S = 15.0
ACTIVE_TIMEOUT_S = 120.0
# How long to keep a FIN'd flow open so the initiator's final ACK joins it
# rather than starting a new one. Two seconds is far longer than the gap
# between a FIN and its ACK on any real stack, and far shorter than the idle
# timeout, so it costs nothing in latency.
FIN_GRACE_S = 2.0

# Per-flow cap on sampled query names / TLS fingerprints.
_PROTO_CAP = 16
#
# Measured impact on the corpora in this repository: **none**. The synthetic
# generator does not emit the final ACK after a FIN, and CIC-IDS2017 ships flow
# records rather than packets, so neither corpus can exercise the path - flow
# counts are identical with the grace at 0s and at 2s (845,322 either way on a
# 300s generated capture). The fix therefore matters for real packet capture,
# which is the deployment this project targets, and it changes no published
# number. Both halves of that are stated because only quoting the first would
# imply an improvement we did not measure.
#
# It also exposes a fidelity gap in our own instrument: real stacks send that
# ACK and ours does not. Fixing the generator would change the inputs to
# experiments 01, 06 and 07, so it is recorded as a known gap rather than
# changed quietly underneath published results.


@dataclass(slots=True)
class _Flow:
    """In-progress flow state. Forward direction only, by construction."""

    src: str
    dst: str
    dport: int
    proto: str
    start_ts: float
    last_ts: float
    pkts: int = 0
    bytes: int = 0
    closed_by_flags: bool = False
    qnames: list = field(default_factory=list)
    tls_fps: list = field(default_factory=list)
    fin_ts: Optional[float] = None
    """When the initiator's FIN was seen. A FIN means "no more data from me",
    not "this flow is over" - the stack still sends a final ACK, and on a
    one-way tap that ACK is the last thing we observe. Closing on the FIN
    itself made that ACK start a *second* flow record for the same session."""

    def to_record(self) -> FlowRecord:
        # ts is the flow's START, not its expiry: the window a flow belongs to
        # is the one it began in, which is what the batch reference does with
        # CIC-IDS2017's Timestamp column.
        return FlowRecord(ts=self.start_ts, src=self.src, dst=self.dst,
                          dport=self.dport, fwd_pkts=float(self.pkts),
                          fwd_bytes=float(self.bytes),
                          qnames=tuple(self.qnames), tls_fps=tuple(self.tls_fps))


class FlowAssembler:
    """Assembles observed packets into flow records with bounded memory.

    Emission is driven by three conditions, checked in this order:

        TCP teardown   RST closes at once; FIN starts a short grace period
        idle timeout   no packet for `idle_timeout` seconds
        active timeout flow has been open for `active_timeout` seconds

    Expiry sweeps are amortised: the table is scanned every `sweep_interval`
    seconds of stream time rather than on every packet, which keeps the
    per-packet cost O(1) in the common case.
    """

    def __init__(self, idle_timeout: float = IDLE_TIMEOUT_S,
                 active_timeout: float = ACTIVE_TIMEOUT_S,
                 max_flows: int = 200_000,
                 sweep_interval: float = 1.0,
                 fin_grace: float = FIN_GRACE_S) -> None:
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.fin_grace = fin_grace
        self.max_flows = max_flows
        self.sweep_interval = sweep_interval

        self._flows: "OrderedDict[Tuple, _Flow]" = OrderedDict()
        # Second index, ordered by flow START. The LRU table is ordered by last
        # activity, which expires idle flows correctly but cannot see a flow
        # that is busy yet has outlived the active timeout. This deque makes
        # active expiry O(1) amortised instead of a full table scan.
        self._by_start: "deque[Tuple[float, Tuple]]" = deque()
        self._last_sweep: Optional[float] = None

        self.n_packets = 0
        self.n_flows_emitted = 0
        self.evicted_flows = 0
        self.closed_by_flags = 0
        self.closed_by_idle = 0
        self.closed_by_active = 0

    # ------------------------------------------------------------------ keys
    @staticmethod
    def _key(pkt: Packet) -> Tuple:
        """5-tuple as observed. No canonicalisation across directions - on a
        one-way tap there is no reverse direction to canonicalise with."""
        return (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto)

    # ---------------------------------------------------------------- ingest
    def push(self, pkt: Packet) -> List[FlowRecord]:
        self.n_packets += 1
        out: List[FlowRecord] = []

        if self._last_sweep is None:
            self._last_sweep = pkt.ts
        elif pkt.ts - self._last_sweep >= self.sweep_interval:
            out.extend(self._sweep(pkt.ts))
            self._last_sweep = pkt.ts

        k = self._key(pkt)
        f = self._flows.get(k)
        if f is None:
            if len(self._flows) >= self.max_flows:
                _, victim = self._flows.popitem(last=False)
                self.evicted_flows += 1
                out.append(victim.to_record())
                self.n_flows_emitted += 1
            f = _Flow(src=pkt.src_ip, dst=pkt.dst_ip, dport=pkt.dst_port,
                      proto=pkt.proto, start_ts=pkt.ts, last_ts=pkt.ts)
            self._flows[k] = f
            self._by_start.append((pkt.ts, k))
        else:
            self._flows.move_to_end(k)

        f.last_ts = pkt.ts
        f.pkts += 1
        f.bytes += pkt.size

        # Protocol evidence rides along with the flow. Capped per flow so a
        # single long-lived tunnel cannot grow one record without bound.
        if pkt.dns_qname and len(f.qnames) < _PROTO_CAP:
            f.qnames.append(pkt.dns_qname)
        if pkt.tls_fp and len(f.tls_fps) < _PROTO_CAP:
            f.tls_fps.append(pkt.tls_fp)

        # RST is abortive: nothing legitimate follows it, so close at once.
        #
        # FIN is not. It means "no more data from me", and the initiator still
        # sends a final ACK - which on a one-way tap is the last packet we see
        # of the session. Closing on the FIN made that ACK arrive at an empty
        # table and open a second flow for the same 5-tuple, so every cleanly
        # closed TCP session was counted twice. That inflates hw_src_n_flows
        # and hw_dst_n_flows, two of the sixteen host-window features the
        # detection result rests on.
        #
        # Engelen et al. (WTMC 2021) found the mirror-image bug in
        # CICFlowMeter, which terminated on a single FIN when it could see both
        # directions and should have waited for the mutual exchange. We cannot
        # wait for the peer's FIN - it never reaches this side of the diode -
        # so we wait a short grace period instead and let the trailing ACK land
        # on the flow it belongs to.
        if pkt.proto == "tcp" and (pkt.flags & RST):
            f.closed_by_flags = True
            del self._flows[k]
            self.closed_by_flags += 1
            self.n_flows_emitted += 1
            out.append(f.to_record())
        elif pkt.proto == "tcp" and (pkt.flags & FIN) and f.fin_ts is None:
            f.fin_ts = pkt.ts

        return out

    # ---------------------------------------------------------------- expiry
    def _sweep(self, now: float) -> List[FlowRecord]:
        """Expire idle and over-long flows.

        Two passes, because the two timeouts need different orderings:

          active  walk `_by_start` from the front, which is sorted by flow
                  start; stop at the first flow young enough to keep.
          idle    walk the LRU table from the least-recently-used end and stop
                  at the first flow fresh enough to keep.

        An earlier version used only the LRU walk and broke out on the first
        fresh flow, which silently never expired a long-running busy flow. That
        is a leak, not a rounding error: a flow open for hours would hold state
        and never be scored.
        """
        out: List[FlowRecord] = []
        idle_cut = now - self.idle_timeout
        active_cut = now - self.active_timeout
        fin_cut = now - self.fin_grace

        # --- FIN grace expired: the trailing ACK has had its chance to arrive
        for k in [k for k, f in self._flows.items()
                  if f.fin_ts is not None and f.fin_ts <= fin_cut]:
            f = self._flows.pop(k)
            f.closed_by_flags = True
            self.closed_by_flags += 1
            self.n_flows_emitted += 1
            out.append(f.to_record())

        # --- active timeout, in start order
        while self._by_start and self._by_start[0][0] <= active_cut:
            _, k = self._by_start.popleft()
            f = self._flows.get(k)
            if f is None or f.start_ts > active_cut:
                continue          # already emitted, or the key was reused
            del self._flows[k]
            self.closed_by_active += 1
            self.n_flows_emitted += 1
            out.append(f.to_record())

        # --- idle timeout, in last-activity order
        while self._flows:
            k = next(iter(self._flows))
            f = self._flows[k]
            if f.last_ts > idle_cut:
                break
            del self._flows[k]
            self.closed_by_idle += 1
            self.n_flows_emitted += 1
            out.append(f.to_record())

        return out

    def flush(self) -> List[FlowRecord]:
        out = [f.to_record() for f in self._flows.values()]
        self.n_flows_emitted += len(out)
        self._flows.clear()
        self._by_start.clear()
        return out

    # ----------------------------------------------------------------- stats
    def stats(self) -> dict:
        return {
            "packets": self.n_packets,
            "flows_emitted": self.n_flows_emitted,
            "open_flows_now": len(self._flows),
            "evicted_flows": self.evicted_flows,
            "closed_by_flags": self.closed_by_flags,
            "closed_by_idle": self.closed_by_idle,
            "closed_by_active": self.closed_by_active,
            "idle_timeout_s": self.idle_timeout,
            "active_timeout_s": self.active_timeout,
        }


def assemble(packets: Iterable[Packet], **kw) -> Tuple[List[FlowRecord], dict]:
    """Drive the assembler over a packet iterable. Returns flows + stats."""
    fa = FlowAssembler(**kw)
    out: List[FlowRecord] = []
    for p in packets:
        out.extend(fa.push(p))
    out.extend(fa.flush())
    return out, fa.stats()

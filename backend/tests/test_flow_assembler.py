"""Flow assembly invariants.

The assembler decides where every flow boundary falls, so a bug here silently
changes every downstream count. These tests pin the expiry policy and the one
property the rest of the pipeline depends on: that a flow record carries its
**start** time, not its expiry time.
"""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.ingest.flow_assembler import FlowAssembler, assemble  # noqa: E402
from ekagra.ingest.records import ACK, FIN, FORWARD, PSH, RST, SYN, Packet  # noqa: E402


def _pkt(i, ts, src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80,
         flags=PSH | ACK, size=100, proto="tcp"):
    return Packet(index=i, ts=ts, src_ip=src, dst_ip=dst, src_port=sport,
                  dst_port=dport, proto=proto, size=size, flags=flags, ttl=64,
                  direction=FORWARD)


def test_record_carries_flow_start_not_expiry():
    """The window a flow belongs to is the one it began in.

    If the record carried the expiry time instead, every long flow would be
    attributed to the wrong window and the out-of-order problem would be
    invisible rather than merely handled.
    """
    fa = FlowAssembler(idle_timeout=10.0)
    pkts = [_pkt(0, 100.0), _pkt(1, 101.0), _pkt(2, 102.0)]
    for p in pkts:
        fa.push(p)
    # push a far-future packet on another flow to trigger the sweep
    out = fa.push(_pkt(3, 200.0, src="10.0.0.9"))
    out += fa.flush()
    rec = [r for r in out if r.src == "10.0.0.1"][0]
    assert rec.ts == 100.0, "record should carry the flow start time"
    assert rec.fwd_pkts == 3 and rec.fwd_bytes == 300


def test_idle_timeout_cuts_the_flow():
    fa = FlowAssembler(idle_timeout=10.0, active_timeout=1000.0)
    fa.push(_pkt(0, 0.0))
    fa.push(_pkt(1, 1.0))
    out = fa.push(_pkt(2, 50.0, src="10.0.0.9"))   # advances stream time
    out += fa.flush()
    first = [r for r in out if r.src == "10.0.0.1"]
    assert len(first) == 1 and first[0].fwd_pkts == 2
    assert fa.closed_by_idle >= 1


def test_active_timeout_cuts_a_busy_flow():
    """A flow that never goes idle must still be cut.

    An earlier version walked only the LRU table and stopped at the first fresh
    entry, so a continuously busy flow was never expired - a state leak, and
    the flow would never be scored at all.
    """
    fa = FlowAssembler(idle_timeout=100.0, active_timeout=20.0, sweep_interval=1.0)
    for i in range(60):
        fa.push(_pkt(i, float(i)))       # one packet per second, never idle
    fa.flush()
    assert fa.closed_by_active >= 1, "busy long-lived flow was never cut"
    assert fa.n_flows_emitted >= 2


def test_rst_closes_immediately():
    """RST is abortive - nothing legitimate follows it."""
    fa = FlowAssembler(idle_timeout=1000.0, active_timeout=1000.0)
    fa.push(_pkt(0, 0.0))
    out = fa.push(_pkt(1, 1.0, flags=RST))
    assert len(out) == 1 and out[0].fwd_pkts == 2
    assert fa.closed_by_flags == 1


def test_fin_waits_so_the_final_ack_joins_the_same_flow():
    """A clean TCP close must produce ONE flow record, not two.

    This test previously asserted that FIN closed the flow immediately, which
    encoded a real bug: a stack sends a final ACK after its FIN, and on a
    one-way tap that ACK is the last packet of the session. Closing on the FIN
    made it arrive at an empty table and open a *second* flow for the same
    5-tuple, so every cleanly closed TCP session was counted twice - inflating
    hw_src_n_flows and hw_dst_n_flows, two of the sixteen host-window features
    the detection result depends on.
    """
    fa = FlowAssembler(idle_timeout=1000.0, active_timeout=1000.0, fin_grace=2.0)
    assert fa.push(_pkt(0, 0.0, flags=SYN)) == []
    assert fa.push(_pkt(1, 0.1, flags=ACK | PSH)) == []
    assert fa.push(_pkt(2, 0.3, flags=FIN | ACK)) == [], "FIN must not close yet"
    assert fa.push(_pkt(3, 0.4, flags=ACK)) == [], "the final ACK belongs here"

    out = fa.flush()
    assert len(out) == 1, f"one session became {len(out)} records"
    assert out[0].fwd_pkts == 4, "the trailing ACK was not counted"


def test_fin_grace_expires_rather_than_leaking():
    """The grace period must end; a FIN'd flow cannot linger indefinitely."""
    fa = FlowAssembler(idle_timeout=1000.0, active_timeout=1000.0, fin_grace=2.0)
    fa.push(_pkt(0, 0.0, flags=SYN))
    fa.push(_pkt(1, 0.3, flags=FIN | ACK))
    fa.push(_pkt(2, 0.4, flags=ACK))
    # A packet well past the grace forces a sweep.
    out = fa.push(_pkt(3, 30.0, src="10.9.9.9", flags=SYN))
    assert len(out) == 1, "the FIN'd flow was never emitted"
    assert out[0].fwd_pkts == 3
    assert fa.closed_by_flags == 1


def test_a_new_session_after_the_grace_is_a_separate_flow():
    """Reusing a 5-tuple later must still start a fresh flow."""
    fa = FlowAssembler(idle_timeout=1000.0, active_timeout=1000.0, fin_grace=2.0)
    out = []
    for i, (ts, fl) in enumerate([(0.0, SYN), (0.3, FIN | ACK), (0.4, ACK), (9.0, SYN)]):
        # The closed flow is emitted by the sweep the last packet triggers, so
        # collect what push() returns as well as the final flush.
        out.extend(fa.push(_pkt(i, ts, flags=fl)))
    out.extend(fa.flush())
    assert len(out) == 2, "the later session was merged into the closed one"
    assert [int(r.fwd_pkts) for r in out] == [3, 1]


def test_distinct_five_tuples_are_distinct_flows():
    fa = FlowAssembler(idle_timeout=1000.0)
    fa.push(_pkt(0, 0.0, sport=1111))
    fa.push(_pkt(1, 0.1, sport=2222))
    fa.push(_pkt(2, 0.2, dport=443))
    out = fa.flush()
    assert len(out) == 3


def test_udp_is_never_closed_by_flags():
    """UDP has no FIN/RST; only timeouts may cut it."""
    fa = FlowAssembler(idle_timeout=1000.0, active_timeout=1000.0)
    fa.push(_pkt(0, 0.0, proto="udp", flags=FIN | RST))
    assert fa.closed_by_flags == 0
    assert len(fa.flush()) == 1


def test_eviction_is_bounded_and_emits():
    """Evicted flows must still be emitted, not silently dropped."""
    fa = FlowAssembler(idle_timeout=10_000.0, active_timeout=10_000.0, max_flows=20)
    out = []
    for i in range(100):
        out.extend(fa.push(_pkt(i, float(i) * 0.001, sport=1000 + i)))
    out.extend(fa.flush())
    assert fa.evicted_flows > 0
    assert len(fa._flows) <= 20
    assert len(out) == 100, "every flow should be emitted exactly once"


def test_every_packet_is_accounted_for():
    """Total packets across emitted flows must equal packets pushed."""
    fa = FlowAssembler(idle_timeout=5.0, active_timeout=30.0)
    out = []
    n = 500
    for i in range(n):
        out.extend(fa.push(_pkt(i, float(i) * 0.5, sport=1000 + (i % 7))))
    out.extend(fa.flush())
    assert sum(r.fwd_pkts for r in out) == n, "packets lost or double-counted"


def test_assemble_helper_matches_manual_drive():
    pkts = [_pkt(i, float(i) * 0.3, sport=1000 + (i % 5)) for i in range(200)]
    flows, stats = assemble(pkts, idle_timeout=5.0)
    assert stats["packets"] == 200
    assert sum(r.fwd_pkts for r in flows) == 200
    assert stats["flows_emitted"] == len(flows)


def test_one_way_tap_sees_only_forward_packets():
    """Sanity: the assembler is only ever fed forward-direction packets, so it
    must not depend on a reverse direction existing."""
    from ekagra.ingest.synthetic import GeneratorConfig, SyntheticSource
    from ekagra.ingest.visibility import DIODE_ONEWAY, VisibilityFilter

    pkts = SyntheticSource(GeneratorConfig(seed=7, duration_s=120.0)).generate()
    observed = list(VisibilityFilter(DIODE_ONEWAY).apply(pkts))
    assert observed and all(p.direction == FORWARD for p in observed)
    flows, stats = assemble(observed)
    assert stats["flows_emitted"] > 0
    assert sum(r.fwd_pkts for r in flows) == len(observed)

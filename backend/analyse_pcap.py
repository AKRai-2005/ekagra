"""Run EKAGRA over a capture file you recorded yourself.

    python analyse_pcap.py mycapture.pcapng
    python analyse_pcap.py mycapture.pcapng --internal 192.168.1. --console

This is the path from real traffic to real features. Everything else in this
repository runs on CIC-IDS2017 flow records (which carry no DNS names and no TLS
fingerprints) or on our own generator (which invents both). A capture you took
yourself is the only input that exercises `ingest/wire.py` against bytes nobody
wrote for us.

What it reports, and why each number is there
---------------------------------------------
The first block is **what the capture contains**, before any detection. This is
deliberately separate from the second block: if a capture yields no DNS queries
and no ClientHellos, the protocol features are all zero and any detection result
below is meaningless. Knowing which of those two situations you are in is the
whole reason for reading the file.

The second block is the pipeline: flows assembled, host-windows built, and the
nine protocol features summarised over them.

There is no model scoring here on purpose. The detector heads are calibrated
against a labelled corpus, and your capture has no labels; printing a threat
class for your own laptop's traffic would be a number with nothing behind it.
What this proves is that the *sensor* works on real traffic - which is the part
that was missing.
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from ekagra.features.protocol import PROTOCOL_FEATURES  # noqa: E402
from ekagra.features.streaming_host_window import StreamingHostWindow  # noqa: E402
from ekagra.ingest.flow_assembler import (  # noqa: E402
    ACTIVE_TIMEOUT_S, IDLE_TIMEOUT_S, FlowAssembler,
)
from ekagra.ingest.pcap import PcapSource  # noqa: E402

WINDOW_S = 60.0
LATENESS_S = 15.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("capture", type=Path, help="a .pcap or .pcapng file")
    ap.add_argument("--internal", default="",
                    help="your LAN prefix, e.g. 192.168.1. - without it every "
                         "packet is treated as outbound, which is honest but "
                         "makes the src/dst split meaningless")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N packets (for a quick look at a big file)")
    ap.add_argument("--top", type=int, default=12, help="query names to list")
    args = ap.parse_args()

    if not args.capture.exists():
        print(f"error: {args.capture} does not exist")
        return 2

    print("=" * 74)
    print(f"EKAGRA  ·  capture analysis  ·  {args.capture.name}")
    print("=" * 74)

    src = PcapSource(args.capture, internal_prefix=args.internal)
    t0 = time.perf_counter()
    packets = []
    try:
        for p in src:
            packets.append(p)
            if args.limit and len(packets) >= args.limit:
                break
    except ValueError as e:
        print(f"\nerror: {e}")
        return 2

    st = src.stats
    read_s = time.perf_counter() - t0
    if not packets:
        print("\nNo IP packets were decoded.")
        print(f"  frames read        {st.packets:,}")
        print(f"  non-IP             {st.non_ip:,}")
        print(f"  unsupported link   {st.unsupported_link:,}  {st.by_linktype}")
        return 1

    print(f"\n[1/3] What the capture contains  ({read_s:.1f}s)")
    print(f"      frames read          {st.packets:,}")
    print(f"      IP packets decoded   {st.emitted:,}")
    print(f"      non-IP (ARP etc)     {st.non_ip:,}")
    if st.unsupported_link:
        print(f"      unsupported link     {st.unsupported_link:,} {st.by_linktype}")
    if st.truncated:
        print(f"      truncated            {st.truncated:,}")
    print(f"      DNS query names      {st.dns_names:,}")
    print(f"      TLS fingerprints     {st.ja3_fingerprints:,}")
    print(f"        over TCP           {st.hellos_reassembled:,} hellos "
          f"({st.hellos_abandoned} abandoned on a gap)")
    print(f"        over QUIC          {st.quic_hellos:,} hellos "
          f"({st.quic_undecryptable} client Initials not decryptable)")
    span = packets[-1].ts - packets[0].ts
    print(f"      time span            {span:.1f}s")

    if st.quic_hellos:
        share = 100 * st.quic_hellos / max(1, st.quic_hellos + st.hellos_reassembled)
        print(f"      {share:.0f}% of handshakes were HTTP/3 - unreachable to a "
              f"sensor that only reads TLS-over-TCP")

    if not st.dns_names and not st.ja3_fingerprints:
        print("\n      NOTE: no DNS queries and no TLS ClientHellos were seen, so")
        print("      the nine protocol features will be zero below. Capture while")
        print("      actively browsing, and do not filter out UDP port 53.")

    names = [p.dns_qname for p in packets if p.dns_qname]
    fps = [p.tls_fp for p in packets if p.tls_fp]
    if names:
        uniq = sorted(set(names))
        print(f"\n      {len(uniq)} distinct query names, first {min(args.top, len(uniq))}:")
        for n in uniq[:args.top]:
            print(f"        {n}")
    if fps:
        uniq_fp = sorted(set(fps))
        print(f"\n      {len(uniq_fp)} distinct JA3 fingerprints:")
        for f in uniq_fp[:args.top]:
            print(f"        {f}  ({fps.count(f)}x)")

    print("\n[2/3] Assembling flows and host-windows")
    fa = FlowAssembler(idle_timeout=IDLE_TIMEOUT_S, active_timeout=ACTIVE_TIMEOUT_S)
    ex = StreamingHostWindow(window_s=WINDOW_S, t0=0.0,
                             allowed_lateness_s=LATENESS_S)
    base = packets[0].ts
    rows = []
    t1 = time.perf_counter()
    for p in packets:
        for rec in fa.push(p):
            rows.extend(ex.push(replace(rec, ts=rec.ts - base)))
    for rec in fa.flush():
        rows.extend(ex.push(replace(rec, ts=rec.ts - base)))
    rows.extend(ex.flush())
    wall = time.perf_counter() - t1

    fstats = fa.stats()
    print(f"      flows assembled      {fstats.get('flows_emitted', 0):,}")
    print(f"      host-window cells    {len(rows):,}")
    print(f"      throughput           {len(packets)/max(1e-9, wall):,.0f} packets/s")

    print("\n[3/3] Protocol features over those cells")
    if not rows:
        print("      none - the capture is shorter than one 60s window.")
        return 0
    nz = 0
    for f in PROTOCOL_FEATURES:
        vals = [r.get(f, 0.0) for r in rows]
        hi = max(vals) if vals else 0.0
        mean = sum(vals) / len(vals) if vals else 0.0
        flag = "" if hi else "   <- always zero"
        if hi:
            nz += 1
        print(f"      {f:28s} mean {mean:10.4f}   max {hi:10.4f}{flag}")

    print(f"\n      {nz} of {len(PROTOCOL_FEATURES)} protocol features are non-zero.")
    print("      These are the features the DGA and encrypted-C2 heads consume,")
    print("      computed from your own traffic rather than from a generator.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

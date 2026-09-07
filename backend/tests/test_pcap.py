"""Capture-file ingest, end to end: bytes on disk to a `Packet` with a JA3.

The tests build real pcap and pcapng files rather than shipping fixtures, so
what is asserted is that we read the *format*, not that we read one particular
file someone once gave us.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.ingest.pcap import PcapSource, read_pcap  # noqa: E402
from ekagra.ingest.records import SYN  # noqa: E402
from ekagra.ingest.wire import ja3, ja4  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_wire import client_hello, dns_query  # noqa: E402


# ------------------------------------------------------------------ builders

def eth_ipv4(payload: bytes, proto: int, src="10.0.0.5", dst="8.8.8.8",
             sport=1234, dport=53, flags=0x02, seq=0) -> bytes:
    if proto == 6:
        tp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 8192, 0, 0)
    else:
        tp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    body = tp + payload
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(body), 1, 0, 64, proto, 0)
    ip += bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    return b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", 0x0800) + ip + body


def write_pcap(path: Path, frames, linktype=1, endian="<", ticks=1_000_000):
    magic = 0xA1B2C3D4 if ticks == 1_000_000 else 0xA1B23C4D
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for i, f in enumerate(frames):
        out += struct.pack(endian + "IIII", 1700000000 + i, 500, len(f), len(f)) + f
    path.write_bytes(out)


def write_pcapng(path: Path, frames, linktype=1):
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) \
        + struct.pack("<I", 28)
    idb_body = struct.pack("<HHI", linktype, 0, 65535)
    idb = struct.pack("<II", 1, 8 + len(idb_body) + 4) + idb_body \
        + struct.pack("<I", 8 + len(idb_body) + 4)
    out = shb + idb
    for i, f in enumerate(frames):
        pad = (-len(f)) % 4
        body = struct.pack("<IIIII", 0, 0, 1700000000 + i, len(f), len(f)) \
            + f + b"\x00" * pad
        total = 12 + len(body)
        out += struct.pack("<II", 6, total) + body + struct.pack("<I", total)
    path.write_bytes(out)


# -------------------------------------------------------------------- tests

def test_a_dns_query_survives_the_whole_path(tmp_path):
    """The point of the module: a real capture file in, a query name out."""
    p = tmp_path / "dns.pcap"
    write_pcap(p, [eth_ipv4(dns_query("malware-c2.example.net"), 17)])
    pkts, stats = read_pcap(p)
    assert len(pkts) == 1
    assert pkts[0].dns_qname == "malware-c2.example.net"
    assert stats.dns_names == 1 and stats.emitted == 1


def test_a_client_hello_becomes_a_fingerprint(tmp_path):
    """JA4 by default: measured on a real capture, JA3 gave 92 distinct
    fingerprints for 97 hellos because Chrome randomises extension order."""
    p = tmp_path / "tls.pcap"
    hello = client_hello()
    write_pcap(p, [eth_ipv4(hello, 6, sport=51000, dport=443, flags=0x18)])
    pkts, stats = read_pcap(p)
    assert pkts[0].tls_fp == ja4(hello) is not None
    assert stats.ja3_fingerprints == 1


def test_ja3_remains_selectable_for_published_corpora(tmp_path):
    """JA3 lookups against abuse.ch and similar need the JA3 value itself."""
    p = tmp_path / "tls3.pcap"
    hello = client_hello()
    write_pcap(p, [eth_ipv4(hello, 6, sport=51000, dport=443, flags=0x18)])
    pkts, _ = read_pcap(p, fingerprint="ja3")
    assert pkts[0].tls_fp == ja3(hello)


def test_an_unknown_fingerprint_scheme_is_refused(tmp_path):
    with pytest.raises(ValueError, match="ja3.*ja4"):
        PcapSource(tmp_path / "x.pcap", fingerprint="ja5")


def test_a_client_hello_split_across_segments_is_reassembled(tmp_path):
    """94% of real ClientHellos exceed one segment - a modern hello carries
    ALPN, key shares and padding. Without this the feature had 6% coverage."""
    hello = client_hello(padding=1600)
    assert len(hello) > 1400, "test needs a hello bigger than one segment"
    a, b = hello[:1400], hello[1400:]
    frames = [
        eth_ipv4(a, 6, sport=52000, dport=443, flags=0x18, seq=1000),
        eth_ipv4(b, 6, sport=52000, dport=443, flags=0x18, seq=1000 + len(a)),
    ]
    p = tmp_path / "split.pcap"
    write_pcap(p, frames)
    pkts, stats = read_pcap(p)
    assert stats.hellos_reassembled == 1
    assert [x.tls_fp for x in pkts if x.tls_fp] == [ja4(hello)]


def test_a_gap_abandons_rather_than_fingerprinting_across_a_hole(tmp_path):
    """A fingerprint assembled across missing bytes is subtly wrong, which is
    worse than absent - it would be indistinguishable from a real client."""
    hello = client_hello(padding=1600)
    a, b = hello[:1400], hello[1500:]           # 100 bytes never arrive
    frames = [
        eth_ipv4(a, 6, sport=53000, dport=443, flags=0x18, seq=500),
        eth_ipv4(b, 6, sport=53000, dport=443, flags=0x18, seq=500 + 1500),
    ]
    p = tmp_path / "gap.pcap"
    write_pcap(p, frames)
    pkts, stats = read_pcap(p)
    assert stats.hellos_reassembled == 0
    assert all(x.tls_fp is None for x in pkts)


def test_pcapng_reads_identically_to_pcap(tmp_path):
    """Wireshark writes pcapng by default. Requiring a Save-As dance would be a
    demo failure mode, so both containers must give the same packets."""
    frames = [eth_ipv4(dns_query("a.example.com"), 17),
              eth_ipv4(client_hello(), 6, sport=4000, dport=443, flags=0x18)]
    a, b = tmp_path / "x.pcap", tmp_path / "x.pcapng"
    write_pcap(a, frames)
    write_pcapng(b, frames)
    pa, _ = read_pcap(a)
    pb, _ = read_pcap(b)
    assert [(x.src_ip, x.dst_ip, x.dns_qname, x.tls_fp) for x in pa] == \
           [(x.src_ip, x.dst_ip, x.dns_qname, x.tls_fp) for x in pb]


@pytest.mark.parametrize("endian", ["<", ">"])
def test_both_pcap_endiannesses(tmp_path, endian):
    p = tmp_path / f"e{endian == '<'}.pcap"
    write_pcap(p, [eth_ipv4(dns_query("e.example.com"), 17)], endian=endian)
    pkts, _ = read_pcap(p)
    assert pkts and pkts[0].dns_qname == "e.example.com"


def test_nanosecond_timestamps_are_not_read_as_microseconds(tmp_path):
    p = tmp_path / "ns.pcap"
    write_pcap(p, [eth_ipv4(dns_query("n.example.com"), 17)], ticks=1_000_000_000)
    pkts, _ = read_pcap(p)
    # 500 ticks is 0.5 microseconds here, not 0.5 milliseconds.
    assert pkts[0].ts == pytest.approx(1700000000 + 500e-9, abs=1e-9)


def test_tcp_flags_are_decoded(tmp_path):
    p = tmp_path / "syn.pcap"
    write_pcap(p, [eth_ipv4(b"", 6, sport=1, dport=80, flags=0x02)])
    pkts, _ = read_pcap(p)
    assert pkts[0].flags & SYN


def test_vlan_tags_are_stripped(tmp_path):
    """A mirrored SPAN port very often delivers tagged frames. Without this the
    entire capture reads as non-IP and the sensor sees nothing."""
    frame = eth_ipv4(dns_query("vlan.example.com"), 17)
    tagged = frame[:12] + struct.pack("!HH", 0x8100, 0x0064) + frame[12:]
    p = tmp_path / "vlan.pcap"
    write_pcap(p, [tagged])
    pkts, _ = read_pcap(p)
    assert pkts and pkts[0].dns_qname == "vlan.example.com"


def test_a_later_fragment_is_not_parsed_as_a_transport_header(tmp_path):
    frame = bytearray(eth_ipv4(dns_query("frag.example.com"), 17))
    struct.pack_into("!H", frame, 14 + 6, 0x0001)          # non-zero frag offset
    p = tmp_path / "frag.pcap"
    write_pcap(p, [bytes(frame)])
    pkts, stats = read_pcap(p)
    assert pkts == [] and stats.non_ip == 1


def test_non_ip_frames_are_counted_not_crashed(tmp_path):
    arp = b"\xff" * 6 + b"\xaa" * 6 + struct.pack("!H", 0x0806) + b"\x00" * 28
    p = tmp_path / "arp.pcap"
    write_pcap(p, [arp])
    pkts, stats = read_pcap(p)
    assert pkts == [] and stats.non_ip == 1


def test_an_unknown_link_type_is_reported_not_guessed(tmp_path):
    p = tmp_path / "weird.pcap"
    write_pcap(p, [b"\x00" * 40], linktype=999)
    pkts, stats = read_pcap(p)
    assert pkts == [] and stats.unsupported_link == 1


def test_a_truncated_capture_stops_cleanly(tmp_path):
    p = tmp_path / "cut.pcap"
    write_pcap(p, [eth_ipv4(dns_query("a.example.com"), 17)])
    p.write_bytes(p.read_bytes()[:-12])                     # chop mid-packet
    pkts, stats = read_pcap(p)
    assert pkts == [] and stats.truncated == 1


def test_a_file_that_is_not_a_capture_says_so_usefully(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"this is not a capture file at all, sorry")
    with pytest.raises(ValueError, match="not a pcap or pcapng"):
        read_pcap(p)


def test_an_empty_file_yields_nothing(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    assert read_pcap(p)[0] == []


def test_direction_needs_a_prefix_and_does_not_guess(tmp_path):
    """Inferring "inside" from RFC1918 would be wrong on any lab capture using
    public addressing, so an unconfigured source calls everything outbound."""
    p = tmp_path / "dir.pcap"
    write_pcap(p, [eth_ipv4(dns_query("d.example.com"), 17, src="10.0.0.5")])
    assert read_pcap(p)[0][0].direction == "out"
    src = PcapSource(p, internal_prefix="192.168.")
    assert list(src)[0].direction == "in"


def test_the_source_exposes_no_way_back_into_the_network():
    """The read-only contract, checked on the shape of the object rather than
    trusted. `test_readonly_constraint.py` checks the AST; this checks the API."""
    for name in ("send", "sendto", "connect", "write", "query", "block"):
        assert not hasattr(PcapSource, name), f"PcapSource.{name} must not exist"

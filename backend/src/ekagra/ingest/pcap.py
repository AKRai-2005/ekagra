"""Read a capture file and emit `Packet`s — the path from real traffic to EKAGRA.

Why this exists
---------------
`wire.py` can compute a JA3 fingerprint and a DNS query name from bytes, and
`features/protocol.py` can turn those into detector features. Between them there
was nothing: `replay.py` reads CIC-IDS2017 flow records (which carry neither)
and `synthetic.py` invents both. This module is the missing middle, and it is
what makes the DGA and encrypted-C2 heads work on traffic nobody generated for
us.

It reads files. It never opens a socket, which is what keeps it inside the
read-only constraint `tests/test_readonly_constraint.py` enforces - live capture
needs a privileged handle on an interface, and that is the diode operator's job,
not this process's. The workflow is deliberately "capture with tcpdump or
Wireshark, hand us the file".

Formats
-------
Classic **pcap** (both endiannesses, microsecond and nanosecond) and **pcapng**
(section header, interface description, enhanced packet blocks). pcapng is here
because it is what Wireshark writes by default, and requiring every user to
find the Save-As dropdown is a support burden and a demo failure mode.

Link layers: Ethernet, Linux cooked capture (SLL/SLL2), raw IPv4/IPv6, and
Null/loopback. VLAN and QinQ tags are stripped. IPv6 is parsed far enough to
skip its extension headers.

ClientHello reassembly, and why it turned out to be mandatory
--------------------------------------------------------------
The first version of this module did no reassembly, on the reasoning that a
ClientHello fits in one segment at any normal MTU. Measured against a real
capture, that reasoning was wrong and not marginally: of 97 ClientHellos,
**6 parsed and 91 did not.** A modern hello carries ALPN, key shares, session
tickets, ECH and padding, and routinely runs past 2 KB - the failures were all
records declaring 1.7-2.0 KB against a ~1460-byte segment. A JA3 feature with
6% coverage is not a limitation, it is a broken feature that would have looked
fine on generated traffic forever.

So there is now a **bounded, single-direction reassembler** for exactly this one
message. It is not TCP reassembly and does not pretend to be: it buffers the
leading bytes of a connection, orders them by sequence number, requires them to
be contiguous, and parses once the declared record length has arrived. It does
not handle retransmissions, overlaps or reordering beyond what a small window
absorbs, and it gives up on a gap rather than guessing across it - because a
fingerprint assembled across a hole is subtly wrong, which is worse than absent.

Every buffer is capped (`MAX_HELLO_BYTES`) and the table of pending connections
is capped and evicted oldest-first (`MAX_PENDING`), so a flood of connections
that each send one byte costs bounded memory rather than unbounded.

QUIC — reached, after being wrongly written off
-----------------------------------------------
An earlier version of this docstring recorded QUIC as a hard ceiling: UDP/443
outnumbered TCP/443 80,291 to 32,069 in the capture, so most HTTPS looked
unreachable. That was wrong. **QUIC Initial packets are decryptable by any
observer** — RFC 9001 derives their keys from the Destination Connection ID in
the clear, using a published salt. `ingest/quic.py` does it, and 24% of the
handshakes in that capture were HTTP/3 that we now fingerprint as JA4 with
transport `q`.

Only client Initials are attempted. A server Initial uses the server secret and
fails by construction — measured, 388 of 463 "undecryptable" packets were simply
the server half, which buried the real failure count until the filter was added.

Malformed input is expected, not exceptional: `wire.py` owns that argument, and
every parse failure here is counted rather than raised, so one bad packet in a
million-packet capture costs a counter increment.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

from .records import ACK, FIN, PSH, RST, SYN, URG, Packet
from .quic import QuicHelloAssembler, looks_like_quic_initial
from .wire import TLS_HANDSHAKE, ja3, ja4, parse_dns_qname

PCAP_MAGIC = {
    0xA1B2C3D4: ("<", 1_000_000),      # little-endian, microseconds
    0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000),  # nanosecond variants
    0x4D3CB2A1: (">", 1_000_000_000),
}
PCAPNG_SHB = 0x0A0D0D0A

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
VLAN_TAGS = (0x8100, 0x88A8, 0x9100)

# Extension headers we know how to step over. Anything else stops the walk and
# the packet is counted as unparsed rather than guessed at.
V6_SKIPPABLE = {0: 8, 43: 8, 60: 8, 51: 8}   # hop-by-hop, routing, dest, AH

DNS_PORTS = (53, 5353, 5355)
MAX_SNAP = 262_144                            # refuse absurd caplen values

# Reassembly bounds. A TLS record cannot exceed 16384 bytes by definition, and
# the pending table is capped so a connection flood costs bounded memory.
MAX_HELLO_BYTES = 16_384
MAX_PENDING = 4_096
SEQ_MOD = 1 << 32


class _HelloAssembler:
    """Reassembles a TLS ClientHello that spans TCP segments, and nothing else.

    Scope is deliberately one message on one side of one connection. It starts
    a buffer when a segment's payload begins with a handshake record, orders
    later segments of that connection by sequence number, and hands over the
    bytes once the record's declared length has arrived contiguously. A gap
    abandons the connection: a fingerprint assembled across a hole is subtly
    wrong, and subtly wrong evidence is worse than none.
    """

    __slots__ = ("_pending", "completed", "abandoned")

    def __init__(self) -> None:
        # key -> (base_seq, {offset: bytes}, declared_total)
        self._pending: Dict[tuple, list] = {}
        self.completed = 0
        self.abandoned = 0

    @staticmethod
    def _declared(buf: bytes) -> Optional[int]:
        """Total bytes needed for the record, from its 5-byte header."""
        if len(buf) < 5:
            return None
        return 5 + struct.unpack_from("!H", buf, 3)[0]

    def push(self, key: tuple, seq: int, payload: bytes) -> Optional[bytes]:
        entry = self._pending.get(key)

        if entry is None:
            if not payload or payload[0] != TLS_HANDSHAKE:
                return None
            need = self._declared(payload)
            if need is None or need > MAX_HELLO_BYTES:
                return None
            if len(payload) >= need:
                self.completed += 1
                return payload                      # fitted in one segment
            if len(self._pending) >= MAX_PENDING:
                self._pending.pop(next(iter(self._pending)))
                self.abandoned += 1
            self._pending[key] = [seq, {0: payload}, need]
            return None

        base, parts, need = entry
        off = (seq - base) % SEQ_MOD
        if off > MAX_HELLO_BYTES:                   # wrapped or unrelated
            del self._pending[key]
            self.abandoned += 1
            return None
        parts[off] = payload

        # Walk forward from zero; stop at the first gap.
        out = bytearray()
        while True:
            chunk = parts.get(len(out))
            if chunk is None:
                break
            out += chunk
            if len(out) > MAX_HELLO_BYTES:
                del self._pending[key]
                self.abandoned += 1
                return None

        if len(out) >= need:
            del self._pending[key]
            self.completed += 1
            return bytes(out[:need])
        return None

    def stats(self) -> dict:
        return {"hellos_reassembled": self.completed,
                "hellos_abandoned": self.abandoned + len(self._pending)}


@dataclass
class CaptureStats:
    """Counted, not raised. A capture is full of things we cannot parse."""

    packets: int = 0
    emitted: int = 0
    non_ip: int = 0
    unsupported_link: int = 0
    truncated: int = 0
    dns_names: int = 0
    ja3_fingerprints: int = 0
    hellos_reassembled: int = 0
    hellos_abandoned: int = 0
    quic_hellos: int = 0
    quic_undecryptable: int = 0
    by_linktype: Dict[int, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"packets": self.packets, "emitted": self.emitted,
                "non_ip": self.non_ip, "unsupported_link": self.unsupported_link,
                "truncated": self.truncated, "dns_names": self.dns_names,
                "ja3_fingerprints": self.ja3_fingerprints,
                "hellos_reassembled": self.hellos_reassembled,
                "hellos_abandoned": self.hellos_abandoned,
                "quic_hellos": self.quic_hellos,
                "quic_undecryptable": self.quic_undecryptable,
                "by_linktype": dict(self.by_linktype)}


class PcapSource:
    """A `PacketSource` over a capture file.

    Satisfies the same read-only contract as every other source: iteration only,
    no method that could reach back into the network.
    """

    def __init__(self, path: Path | str, *, internal_prefix: str = "",
                 label: str = "unknown", fingerprint: str = "ja4") -> None:
        if fingerprint not in ("ja3", "ja4"):
            raise ValueError(f"fingerprint must be 'ja3' or 'ja4', got {fingerprint!r}")
        self.path = Path(path)
        self.internal_prefix = internal_prefix
        self.label = label
        self.fingerprint = fingerprint
        self.stats = CaptureStats()
        self._hellos = _HelloAssembler()
        self._quic = QuicHelloAssembler()

    def __iter__(self) -> Iterator[Packet]:
        with self.path.open("rb") as fh:
            head = fh.read(4)
            if len(head) < 4:
                return
            magic = struct.unpack("<I", head)[0]
            if magic == PCAPNG_SHB:
                yield from self._read_pcapng(fh)
            else:
                yield from self._read_pcap(fh, magic)

    # ------------------------------------------------------------- containers
    def _read_pcap(self, fh, magic: int) -> Iterator[Packet]:
        big = struct.unpack(">I", struct.pack("<I", magic))[0]
        for m in (magic, big):
            if m in PCAP_MAGIC:
                endian, ticks = PCAP_MAGIC[m]
                break
        else:
            raise ValueError(
                f"{self.path.name} is not a pcap or pcapng file "
                f"(magic 0x{magic:08x}). If it came from Wireshark, use "
                f"File > Save As and pick 'Wireshark/tcpdump/... pcap'.")

        rest = fh.read(20)
        if len(rest) < 20:
            return
        # version_major, version_minor, thiszone, sigfigs, snaplen, network
        *_, linktype = struct.unpack(endian + "HHiIII", rest)

        idx = 0
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                return
            ts_s, ts_frac, caplen, origlen = struct.unpack(endian + "IIII", hdr)
            if caplen > MAX_SNAP:
                return                       # corrupt length; stop rather than thrash
            data = fh.read(caplen)
            if len(data) < caplen:
                self.stats.truncated += 1
                return
            ts = ts_s + ts_frac / ticks
            p = self._decode(data, linktype, ts, idx, origlen)
            idx += 1
            if p is not None:
                yield p

    def _read_pcapng(self, fh) -> Iterator[Packet]:
        fh.seek(0)
        endian = "<"
        tsres: Dict[int, int] = {}
        links: Dict[int, int] = {}
        iface = 0
        idx = 0

        while True:
            head = fh.read(8)
            if len(head) < 8:
                return
            btype = struct.unpack(endian + "I", head[:4])[0]
            blen = struct.unpack(endian + "I", head[4:8])[0]

            if btype == PCAPNG_SHB:
                bom = fh.read(4)
                if len(bom) < 4:
                    return
                if struct.unpack("<I", bom)[0] != 0x1A2B3C4D:
                    endian = ">"
                    blen = struct.unpack(endian + "I", head[4:8])[0]
                body = fh.read(max(0, blen - 16))
                fh.read(4)
                iface = 0
                continue

            if blen < 12 or blen > (MAX_SNAP + 1024):
                return
            body = fh.read(blen - 12)
            if len(body) < blen - 12:
                return
            fh.read(4)                        # trailing block length

            if btype == 1:                    # interface description
                lt = struct.unpack(endian + "H", body[:2])[0]
                links[iface] = lt
                tsres[iface] = self._if_tsres(body[8:], endian)
                iface += 1

            elif btype == 6:                  # enhanced packet block
                if len(body) < 20:
                    continue
                ifid, hi, lo, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
                data = body[20:20 + caplen]
                if len(data) < caplen:
                    self.stats.truncated += 1
                    continue
                div = tsres.get(ifid, 1_000_000)
                ts = ((hi << 32) | lo) / div
                p = self._decode(data, links.get(ifid, LINKTYPE_ETHERNET),
                                 ts, idx, origlen)
                idx += 1
                if p is not None:
                    yield p

            elif btype == 3:                  # simple packet block
                if len(body) < 4:
                    continue
                origlen = struct.unpack(endian + "I", body[:4])[0]
                data = body[4:]
                p = self._decode(data, links.get(0, LINKTYPE_ETHERNET),
                                 0.0, idx, origlen)
                idx += 1
                if p is not None:
                    yield p

    @staticmethod
    def _if_tsres(opts: bytes, endian: str) -> int:
        """if_tsresol option (code 9): a power of ten, or a power of two when
        the high bit is set. Defaults to microseconds when absent."""
        off = 0
        while off + 4 <= len(opts):
            code, ln = struct.unpack(endian + "HH", opts[off:off + 4])
            val = opts[off + 4:off + 4 + ln]
            if code == 0:
                break
            if code == 9 and ln >= 1:
                r = val[0]
                return (1 << (r & 0x7F)) if r & 0x80 else (10 ** r)
            off += 4 + ((ln + 3) & ~3)
        return 1_000_000

    # ------------------------------------------------------------ link layer
    def _decode(self, data: bytes, linktype: int, ts: float,
                idx: int, origlen: int) -> Optional[Packet]:
        self.stats.packets += 1
        self.stats.by_linktype[linktype] = self.stats.by_linktype.get(linktype, 0) + 1

        if linktype == LINKTYPE_ETHERNET:
            if len(data) < 14:
                return None
            etype = struct.unpack("!H", data[12:14])[0]
            off = 14
            hops = 0
            while etype in VLAN_TAGS and hops < 3:
                if len(data) < off + 4:
                    return None
                etype = struct.unpack("!H", data[off + 2:off + 4])[0]
                off += 4
                hops += 1
        elif linktype == LINKTYPE_LINUX_SLL:
            if len(data) < 16:
                return None
            etype, off = struct.unpack("!H", data[14:16])[0], 16
        elif linktype == LINKTYPE_LINUX_SLL2:
            if len(data) < 20:
                return None
            etype, off = struct.unpack("!H", data[0:2])[0], 20
        elif linktype == LINKTYPE_RAW:
            if not data:
                return None
            etype = ETH_P_IP if (data[0] >> 4) == 4 else ETH_P_IPV6
            off = 0
        elif linktype == LINKTYPE_NULL:
            if len(data) < 4:
                return None
            fam = struct.unpack("<I", data[:4])[0]
            etype = ETH_P_IP if fam == 2 else ETH_P_IPV6
            off = 4
        else:
            self.stats.unsupported_link += 1
            return None

        if etype == ETH_P_IP:
            return self._ipv4(data, off, ts, idx, origlen)
        if etype == ETH_P_IPV6:
            return self._ipv6(data, off, ts, idx, origlen)
        self.stats.non_ip += 1
        return None

    # ------------------------------------------------------------------- IP
    def _ipv4(self, d: bytes, off: int, ts: float, idx: int,
              origlen: int) -> Optional[Packet]:
        if len(d) < off + 20:
            return None
        vihl = d[off]
        ihl = (vihl & 0x0F) * 4
        if ihl < 20 or len(d) < off + ihl:
            return None
        proto = d[off + 9]
        ttl = d[off + 8]
        src = ".".join(str(b) for b in d[off + 12:off + 16])
        dst = ".".join(str(b) for b in d[off + 16:off + 20])
        # A fragment after the first carries no transport header.
        frag = struct.unpack("!H", d[off + 6:off + 8])[0]
        if frag & 0x1FFF:
            self.stats.non_ip += 1
            return None
        return self._transport(d, off + ihl, proto, src, dst, ttl, ts, idx, origlen)

    def _ipv6(self, d: bytes, off: int, ts: float, idx: int,
              origlen: int) -> Optional[Packet]:
        if len(d) < off + 40:
            return None
        nxt = d[off + 6]
        hop = d[off + 7]
        src = _v6(d[off + 8:off + 24])
        dst = _v6(d[off + 24:off + 40])
        p = off + 40
        hops = 0
        while nxt in V6_SKIPPABLE and hops < 8:
            if len(d) < p + 2:
                return None
            ext_len = (d[p + 1] + 1) * 8 if nxt != 51 else (d[p + 1] + 2) * 4
            nxt = d[p]
            p += ext_len
            hops += 1
        return self._transport(d, p, nxt, src, dst, hop, ts, idx, origlen)

    def _transport(self, d: bytes, off: int, proto: int, src: str, dst: str,
                   ttl: int, ts: float, idx: int, origlen: int) -> Optional[Packet]:
        if proto == 6:
            if len(d) < off + 20:
                return None
            sport, dport, seq = struct.unpack("!HHI", d[off:off + 8])
            doff = (d[off + 12] >> 4) * 4
            raw = d[off + 13]
            flags = ((raw & 0x01) * FIN | ((raw >> 1) & 1) * SYN
                     | ((raw >> 2) & 1) * RST | ((raw >> 3) & 1) * PSH
                     | ((raw >> 4) & 1) * ACK | ((raw >> 5) & 1) * URG)
            payload = d[off + doff:] if doff >= 20 else b""
            pname = "tcp"
        elif proto == 17:
            if len(d) < off + 8:
                return None
            sport, dport = struct.unpack("!HH", d[off:off + 4])
            flags = 0
            payload = d[off + 8:]
            pname = "udp"
        elif proto == 1:
            sport = dport = 0
            flags = 0
            payload = b""
            pname = "icmp"
        else:
            self.stats.non_ip += 1
            return None

        qname = fp = None
        if payload:
            if pname == "udp" and (sport in DNS_PORTS or dport in DNS_PORTS):
                qname = parse_dns_qname(payload)
            elif pname == "udp" and dport == 443 and looks_like_quic_initial(payload):
                # Client-to-server only. A server Initial is encrypted with the
                # server secret, so attempting it would fail by construction and
                # bury the real failure count under expected ones - measured on
                # a real capture, 388 of 463 "undecryptable" packets were simply
                # the server half.
                # HTTP/3. The Initial packet's keys come from the connection ID
                # in its own header, so this is readable by any observer - see
                # ingest/quic.py on why that is not payload decryption.
                whole = self._quic.push(payload)
                if whole is not None:
                    fp = ja3(whole) if self.fingerprint == "ja3" else                         ja4(whole, transport="q")
            elif pname == "tcp" and (sport == 53 or dport == 53):
                qname = parse_dns_qname(payload, tcp=True)
            elif pname == "tcp":
                # A hello may span segments, so this is asked on every segment
                # of a connection until it either completes or is abandoned.
                whole = self._hellos.push((src, sport, dst, dport), seq, payload)
                if whole is not None:
                    # JA4 by default. On a real capture JA3 gave 92 distinct
                    # fingerprints for 97 hellos because Chrome randomises
                    # extension order; JA4 sorts and gave 7. `fingerprint="ja3"`
                    # is kept for comparing against published JA3 corpora.
                    fp = ja3(whole) if self.fingerprint == "ja3" else ja4(whole)
        if qname:
            self.stats.dns_names += 1
        if fp:
            self.stats.ja3_fingerprints += 1
        self.stats.hellos_reassembled = self._hellos.completed
        qs = self._quic.stats()
        self.stats.quic_hellos = qs["quic_hellos"]
        self.stats.quic_undecryptable = qs["quic_undecryptable"]
        self.stats.hellos_abandoned = self._hellos.abandoned + len(self._hellos._pending)

        self.stats.emitted += 1
        return Packet(
            index=idx, ts=ts, src_ip=src, dst_ip=dst, src_port=sport,
            dst_port=dport, proto=pname, size=origlen, flags=flags, ttl=ttl,
            direction=self._direction(src), label=self.label,
            dns_qname=qname, tls_fp=fp,
        )

    def _direction(self, src: str) -> str:
        """Which way this packet crossed the tap.

        With no `internal_prefix` configured every packet is "out", which is the
        honest default for a capture whose topology we were not told: guessing
        an inside from RFC1918 ranges would be wrong on any lab capture that
        uses public addressing.
        """
        if not self.internal_prefix:
            return "out"
        return "out" if src.startswith(self.internal_prefix) else "in"


def _v6(b: bytes) -> str:
    if len(b) < 16:
        return "::"
    parts = [f"{(b[i] << 8) | b[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def read_pcap(path: Path | str, *, internal_prefix: str = "",
              label: str = "unknown",
              fingerprint: str = "ja4") -> Tuple[list, CaptureStats]:
    """Convenience: read a whole capture into memory with its statistics."""
    src = PcapSource(path, internal_prefix=internal_prefix, label=label,
                     fingerprint=fingerprint)
    return list(src), src.stats

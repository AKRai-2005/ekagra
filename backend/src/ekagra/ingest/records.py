"""Core observation records.

Everything downstream consumes `Packet`. It is deliberately the *only* thing a
diode tap can give us: what crossed the link, in one direction, with no ability
to ask the endpoints anything.

Design notes
------------
`slots=True` because these are allocated in the millions and attribute dict
overhead dominates otherwise. Fields are ordered by access frequency in the
feature layer.

Application-layer fields (`dns_qname`, `tls_fp`) are metadata observable
*without decryption* — a DNS query name travels in clear, and a TLS client
fingerprint is derived from the unencrypted ClientHello. No payload bytes are
carried on this record, by design: if the field does not exist, feature code
cannot accidentally depend on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional, Protocol

# TCP flag bitmask (RFC 793 order, low bits first)
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

FLAG_NAMES = {FIN: "FIN", SYN: "SYN", RST: "RST", PSH: "PSH", ACK: "ACK", URG: "URG"}

# Direction of travel relative to the flow initiator.
FORWARD = 1
REVERSE = -1


def flags_to_str(flags: int) -> str:
    """Human-readable flag string, e.g. 0x12 -> 'SYN|ACK'. Used in evidence bundles."""
    parts = [name for bit, name in FLAG_NAMES.items() if flags & bit]
    return "|".join(parts) if parts else "-"


@dataclass(slots=True)
class Packet:
    """A single observed packet.

    `index` is the monotonic position in the observed stream. Evidence bundles
    cite these indices so an analyst can replay the exact packets that produced
    an alert.
    """

    index: int
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # "tcp" | "udp"
    size: int
    flags: int
    ttl: int
    direction: int  # FORWARD | REVERSE, relative to flow initiator
    dns_qname: Optional[str] = None
    tls_fp: Optional[str] = None

    # Ground-truth label. Present only in generated/labelled corpora; the
    # detection path must never read it. `tests/test_no_label_leakage.py`
    # enforces that.
    label: str = "benign"

    @property
    def flow_key(self) -> "FlowKey":
        """Canonical 5-tuple, oriented so both directions map to one key."""
        if self.direction == FORWARD:
            return FlowKey(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)
        return FlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.proto)


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Initiator-oriented 5-tuple. Hashable, used as the flow-table key."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.proto}"


class PacketSource(Protocol):
    """The read-only ingest contract.

    Every source — synthetic generator, PCAP replay, CSV replay — implements
    exactly this. There is no `send`, no `query`, no `block`. The absence of
    those methods is the architectural enforcement of the PS constraint:
    downstream code cannot call back into the network because the interface
    it holds has no way to express it.
    """

    def __iter__(self) -> Iterator[Packet]:  # pragma: no cover - protocol
        ...


# Threat classes, named to match the six in the problem statement (§a-f).
THREAT_CLASSES = (
    "benign",
    "ddos",        # (a) volumetric / protocol DDoS
    "beacon",      # (b) botnet C2 beaconing
    "dga",         # (c) DGA domains and DNS tunnelling
    "encrypted",   # (d) malware inside encrypted sessions
    "scan",        # (e) reconnaissance and port scanning
    "exfil",       # (f) data exfiltration
)

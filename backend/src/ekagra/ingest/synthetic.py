"""Labelled traffic generator.

Why this exists
---------------
CIC-IDS2017 and friends are multi-gigabyte downloads and their labels have
documented problems. This generator makes the entire repository runnable with
zero downloads, and — more importantly — it is the only way to get **ground
truth we control**, which KALACHAKRA needs for counterfactual validation.

Honesty constraints we hold ourselves to
----------------------------------------
A generator that makes the result come out the way we want is worthless. Three
rules, deliberately adopted:

1. **Benign traffic contains periodic flows.** NTP sync, telemetry heartbeats
   and health checks all beacon. If benign traffic were aperiodic, beacon
   detection would be trivial and the experiment would be rigged.

2. **Attacks emit realistic forward-side traffic**, not cartoon signatures.
   A SYN flood's client-side ACK is genuinely absent; a benign handshake's
   client ACK is genuinely present. That asymmetry is *real*, and it means the
   diode tap is not as blind as a lazy design would assume. We keep it.

3. **We do not tune the generator after seeing experiment results.** The
   parameters below were fixed from protocol behaviour, not fitted to produce
   a gap. If the ablation gap turns out small, that is the finding.

Realism ceiling
---------------
This is a *behavioural* simulator, not a packet-accurate one. It models arrival
processes, volumes, flag sequences, fan-out and name/fingerprint statistics.
It does not model TCP congestion control, retransmission or fragmentation.
Results here are directional; `ingest/replay.py` runs the same pipeline on real
corpora and is the confirmatory evidence.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from typing import Iterator, List

from .records import ACK, FIN, FORWARD, PSH, REVERSE, RST, SYN, Packet

# Common benign TLS client fingerprints (JA4-like). Real deployments see a
# heavy head: a handful of browser/OS combinations dominate.
BENIGN_TLS_FPS = [
    "t13d1516h2_8daaf6152771_02713d6af862",
    "t13d1517h2_8daaf6152771_b0da82dd1658",
    "t13d1715h2_5b57614c22b0_3d5424432f57",
    "t12d1207h2_c1d1b1a1f1e1_9a8b7c6d5e4f",
    "t13d1516h2_a09f3c656075_14788d8d241b",
]

# Rare fingerprints associated with non-browser TLS stacks. Rarity — not the
# specific value — is the signal.
MALWARE_TLS_FPS = [
    "t12d0908h1_ffaa11223344_deadbeef0001",
    "t13d0512h2_11ee22dd33cc_deadbeef0002",
    "t12d0706h1_99887766aabb_deadbeef0003",
]

BENIGN_DOMAINS = [
    "google.com", "gstatic.com", "cloudflare.com", "microsoft.com", "windowsupdate.com",
    "githubusercontent.com", "akamaiedge.net", "doubleclick.net", "nic.in", "gov.in",
    "sbi.co.in", "irctc.co.in", "ubuntu.com", "pypi.org", "office365.com",
]

# Ports that are commonly abused for UDP reflection/amplification.
AMPLIFIER_PORTS = [53, 123, 1900, 11211, 389]


def _rand_ip(rng: random.Random, prefix: str | None = None) -> str:
    if prefix:
        return f"{prefix}.{rng.randint(1, 254)}"
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _dga_name(rng: random.Random) -> str:
    """High-entropy algorithmically generated domain.

    Uniform character sampling gives ~4.7 bits/char, well above English-like
    domain names (~3.5). That gap is what the entropy feature measures.
    """
    n = rng.randint(12, 24)
    core = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))
    return f"{core}.{rng.choice(['top', 'xyz', 'info', 'cc', 'su'])}"


def _tunnel_name(rng: random.Random, base: str = "t.exfil-c2.net") -> str:
    """DNS tunnelling: base32-ish payload smuggled into long labels."""
    chunk = "".join(rng.choice(string.ascii_lowercase + "234567") for _ in range(rng.randint(40, 60)))
    return f"{chunk[:31]}.{chunk[31:]}.{base}"


@dataclass
class GeneratorConfig:
    seed: int = 1337
    duration_s: float = 3600.0
    n_internal_hosts: int = 60
    internal_prefix: str = "10.20.30"

    # Benign volume
    n_web_sessions: int = 900
    n_dns_clients: int = 40
    n_telemetry_hosts: int = 22        # periodic benign — keeps beaconing hard
    n_bulk_transfers: int = 45

    # Attack episode counts.
    #
    # These are tuned for *row balance* after aggregation, not for packet
    # counts. A single flood produces millions of packets but only a handful of
    # (window, host) rows, because it targets one victim; a scan produces few
    # packets but touches hundreds of hosts. Balancing at the packet level
    # would leave us unable to train the rare classes at all.
    n_ddos_syn: int = 22
    n_ddos_amp: int = 16
    n_beacon: int = 30
    n_dga: int = 26
    n_scan: int = 14
    n_exfil: int = 26
    n_encrypted_c2: int = 28


@dataclass
class SyntheticSource:
    """Generates a labelled bidirectional packet stream.

    Produces *both* directions. The diode filter is what removes one — keeping
    them separate is what lets us measure the cost of the constraint.
    """

    config: GeneratorConfig = field(default_factory=GeneratorConfig)

    def __post_init__(self) -> None:
        self.rng = random.Random(self.config.seed)
        self._raw: List[tuple] = []

    # ---------------------------------------------------------------- helpers
    def _emit(self, ts, src, dst, sport, dport, proto, size, flags, ttl, direction,
              label="benign", qname=None, tls=None) -> None:
        self._raw.append((ts, src, dst, sport, dport, proto, size, flags, ttl,
                          direction, label, qname, tls))

    def _internal(self) -> str:
        return _rand_ip(self.rng, self.config.internal_prefix)

    def _jittered(self, base: float, jitter_frac: float) -> float:
        """Interval with proportional jitter. Real beacons jitter; so do heartbeats."""
        return base * (1.0 + self.rng.uniform(-jitter_frac, jitter_frac))

    # ------------------------------------------------------------- benign
    def _gen_web_session(self) -> None:
        """Browser session: handshake, request burst, teardown. Client ACK present."""
        rng = self.rng
        t = rng.uniform(0, self.config.duration_s - 60)
        c, s = self._internal(), _rand_ip(rng)
        sport, dport = rng.randint(32768, 60999), rng.choice([443, 443, 443, 80])
        ttl = rng.choice([64, 128])
        tls = rng.choice(BENIGN_TLS_FPS) if dport == 443 else None

        self._emit(t, c, s, sport, dport, "tcp", 74, SYN, ttl, FORWARD)
        self._emit(t + rng.uniform(0.01, 0.08), s, c, dport, sport, "tcp", 74, SYN | ACK, 55, REVERSE)
        t_ack = t + rng.uniform(0.02, 0.12)
        # The client ACK is a FORWARD packet: it survives the diode. This is
        # genuine forward-side evidence of completion, and we do not hide it.
        self._emit(t_ack, c, s, sport, dport, "tcp", 66, ACK, ttl, FORWARD, tls=tls)

        n_req = rng.randint(3, 25)
        cur = t_ack
        for _ in range(n_req):
            cur += rng.expovariate(1 / 0.35)
            if cur > self.config.duration_s:
                return
            self._emit(cur, c, s, sport, dport, "tcp", rng.randint(200, 900), PSH | ACK, ttl, FORWARD)
            # Response is typically much larger than the request.
            for _ in range(rng.randint(1, 6)):
                self._emit(cur + rng.uniform(0.02, 0.3), s, c, dport, sport, "tcp",
                           rng.randint(600, 1500), PSH | ACK, 55, REVERSE)
        self._emit(cur + 0.5, c, s, sport, dport, "tcp", 66, FIN | ACK, ttl, FORWARD)
        self._emit(cur + 0.6, s, c, dport, sport, "tcp", 66, FIN | ACK, 55, REVERSE)

    def _gen_dns_client(self) -> None:
        """Ordinary name resolution against an internal resolver."""
        rng = self.rng
        c, resolver = self._internal(), f"{self.config.internal_prefix}.2"
        t = rng.uniform(0, 120)
        while t < self.config.duration_s:
            q = rng.choice(BENIGN_DOMAINS)
            sport = rng.randint(32768, 60999)
            self._emit(t, c, resolver, sport, 53, "udp", rng.randint(60, 90), 0, 64, FORWARD, qname=q)
            self._emit(t + rng.uniform(0.005, 0.05), resolver, c, 53, sport, "udp",
                       rng.randint(90, 300), 0, 64, REVERSE, qname=q)
            t += rng.expovariate(1 / 12.0)

    def _gen_telemetry(self) -> None:
        """Benign periodic traffic — NTP / agent heartbeat / health check.

        This is the control that makes beacon detection non-trivial. Removing
        it would inflate our beacon numbers dishonestly.
        """
        rng = self.rng
        h = self._internal()
        collector = _rand_ip(rng, "10.20.40")
        interval = rng.choice([30.0, 60.0, 60.0, 120.0, 300.0])
        jitter = rng.uniform(0.02, 0.15)  # real agents jitter a little
        sport, dport = rng.randint(32768, 60999), rng.choice([123, 443, 8125, 9100])
        t = rng.uniform(0, interval)
        while t < self.config.duration_s:
            self._emit(t, h, collector, sport, dport, "udp" if dport == 123 else "tcp",
                       rng.randint(80, 260), PSH | ACK if dport != 123 else 0, 64, FORWARD)
            self._emit(t + rng.uniform(0.005, 0.06), collector, h, dport, sport,
                       "udp" if dport == 123 else "tcp", rng.randint(80, 200),
                       PSH | ACK if dport != 123 else 0, 58, REVERSE)
            t += self._jittered(interval, jitter)

    def _gen_bulk_transfer(self) -> None:
        """Large *inbound* download — the benign look-alike for exfiltration.

        Without this, 'large transfer' alone would separate exfil perfectly.
        """
        rng = self.rng
        t = rng.uniform(0, self.config.duration_s - 120)
        c, s = self._internal(), _rand_ip(rng)
        sport, dport = rng.randint(32768, 60999), rng.choice([443, 80, 21])
        self._emit(t, c, s, sport, dport, "tcp", 74, SYN, 64, FORWARD)
        self._emit(t + 0.05, s, c, dport, sport, "tcp", 74, SYN | ACK, 55, REVERSE)
        self._emit(t + 0.08, c, s, sport, dport, "tcp", 66, ACK, 64, FORWARD)
        cur, n = t + 0.1, rng.randint(400, 1600)
        for _ in range(n):
            cur += rng.expovariate(1 / 0.012)
            if cur > self.config.duration_s:
                break
            self._emit(cur, s, c, dport, sport, "tcp", 1500, PSH | ACK, 55, REVERSE)
            if rng.random() < 0.4:  # client ACKs periodically
                self._emit(cur + 0.001, c, s, sport, dport, "tcp", 66, ACK, 64, FORWARD)

    # ------------------------------------------------------------- attacks
    def _gen_ddos_syn(self) -> None:
        """(a) SYN flood from spoofed sources.

        Forward: a torrent of SYNs from many sources, and *no client ACK*.
        Reverse: the server's SYN-ACKs, which the diode does not see.
        Lost under ablation: half-open state. Retained: source dispersion.
        """
        rng = self.rng
        t0 = rng.uniform(0, self.config.duration_s - 90)
        victim = self._internal()
        dport = rng.choice([80, 443, 22, 3306])
        rate = rng.uniform(150, 600)  # packets/sec
        dur = rng.uniform(15, 50)
        n = int(rate * dur)
        for i in range(n):
            t = t0 + i / rate
            src = _rand_ip(rng)  # spoofed, near-unique per packet
            self._emit(t, src, victim, rng.randint(1024, 65535), dport, "tcp", 74, SYN,
                       rng.choice([44, 51, 118, 240]), FORWARD, label="ddos")
            self._emit(t + 0.001, victim, src, dport, rng.randint(1024, 65535), "tcp", 74,
                       SYN | ACK, 64, REVERSE, label="ddos")

    def _gen_ddos_amp(self) -> None:
        """(a) UDP reflection/amplification.

        The defining feature — a tiny query producing a huge response — lives
        entirely in the reverse direction. This is the class the diode hurts most.
        """
        rng = self.rng
        t0 = rng.uniform(0, self.config.duration_s - 60)
        victim = self._internal()
        dport = rng.choice(AMPLIFIER_PORTS)
        rate = rng.uniform(100, 400)
        dur = rng.uniform(12, 40)
        for i in range(int(rate * dur)):
            t = t0 + i / rate
            reflector = _rand_ip(rng)
            self._emit(t, victim, reflector, rng.randint(1024, 65535), dport, "udp",
                       rng.randint(50, 90), 0, 64, FORWARD, label="ddos")
            self._emit(t + rng.uniform(0.005, 0.05), reflector, victim, dport,
                       rng.randint(1024, 65535), "udp", rng.randint(2000, 4000), 0, 52,
                       REVERSE, label="ddos")

    def _gen_beacon(self) -> None:
        """(b) C2 beaconing — regular callbacks to a small destination set."""
        rng = self.rng
        host = self._internal()
        c2 = _rand_ip(rng)
        interval = rng.choice([15.0, 30.0, 45.0, 60.0, 90.0])
        jitter = rng.uniform(0.0, 0.12)  # tighter than benign telemetry, but overlapping
        dport = rng.choice([443, 8080, 8443, 53])
        t = rng.uniform(0, self.config.duration_s * 0.3)
        tls = rng.choice(MALWARE_TLS_FPS) if dport in (443, 8443) else None
        while t < self.config.duration_s:
            sport = rng.randint(32768, 60999)
            self._emit(t, host, c2, sport, dport, "tcp", rng.randint(120, 300), PSH | ACK,
                       64, FORWARD, label="beacon", tls=tls)
            self._emit(t + rng.uniform(0.05, 0.4), c2, host, dport, sport, "tcp",
                       rng.randint(100, 1200), PSH | ACK, 47, REVERSE, label="beacon")
            t += self._jittered(interval, jitter)

    def _gen_dga(self) -> None:
        """(c) DGA lookups and DNS tunnelling.

        Reverse direction carries NXDOMAIN — the classic signal, and it is lost.
        Forward direction carries the query name, whose entropy replaces it.
        """
        rng = self.rng
        host = self._internal()
        resolver = f"{self.config.internal_prefix}.2"
        tunnelling = rng.random() < 0.4
        t = rng.uniform(0, self.config.duration_s * 0.5)
        n = rng.randint(60, 400)
        for _ in range(n):
            q = _tunnel_name(rng) if tunnelling else _dga_name(rng)
            sport = rng.randint(32768, 60999)
            size = rng.randint(120, 280) if tunnelling else rng.randint(70, 110)
            self._emit(t, host, resolver, sport, 53, "udp", size, 0, 64, FORWARD,
                       label="dga", qname=q)
            # NXDOMAIN for DGA; large TXT for tunnelling. Both reverse-only.
            self._emit(t + rng.uniform(0.01, 0.09), resolver, host, 53, sport, "udp",
                       rng.randint(300, 900) if tunnelling else rng.randint(70, 120),
                       0, 64, REVERSE, label="dga", qname=q)
            t += rng.expovariate(1 / (0.6 if tunnelling else 3.0))
            if t > self.config.duration_s:
                break

    def _gen_scan(self) -> None:
        """(e) Reconnaissance: horizontal or vertical fan-out.

        RST responses are reverse-only. Fan-out cardinality is forward-side.
        """
        rng = self.rng
        src = self._internal()
        t = rng.uniform(0, self.config.duration_s - 60)
        vertical = rng.random() < 0.5
        rate = rng.uniform(30, 300)
        if vertical:
            target = self._internal()
            ports = rng.sample(range(1, 10000), rng.randint(300, 1500))
            pairs = [(target, p) for p in ports]
        else:
            port = rng.choice([22, 445, 3389, 80, 443])
            hosts = [self._internal() for _ in range(rng.randint(200, 900))]
            pairs = [(h, port) for h in hosts]
        for i, (dst, dp) in enumerate(pairs):
            ts = t + i / rate
            if ts > self.config.duration_s:
                break
            sport = rng.randint(32768, 60999)
            self._emit(ts, src, dst, sport, dp, "tcp", 74, SYN, 64, FORWARD, label="scan")
            self._emit(ts + 0.002, dst, src, dp, sport, "tcp", 66, RST | ACK, 64, REVERSE,
                       label="scan")

    def _gen_exfil(self) -> None:
        """(f) Outbound bulk exfiltration.

        The out:in byte ratio needs both directions. Forward-side substitute is
        absolute outbound volume against a per-host baseline — which is why
        benign bulk *downloads* exist in this generator as the confuser.
        """
        rng = self.rng
        host = self._internal()
        dst = _rand_ip(rng)
        dport = rng.choice([443, 22, 21, 8443])
        t = rng.uniform(0, self.config.duration_s - 180)
        sport = rng.randint(32768, 60999)
        self._emit(t, host, dst, sport, dport, "tcp", 74, SYN, 64, FORWARD, label="exfil")
        self._emit(t + 0.06, dst, host, dport, sport, "tcp", 74, SYN | ACK, 49, REVERSE,
                   label="exfil")
        self._emit(t + 0.09, host, dst, sport, dport, "tcp", 66, ACK, 64, FORWARD, label="exfil")
        cur = t + 0.1
        for _ in range(rng.randint(600, 2500)):
            cur += rng.expovariate(1 / 0.02)
            if cur > self.config.duration_s:
                break
            self._emit(cur, host, dst, sport, dport, "tcp", 1500, PSH | ACK, 64, FORWARD,
                       label="exfil")
            if rng.random() < 0.35:
                self._emit(cur + 0.002, dst, host, dport, sport, "tcp", 66, ACK, 49,
                           REVERSE, label="exfil")

    def _gen_encrypted_c2(self) -> None:
        """(d) Malware inside TLS.

        Server certificate and JA3S/JA4S are reverse-only. Client fingerprint
        rarity plus packet-size/timing sequence are what remain.
        """
        rng = self.rng
        host = self._internal()
        c2 = _rand_ip(rng)
        fp = rng.choice(MALWARE_TLS_FPS)
        t = rng.uniform(0, self.config.duration_s * 0.6)
        for _ in range(rng.randint(8, 30)):
            sport = rng.randint(32768, 60999)
            self._emit(t, host, c2, sport, 443, "tcp", 74, SYN, 64, FORWARD, label="encrypted")
            self._emit(t + 0.04, c2, host, 443, sport, "tcp", 74, SYN | ACK, 51, REVERSE,
                       label="encrypted")
            self._emit(t + 0.07, host, c2, sport, 443, "tcp", 66, ACK, 64, FORWARD,
                       label="encrypted", tls=fp)
            # Machine-generated request/response cadence: tight, low-variance sizes.
            cur = t + 0.1
            for _ in range(rng.randint(4, 14)):
                cur += rng.gauss(0.25, 0.03)
                self._emit(cur, host, c2, sport, 443, "tcp",
                           int(rng.gauss(180, 12)), PSH | ACK, 64, FORWARD, label="encrypted")
                self._emit(cur + 0.03, c2, host, 443, sport, "tcp",
                           int(rng.gauss(340, 40)), PSH | ACK, 51, REVERSE, label="encrypted")
            t += rng.uniform(40, 300)
            if t > self.config.duration_s:
                break

    # ---------------------------------------------------------------- driver
    def generate(self) -> List[Packet]:
        c = self.config
        for _ in range(c.n_web_sessions):
            self._gen_web_session()
        for _ in range(c.n_dns_clients):
            self._gen_dns_client()
        for _ in range(c.n_telemetry_hosts):
            self._gen_telemetry()
        for _ in range(c.n_bulk_transfers):
            self._gen_bulk_transfer()
        for _ in range(c.n_ddos_syn):
            self._gen_ddos_syn()
        for _ in range(c.n_ddos_amp):
            self._gen_ddos_amp()
        for _ in range(c.n_beacon):
            self._gen_beacon()
        for _ in range(c.n_dga):
            self._gen_dga()
        for _ in range(c.n_scan):
            self._gen_scan()
        for _ in range(c.n_exfil):
            self._gen_exfil()
        for _ in range(c.n_encrypted_c2):
            self._gen_encrypted_c2()

        self._raw.sort(key=lambda r: r[0])
        packets = [
            Packet(index=i, ts=r[0], src_ip=r[1], dst_ip=r[2], src_port=r[3], dst_port=r[4],
                   proto=r[5], size=r[6], flags=r[7], ttl=r[8], direction=r[9],
                   label=r[10], dns_qname=r[11], tls_fp=r[12])
            for i, r in enumerate(self._raw)
        ]
        self._raw.clear()
        return packets

    def __iter__(self) -> Iterator[Packet]:
        yield from self.generate()

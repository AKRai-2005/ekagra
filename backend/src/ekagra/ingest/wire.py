"""Wire-format parsers: DNS query names and JA3/JA3S/JA4 TLS fingerprints.

Why this exists
---------------
SIH26145 names two threat categories by the evidence that identifies them:

    (c) DGA domains and DNS tunnelling - "entropy and n-gram analysis of DNS
        query names, including anomalies in query length"
    (d) Malware in encrypted sessions - "JA3/JA3S or JA4 fingerprints,
        packet-size and timing patterns", without decryption

`features/protocol.py` computes those statistics and has done for a while. What
was missing was the step that produces their inputs from actual bytes: until
now `Packet.dns_qname` and `Packet.tls_fp` were populated by our own generator,
which drew fingerprints from a fixed list. The statistics were real; the source
was invented. This module closes that, so both features work on a live tap.

Where it runs, and why not on the record
----------------------------------------
`records.Packet` deliberately carries **no payload bytes** - the docstring there
makes the argument: a field that does not exist cannot be accidentally depended
on by feature code. So these are pure functions called at the ingest boundary,
turning bytes into a query name or a fingerprint string as the `Packet` is
constructed. Payload never lands on the record and never reaches the feature
layer.

Nothing here decrypts anything. A DNS query name travels in clear text, and a
JA3 fingerprint is computed entirely from the **unencrypted** ClientHello that
precedes the key exchange. That is the whole point of fingerprinting: it
identifies the client stack without touching the session.

The threat model these parsers are actually in
-----------------------------------------------
This is the one place in EKAGRA that reads adversary-controlled bytes. A sensor
that can be crashed or hung by a malformed packet is worse than no sensor,
because it fails exactly when someone wants it to. So every read here is
bounds-checked, every loop is bounded, and every parser returns `None` on
anything it does not fully understand rather than raising. `test_wire.py`
fuzzes both with random and truncated input and asserts no exception escapes.

Two specific hazards, both handled:

* **DNS compression pointers** can point backwards into a packet, and a crafted
  packet can point a label at itself - an infinite loop in a naive parser. Jumps
  are capped and every offset must move strictly backwards.
* **GREASE** (RFC 8701) values are injected by browsers into cipher and
  extension lists specifically to catch implementations that assume a fixed set.
  They are random per connection, so leaving them in makes every Chrome
  connection a unique fingerprint. They are stripped, per the JA3 spec.
"""

from __future__ import annotations

import hashlib
import struct
from typing import List, Optional, Tuple

# --------------------------------------------------------------------- limits
# All bounds, in one place, because "how much work can one packet cost me" is a
# security property and not a tuning knob.
MAX_QNAME_LEN = 255          # RFC 1035 s2.3.4
MAX_LABEL_LEN = 63           # RFC 1035 s2.3.4
MAX_LABELS = 128             # a 255-byte name cannot hold more
MAX_POINTER_JUMPS = 8        # compression is legal; a pointer chain is not
MAX_LIST_ITEMS = 512         # cipher suites / extensions / curves

DNS_HEADER_LEN = 12
TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SERVER_HELLO = 0x02
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B


def _is_grease(v: int) -> bool:
    """RFC 8701 GREASE: 0x0a0a, 0x1a1a, ... 0xfafa.

    Both bytes equal, low nibble 0xa. Browsers inject these at random to keep
    middleboxes honest; leaving them in would give every Chrome connection its
    own fingerprint and make fingerprint novelty meaningless.
    """
    return (v & 0x0F0F) == 0x0A0A and ((v >> 8) & 0xFF) == (v & 0xFF)


# ------------------------------------------------------------------------ DNS

def parse_dns_qname(payload: bytes, *, tcp: bool = False) -> Optional[str]:
    """First QNAME from a DNS message, lowercased, or None.

    `tcp=True` strips the two-byte length prefix DNS-over-TCP prepends.

    Returns None for anything that is not a well-formed query with at least one
    question - including responses, which we skip because the query name is
    already recorded from the request and counting it twice would double every
    per-host DNS statistic.
    """
    if not payload:
        return None
    if tcp:
        if len(payload) < 2:
            return None
        payload = payload[2:]
    if len(payload) < DNS_HEADER_LEN:
        return None

    try:
        flags, qdcount = struct.unpack_from("!HH", payload, 2)
    except struct.error:
        return None

    if flags & 0x8000:                 # QR bit: this is a response
        return None
    if (flags >> 11) & 0x0F:           # OPCODE != QUERY (0)
        return None
    if qdcount < 1:
        return None

    name = _read_name(payload, DNS_HEADER_LEN)
    return name


def _read_name(buf: bytes, off: int) -> Optional[str]:
    """Read a length-prefixed DNS name, following compression pointers safely.

    A pointer must point strictly *backwards*: that is what RFC 1035 intends and
    it is also what makes a cycle impossible, since each jump strictly decreases
    the offset. The jump cap is belt-and-braces on top of that.
    """
    labels: List[str] = []
    total = 0
    jumps = 0
    n = len(buf)
    lowest_seen = n

    while True:
        if off < 0 or off >= n:
            return None
        length = buf[off]

        if length == 0:                                  # end of name
            break

        if (length & 0xC0) == 0xC0:                      # compression pointer
            if off + 1 >= n:
                return None
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            jumps += 1
            if jumps > MAX_POINTER_JUMPS or ptr >= lowest_seen:
                return None                              # forward or repeated
            lowest_seen = ptr
            off = ptr
            continue

        if length & 0xC0:                                # reserved label type
            return None
        if length > MAX_LABEL_LEN:
            return None

        start = off + 1
        end = start + length
        if end > n:
            return None
        total += length + 1
        if total > MAX_QNAME_LEN or len(labels) >= MAX_LABELS:
            return None

        try:
            labels.append(buf[start:end].decode("ascii").lower())
        except UnicodeDecodeError:
            # Non-ASCII in a query name is either IDN punycode (which is ASCII
            # by construction) or junk. Junk is itself a DGA signal, so it is
            # kept rather than dropped, with unmappable bytes escaped.
            labels.append(buf[start:end].decode("ascii", "backslashreplace").lower())
        off = end

    if not labels:
        return None
    return ".".join(labels)


# ------------------------------------------------------------------------ TLS

def _u8(buf: bytes, off: int) -> Tuple[int, int]:
    if off + 1 > len(buf):
        raise IndexError
    return buf[off], off + 1


def _u16(buf: bytes, off: int) -> Tuple[int, int]:
    if off + 2 > len(buf):
        raise IndexError
    return struct.unpack_from("!H", buf, off)[0], off + 2


def _u16_list(buf: bytes, off: int, nbytes: int) -> Tuple[List[int], int]:
    """Read `nbytes` of 2-byte big-endian values, dropping GREASE."""
    if nbytes < 0 or off + nbytes > len(buf):
        raise IndexError
    if nbytes // 2 > MAX_LIST_ITEMS:
        raise IndexError
    out = []
    end = off + nbytes
    while off + 2 <= end:
        v = struct.unpack_from("!H", buf, off)[0]
        if not _is_grease(v):
            out.append(v)
        off += 2
    return out, end


def ja3_string(payload: bytes) -> Optional[str]:
    """The pre-hash JA3 string, or None if this is not a parseable ClientHello.

        SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats

    Returned separately from the digest because a fingerprint you cannot explain
    is not evidence. An analyst looking at an alert can read this and see which
    client stack it describes; the digest alone is opaque.
    """
    try:
        return _ja3(payload, client=True)
    except (IndexError, struct.error, ValueError):
        return None


def ja3s_string(payload: bytes) -> Optional[str]:
    """JA3S - the server's half: SSLVersion,Cipher,Extensions.

    On a one-way tap you will usually only see one side, so this is here for the
    mirrored-port deployment rather than the diode one. It costs twenty lines
    and its absence would be a question we could not answer.
    """
    try:
        return _ja3(payload, client=False)
    except (IndexError, struct.error, ValueError):
        return None


def _ja3(payload: bytes, *, client: bool) -> Optional[str]:
    if len(payload) < 6 or payload[0] != TLS_HANDSHAKE:
        return None

    # Record layer: type(1) version(2) length(2), then the handshake message.
    rec_len = struct.unpack_from("!H", payload, 3)[0]
    body = payload[5:5 + rec_len]
    want = TLS_CLIENT_HELLO if client else TLS_SERVER_HELLO
    if len(body) < 4 or body[0] != want:
        return None

    hs_len = int.from_bytes(body[1:4], "big")
    msg = body[4:4 + hs_len]

    off = 0
    version, off = _u16(msg, off)
    off += 32                                   # random
    sid_len, off = _u8(msg, off)
    off += sid_len
    if off > len(msg):
        raise IndexError

    if client:
        cs_bytes, off = _u16(msg, off)
        ciphers, off = _u16_list(msg, off, cs_bytes)
        comp_len, off = _u8(msg, off)
        off += comp_len
    else:
        one, off = _u16(msg, off)               # server picks exactly one
        ciphers = [] if _is_grease(one) else [one]
        off += 1                                # compression method

    curves: List[int] = []
    formats: List[int] = []
    exts: List[int] = []

    # Extensions are optional: a ClientHello may legally end here.
    if off + 2 <= len(msg):
        ext_total, off = _u16(msg, off)
        end = min(off + ext_total, len(msg))
        seen = 0
        while off + 4 <= end and seen < MAX_LIST_ITEMS:
            seen += 1
            etype, off = _u16(msg, off)
            elen, off = _u16(msg, off)
            if off + elen > end:
                raise IndexError
            data_end = off + elen
            if not _is_grease(etype):
                exts.append(etype)
            if client and etype == EXT_SUPPORTED_GROUPS and elen >= 2:
                n, p = _u16(msg, off)
                curves, _ = _u16_list(msg, p, min(n, elen - 2))
            elif client and etype == EXT_EC_POINT_FORMATS and elen >= 1:
                n, p = _u8(msg, off)
                n = min(n, elen - 1)
                if p + n > len(msg):
                    raise IndexError
                formats = list(msg[p:p + n])
            off = data_end

    j = "-".join
    if client:
        return (f"{version},{j(map(str, ciphers))},{j(map(str, exts))},"
                f"{j(map(str, curves))},{j(map(str, formats))}")
    return f"{version},{j(map(str, ciphers))},{j(map(str, exts))}"


def ja3(payload: bytes) -> Optional[str]:
    """JA3 fingerprint: MD5 of the JA3 string, or None.

    MD5 because the JA3 specification says MD5 - the value has to match the
    published threat-intelligence corpora (abuse.ch, Salesforce's own lists) or
    it is not a JA3 fingerprint and cannot be looked up. This is an identifier,
    not a security primitive: nothing authenticates it and collision resistance
    is irrelevant to what it is used for here. `evidence/bundle.py` uses SHA-256
    where integrity actually matters.
    """
    s = ja3_string(payload)
    return None if s is None else hashlib.md5(s.encode()).hexdigest()


def ja3s(payload: bytes) -> Optional[str]:
    s = ja3s_string(payload)
    return None if s is None else hashlib.md5(s.encode()).hexdigest()


# ------------------------------------------------------------------------ JA4
# JA3 is not enough on today's web, and the evidence for that came from a real
# capture rather than from reading about it. Across 97 ClientHellos from one
# laptop's browsing:
#
#     distinct JA3 strings              92
#     distinct extension SETS            7
#
# Chrome has randomised TLS extension *order* on every connection since v110
# (2023), deliberately, to stop middleboxes ossifying the protocol. JA3 hashes
# extensions in wire order, so it assigns almost every connection its own
# fingerprint - which makes "novel fingerprint" fire constantly on benign
# traffic and makes the feature worse than useless.
#
# JA4 (FoxIO) fixes exactly this by **sorting** the cipher and extension lists
# before hashing. The problem statement names "JA3/JA3S or JA4"; on modern
# traffic JA4 is the one that identifies a client stack rather than a
# connection. Both ship, and `RESULTS.md` records the measurement.

_SIG_ALGS_EXT = 0x000D
_SNI_EXT = 0x0000
_ALPN_EXT = 0x0010
_SUPPORTED_VERSIONS_EXT = 0x002B

_VERSION_NAMES = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
    0x0300: "s3", 0x0002: "s2",
}


def _ja4_version(legacy: int, supported: List[int]) -> str:
    """Highest offered version. `supported_versions` wins when present, because
    a TLS 1.3 hello still carries a legacy version of 1.2 for compatibility."""
    best = max(supported) if supported else legacy
    return _VERSION_NAMES.get(best, "00")


def ja4(payload: bytes, *, transport: str = "t") -> Optional[str]:
    """JA4 client fingerprint, or None if this is not a parseable ClientHello.

    Format `a_b_c`:
      a  transport, TLS version, SNI present, cipher count, extension count, ALPN
      b  12 hex of SHA-256 over the **sorted** cipher list
      c  12 hex of SHA-256 over the **sorted** extension list, then the
         signature algorithms in their original order

    `transport` is "t" for TCP and "q" for QUIC. We only produce "t" today - see
    `ingest/pcap.py` on why QUIC is out of reach without Initial decryption.
    """
    try:
        parsed = _parse_hello(payload)
    except (IndexError, struct.error, ValueError):
        return None
    if parsed is None:
        return None
    legacy, ciphers, ext_types, ext_data = parsed

    supported: List[int] = []
    raw = ext_data.get(_SUPPORTED_VERSIONS_EXT)
    if raw and len(raw) >= 1:
        n = min(raw[0], len(raw) - 1)
        for i in range(1, 1 + n - 1, 2):
            v = struct.unpack_from("!H", raw, i)[0]
            if not _is_grease(v):
                supported.append(v)

    sni = "d" if _SNI_EXT in ext_types else "i"

    alpn = "00"
    raw = ext_data.get(_ALPN_EXT)
    if raw and len(raw) >= 3:
        first_len = raw[2]
        if first_len and 3 + first_len <= len(raw):
            val = raw[3:3 + first_len]
            try:
                t = val.decode("ascii")
                alpn = t[0] + t[-1]
            except (UnicodeDecodeError, IndexError):
                alpn = "99"

    sigs: List[int] = []
    raw = ext_data.get(_SIG_ALGS_EXT)
    if raw and len(raw) >= 2:
        n = struct.unpack_from("!H", raw, 0)[0]
        n = min(n, len(raw) - 2)
        for i in range(2, 2 + n - 1, 2):
            v = struct.unpack_from("!H", raw, i)[0]
            if not _is_grease(v):
                sigs.append(v)

    # The count includes SNI and ALPN; the hashed list below does not. That
    # asymmetry is the spec's, not ours: the count still carries the signal
    # that they were present, while the hash stays stable when they are not.
    a = (f"{transport}{_ja4_version(legacy, supported)}{sni}"
         f"{min(len(ciphers), 99):02d}{min(len(ext_types), 99):02d}{alpn}")

    b = _trunc_sha256(",".join(f"{c:04x}" for c in sorted(ciphers))) \
        if ciphers else "000000000000"

    hashed_exts = sorted(e for e in ext_types if e not in (_SNI_EXT, _ALPN_EXT))
    if hashed_exts or sigs:
        c_src = ",".join(f"{e:04x}" for e in hashed_exts) + "_" \
            + ",".join(f"{s:04x}" for s in sigs)
        c = _trunc_sha256(c_src)
    else:
        c = "000000000000"

    return f"{a}_{b}_{c}"


def _trunc_sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _parse_hello(payload: bytes):
    """Shared ClientHello walk: (legacy_version, ciphers, ext_types, ext_data).

    Extension bodies are kept because JA4 needs to look inside three of them,
    where JA3 only ever needed the type numbers.
    """
    if len(payload) < 6 or payload[0] != TLS_HANDSHAKE:
        return None
    rec_len = struct.unpack_from("!H", payload, 3)[0]
    body = payload[5:5 + rec_len]
    if len(body) < 4 or body[0] != TLS_CLIENT_HELLO:
        return None
    hs_len = int.from_bytes(body[1:4], "big")
    msg = body[4:4 + hs_len]

    off = 0
    legacy, off = _u16(msg, off)
    off += 32
    sid_len, off = _u8(msg, off)
    off += sid_len
    if off > len(msg):
        raise IndexError

    cs_bytes, off = _u16(msg, off)
    ciphers, off = _u16_list(msg, off, cs_bytes)
    comp_len, off = _u8(msg, off)
    off += comp_len

    ext_types: List[int] = []
    ext_data: dict = {}
    if off + 2 <= len(msg):
        ext_total, off = _u16(msg, off)
        end = min(off + ext_total, len(msg))
        seen = 0
        while off + 4 <= end and seen < MAX_LIST_ITEMS:
            seen += 1
            etype, off = _u16(msg, off)
            elen, off = _u16(msg, off)
            if off + elen > end:
                raise IndexError
            if not _is_grease(etype):
                ext_types.append(etype)
                ext_data[etype] = msg[off:off + elen]
            off += elen
    return legacy, ciphers, ext_types, ext_data

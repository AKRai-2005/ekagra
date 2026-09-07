"""DNS and JA3 parsing, including the malformed input a sensor will actually see.

These parsers are the only code in EKAGRA that reads adversary-controlled bytes.
A sensor that can be crashed or hung by a crafted packet fails exactly when
someone wants it to, so roughly half of this file is hostile input rather than
happy paths.
"""

from __future__ import annotations

import hashlib
import random
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.ingest.wire import (  # noqa: E402
    MAX_QNAME_LEN, ja3, ja3_string, ja3s_string, parse_dns_qname, _is_grease,
)


# ------------------------------------------------------------------ builders

def dns_query(name: str, *, qtype: int = 1, flags: int = 0x0100,
              qdcount: int = 1) -> bytes:
    body = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, flags, qdcount, 0, 0, 0) + body \
        + struct.pack("!HH", qtype, 1)


def client_hello(version: int = 0x0301,
                 ciphers=(0x0A0A, 0x1301, 0xC02B),
                 exts=(0x1A1A, 0x0000, 0x000A, 0x000B),
                 curves=(0x001D, 0x0017),
                 formats=(0,),
                 padding: int = 0) -> bytes:
    """A ClientHello with GREASE deliberately present in ciphers and extensions.

    `padding` adds a TLS padding extension (RFC 7685) of that many bytes, which
    is how a real hello gets large - key shares, session tickets and padding,
    not hundreds of cipher suites.
    """
    ext_blob = b""
    if padding:
        ext_blob += struct.pack("!HH", 0x0015, padding) + bytes(padding)
    for e in exts:
        if e == 0x000A:
            data = struct.pack("!H", 2 * len(curves)) + b"".join(
                struct.pack("!H", c) for c in curves)
        elif e == 0x000B:
            data = bytes([len(formats)]) + bytes(formats)
        else:
            data = b""
        ext_blob += struct.pack("!HH", e, len(data)) + data

    body = struct.pack("!H", version) + b"\xAB" * 32 + b"\x00"      # no session id
    body += struct.pack("!H", 2 * len(ciphers))
    body += b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"                                              # compression
    body += struct.pack("!H", len(ext_blob)) + ext_blob

    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# ---------------------------------------------------------------------- DNS

def test_a_plain_query_name_is_read():
    assert parse_dns_qname(dns_query("www.example.com")) == "www.example.com"


def test_names_are_lowercased_so_a_host_is_one_host():
    """DNS is case-insensitive on the wire, and 0x20 encoding randomises case
    deliberately. Without folding, one domain would look like many novel ones
    and every DGA statistic would read high."""
    assert parse_dns_qname(dns_query("WwW.ExAmPlE.CoM")) == "www.example.com"


def test_a_long_dga_style_label_survives():
    name = "kq3v9v0m4wjq2p1x8lz.example.net"
    assert parse_dns_qname(dns_query(name)) == name


def test_responses_are_skipped_not_counted_twice():
    """The request already recorded this name. Counting the response as well
    would double every per-host DNS statistic."""
    assert parse_dns_qname(dns_query("a.b.com", flags=0x8180)) is None


def test_non_query_opcodes_are_skipped():
    assert parse_dns_qname(dns_query("a.b.com", flags=0x0900)) is None  # OPCODE 1


def test_zero_question_count_is_not_a_name():
    assert parse_dns_qname(dns_query("a.b.com", qdcount=0)) is None


def test_dns_over_tcp_length_prefix():
    msg = dns_query("tcp.example.com")
    assert parse_dns_qname(struct.pack("!H", len(msg)) + msg, tcp=True) == \
        "tcp.example.com"


def test_a_self_referential_compression_pointer_terminates():
    """The classic decompression-bomb shape. A naive parser loops forever here,
    which on a sensor means one packet stops all detection."""
    bomb = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xC0\x0C"
    assert parse_dns_qname(bomb) is None


def test_a_forward_pointer_is_refused():
    """Pointers must move strictly backwards; that is what makes a cycle
    impossible rather than merely unlikely."""
    msg = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xC0\x20" + b"\x00" * 32
    assert parse_dns_qname(msg) is None


def test_a_label_longer_than_the_buffer_is_refused():
    msg = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x3f" + b"ab"
    assert parse_dns_qname(msg) is None


def test_an_over_long_name_is_refused():
    name = ".".join("a" * 60 for _ in range(6))          # > 255 bytes
    assert len(name) > MAX_QNAME_LEN
    assert parse_dns_qname(dns_query(name)) is None


def test_truncated_dns_never_raises():
    full = dns_query("www.example.com")
    for i in range(len(full)):
        parse_dns_qname(full[:i])                        # must not raise


# ---------------------------------------------------------------------- JA3

def test_ja3_string_matches_the_specified_field_order():
    """SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats - with the
    GREASE values (0x0a0a, 0x1a1a) stripped per RFC 8701, which is what the
    JA3 spec requires and what makes the fingerprint stable across
    connections from the same client."""
    assert ja3_string(client_hello()) == "769,4865-49195,0-10-11,29-23,0"


def test_ja3_is_the_md5_of_that_string():
    s = ja3_string(client_hello())
    assert ja3(client_hello()) == hashlib.md5(s.encode()).hexdigest()


def test_grease_is_stripped_so_one_client_is_one_fingerprint():
    """Browsers inject different GREASE values per connection. Leaving them in
    would make every Chrome connection a unique, never-before-seen fingerprint
    and drive `hw_src_tls_fp_novel` to 1.0 for entirely benign traffic."""
    a = ja3(client_hello(ciphers=(0x0A0A, 0x1301), exts=(0x1A1A, 0x0000)))
    b = ja3(client_hello(ciphers=(0x2A2A, 0x1301), exts=(0xFAFA, 0x0000)))
    assert a == b and a is not None


def test_different_client_stacks_get_different_fingerprints():
    assert ja3(client_hello(ciphers=(0x1301,))) != ja3(client_hello(ciphers=(0xC02B,)))


def test_a_hello_with_no_extensions_is_still_a_fingerprint():
    """Legal, and older malware does exactly this. Trailing empty fields are
    part of the JA3 string, not an error."""
    assert ja3_string(client_hello(exts=())) == "769,4865-49195,,,"


def test_grease_detection_matches_rfc8701():
    for v in (0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA):
        assert _is_grease(v)
    for v in (0x1301, 0xC02B, 0x0000, 0x000A, 0x0A1A, 0x1A0A):
        assert not _is_grease(v)


def test_a_server_hello_is_not_read_as_a_client_hello():
    hello = bytearray(client_hello())
    hello[5] = 0x02                                       # ServerHello
    assert ja3_string(bytes(hello)) is None


def test_ja3s_reads_the_servers_single_cipher():
    body = struct.pack("!H", 0x0303) + b"\xCD" * 32 + b"\x00" \
        + struct.pack("!H", 0xC02F) + b"\x00" + struct.pack("!H", 0)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    assert ja3s_string(rec) == "771,49199,"


def test_non_tls_bytes_are_not_a_fingerprint():
    assert ja3(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    assert ja3(b"") is None


def test_truncated_client_hello_never_raises():
    full = client_hello()
    for i in range(len(full)):
        ja3(full[:i])                                     # must not raise


def test_a_lying_length_field_does_not_read_past_the_buffer():
    """Every field here is attacker-controlled, including the ones that say how
    long the other fields are."""
    hello = bytearray(client_hello())
    struct.pack_into("!H", hello, 3, 0xFFFF)              # record claims 64KB
    # Slicing past the end is safe in Python, so the parse still succeeds; what
    # matters is that it read only the bytes that exist and produced the same
    # fingerprint rather than trusting the claimed length.
    assert ja3(bytes(hello)) == ja3(client_hello())

    # Now a length that lies in the other direction: the cipher-list length
    # claims more than the message holds, which must be refused outright.
    hello2 = bytearray(client_hello())
    i = hello2.index(bytes([0xAB]) * 32) + 32 + 1               # past random + sid len
    struct.pack_into("!H", hello2, i, 0xFFFE)
    assert ja3(bytes(hello2)) is None


@pytest.mark.parametrize("seed", range(24))
def test_fuzz_random_bytes_never_raise(seed):
    rng = random.Random(seed)
    blob = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300)))
    parse_dns_qname(blob)
    parse_dns_qname(blob, tcp=True)
    ja3(blob)
    ja3s_string(blob)


@pytest.mark.parametrize("seed", range(24))
def test_fuzz_corrupted_valid_messages_never_raise(seed):
    """Bit-flips in an otherwise valid message find the paths random noise
    never reaches, because they keep the outer framing plausible."""
    rng = random.Random(seed)
    for msg, fn in ((dns_query("www.example.com"), parse_dns_qname),
                    (client_hello(), ja3)):
        b = bytearray(msg)
        for _ in range(rng.randrange(1, 6)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        fn(bytes(b))


# ---------------------------------------------------------------------- JA4
# JA3 is not usable on modern browser traffic and these tests pin why. Measured
# on a real 147 MB capture: 97 ClientHellos gave 92 distinct JA3 fingerprints
# and 7 distinct JA4 ones.

def hello_v13(ciphers=(0x1301, 0x1302), ext_order=(0x0000, 0x000A, 0x002B, 0x000D, 0x0010),
              alpn=b"h2", sigs=(0x0403, 0x0804)):
    """A TLS 1.3 hello with SNI, ALPN, signature algorithms and supported
    versions - the extensions JA4 actually reads into."""
    blob = b""
    for e in ext_order:
        if e == 0x000A:
            d = struct.pack("!H", 4) + struct.pack("!HH", 0x001D, 0x0017)
        elif e == 0x002B:
            d = bytes([2]) + struct.pack("!H", 0x0304)
        elif e == 0x000D:
            d = struct.pack("!H", 2 * len(sigs)) + b"".join(
                struct.pack("!H", s) for s in sigs)
        elif e == 0x0010:
            inner = bytes([len(alpn)]) + alpn
            d = struct.pack("!H", len(inner)) + inner
        elif e == 0x0000:
            d = b"\x00\x0e\x00\x00\x0b" + b"example.com"
        else:
            d = b""
        blob += struct.pack("!HH", e, len(d)) + d
    body = struct.pack("!H", 0x0303) + b"\x22" * 32 + b"\x00"
    body += struct.pack("!H", 2 * len(ciphers))
    body += b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00" + struct.pack("!H", len(blob)) + blob
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_ja4_is_stable_when_only_extension_order_changes():
    """The whole reason JA4 exists, and the reason JA3 failed on real traffic:
    Chrome has randomised extension order per connection since v110 to stop
    protocol ossification."""
    from ekagra.ingest.wire import ja4
    a = ja4(hello_v13(ext_order=(0x0000, 0x000A, 0x002B, 0x000D, 0x0010)))
    b = ja4(hello_v13(ext_order=(0x0010, 0x002B, 0x0000, 0x000D, 0x000A)))
    assert a == b is not None


def test_ja3_is_not_stable_under_the_same_reordering():
    """Stated as a test so the difference is a measured property of our code
    rather than a claim in a comment."""
    a = ja3(hello_v13(ext_order=(0x0000, 0x000A, 0x002B, 0x000D, 0x0010)))
    b = ja3(hello_v13(ext_order=(0x0010, 0x002B, 0x0000, 0x000D, 0x000A)))
    assert a != b


def test_ja4_header_fields_are_readable():
    """`a` is designed to be human-readable, which is why it is not hashed."""
    from ekagra.ingest.wire import ja4
    fp = ja4(hello_v13())
    a = fp.split("_")[0]
    assert a.startswith("t13d")            # TCP, TLS 1.3, SNI present
    assert a[4:6] == "02"                  # two cipher suites
    assert a[6:8] == "05"                  # five extensions (SNI+ALPN counted)
    assert a.endswith("h2")                # first ALPN value


def test_ja4_reports_no_sni_and_no_alpn():
    from ekagra.ingest.wire import ja4
    a = ja4(hello_v13(ext_order=(0x000A, 0x002B, 0x000D))).split("_")[0]
    assert a[3] == "i"                     # no SNI: an IP-addressed connection
    assert a.endswith("00")                # no ALPN


def test_ja4_version_comes_from_supported_versions_not_the_legacy_field():
    """A TLS 1.3 hello still advertises legacy_version 1.2 for compatibility.
    Reading the legacy field would label every modern client as TLS 1.2."""
    from ekagra.ingest.wire import ja4
    assert ja4(hello_v13()).startswith("t13")
    no_sv = ja4(hello_v13(ext_order=(0x0000, 0x000A, 0x000D, 0x0010)))
    assert no_sv.startswith("t12")

def test_ja4_distinguishes_client_stacks():
    from ekagra.ingest.wire import ja4
    assert ja4(hello_v13(ciphers=(0x1301,))) != ja4(hello_v13(ciphers=(0xC02F, 0xC030)))


def test_ja4_signature_algorithms_are_not_sorted():
    """Ciphers and extensions are sorted; signature algorithms are not, by
    specification - their order carries stack identity."""
    from ekagra.ingest.wire import ja4
    assert ja4(hello_v13(sigs=(0x0403, 0x0804))) != ja4(hello_v13(sigs=(0x0804, 0x0403)))


@pytest.mark.parametrize("seed", range(16))
def test_fuzz_ja4_never_raises(seed):
    from ekagra.ingest.wire import ja4
    rng = random.Random(seed)
    b = bytearray(hello_v13())
    for _ in range(rng.randrange(1, 8)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    ja4(bytes(b))
    ja4(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 200))))

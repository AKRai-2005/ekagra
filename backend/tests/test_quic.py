"""QUIC Initial decryption, checked against RFC 9001's own test vectors.

Crypto that "seems to work" is the most dangerous kind of code in this
repository: a key-derivation bug produces plausible-looking garbage rather than
an exception, and downstream every fingerprint would be wrong in a way no test
of ours would notice. So the derivation is pinned to the worked example in
RFC 9001 Appendix A, which is an external ground truth we cannot accidentally
satisfy with a matching bug on both sides.
"""

from __future__ import annotations

import random
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.ingest.quic import (  # noqa: E402
    INITIAL_SALT_V1, SALTS, QuicHelloAssembler, _hkdf_expand_label,
    _hkdf_extract, _initial_keys, _parse_long_header, _varint, crypto_frames,
    decrypt_initial, looks_like_quic_initial,
)

# RFC 9001 Appendix A.1 — the worked example everyone implements against.
RFC_DCID = bytes.fromhex("8394c8f03e515708")
RFC_INITIAL_SECRET = bytes.fromhex(
    "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
RFC_CLIENT_SECRET = bytes.fromhex(
    "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
RFC_CLIENT_KEY = bytes.fromhex("1f369613dd76d5467730efcbe3b1a22d")
RFC_CLIENT_IV = bytes.fromhex("fa044b2f42a3fd3b46fb255c")
RFC_CLIENT_HP = bytes.fromhex("9f50449e04a0e810283a1e9933adedd2")


def test_initial_secret_matches_rfc9001():
    assert _hkdf_extract(INITIAL_SALT_V1, RFC_DCID) == RFC_INITIAL_SECRET


def test_client_initial_secret_matches_rfc9001():
    initial = _hkdf_extract(INITIAL_SALT_V1, RFC_DCID)
    assert _hkdf_expand_label(initial, b"client in", 32) == RFC_CLIENT_SECRET


def test_derived_key_iv_and_header_protection_match_rfc9001():
    """The three values everything downstream depends on. If any one of these
    drifts, decryption still 'works' and returns plausible nonsense."""
    key, iv, hp = _initial_keys(0x00000001, RFC_DCID)
    assert key == RFC_CLIENT_KEY
    assert iv == RFC_CLIENT_IV
    assert hp == RFC_CLIENT_HP


def test_v2_uses_a_different_salt_and_labels():
    """QUIC v2 changed both deliberately so a v1 implementation cannot silently
    half-work on v2 traffic. Deriving the same keys would mean we ignored it."""
    assert SALTS[0x00000001] != SALTS[0x6B3343CF]
    assert _initial_keys(0x00000001, RFC_DCID) != _initial_keys(0x6B3343CF, RFC_DCID)


def test_an_unknown_quic_version_is_refused_not_guessed():
    assert _initial_keys(0xDEADBEEF, RFC_DCID) is None


# ------------------------------------------------------------------ varint

@pytest.mark.parametrize("encoded,value", [
    (b"\x25", 37),                                   # 1-byte form
    (b"\x7b\xbd", 15293),                            # 2-byte form
    (b"\x9d\x7f\x3e\x7d", 494878333),                # 4-byte form
])
def test_varint_matches_rfc9000_examples(encoded, value):
    assert _varint(encoded, 0) == (value, len(encoded))


def test_varint_refuses_to_read_past_the_buffer():
    assert _varint(b"\x9d\x7f", 0) is None           # claims 4 bytes, has 2


# ------------------------------------------------------------------ headers

def long_header(version=0x00000001, dcid=b"\x01" * 8, ptype=0x00, body=b"\x00" * 64):
    first = 0xC0 | ptype
    d = bytes([first]) + struct.pack("!I", version) + bytes([len(dcid)]) + dcid
    d += b"\x00"                                      # zero-length SCID
    d += b"\x00"                                      # zero-length token
    d += bytes([0x40 | ((len(body) >> 8) & 0x3F), len(body) & 0xFF])
    return d + body


def test_a_version_negotiation_packet_is_not_an_initial():
    assert _parse_long_header(long_header(version=0)) is None


def test_a_handshake_packet_is_not_treated_as_an_initial():
    """Handshake packets use keys derived from the TLS handshake, which a
    passive observer does not have and must not try to obtain."""
    assert _parse_long_header(long_header(ptype=0x20)) is None


def test_an_oversized_connection_id_is_refused():
    assert _parse_long_header(long_header(dcid=b"\x01" * 40)) is None


def test_short_header_packets_are_ignored():
    """1-RTT packets carry application data under keys we deliberately lack."""
    assert not looks_like_quic_initial(b"\x40" + b"\x00" * 40)
    assert _parse_long_header(b"\x40" + b"\x00" * 40) is None


def test_garbage_is_not_decryptable():
    assert decrypt_initial(b"\xc0\x00\x00\x00\x01" + b"\x00" * 80) is None


# ------------------------------------------------------------ CRYPTO frames

def test_crypto_frames_are_extracted_in_offset_order():
    payload = b"\x06\x00\x04abcd" + b"\x06\x04\x02ef"
    assert crypto_frames(payload) == [(0, b"abcd"), (4, b"ef")]


def test_padding_before_a_crypto_frame_is_skipped():
    """Client Initials are padded to 1200 bytes by RFC 9000, almost always
    with PADDING frames ahead of or around the CRYPTO frame."""
    assert crypto_frames(b"\x00" * 20 + b"\x06\x00\x03xyz") == [(0, b"xyz")]


def test_an_unknown_frame_type_stops_the_walk_rather_than_guessing():
    """Guessing an unknown frame's length is how a parser reads into the next
    frame's data and emits a fingerprint from bytes that were never a hello."""
    assert crypto_frames(b"\x1e" + b"\x06\x00\x03xyz") == []


def test_a_lying_crypto_length_is_refused():
    assert crypto_frames(b"\x06\x00\x44\xff" + b"ab") == []


# -------------------------------------------------------------- assembler

def test_the_assembler_ignores_non_initial_datagrams():
    a = QuicHelloAssembler()
    assert a.push(b"\x40" + b"\x00" * 60) is None
    assert a.completed == 0


def test_an_unknown_version_is_counted_not_attempted():
    a = QuicHelloAssembler()
    a.push(long_header(version=0xDEADBEEF))
    assert a.unknown_version == 1 and a.completed == 0


def test_an_undecryptable_initial_is_counted():
    a = QuicHelloAssembler()
    a.push(long_header())
    assert a.undecryptable == 1 and a.completed == 0


@pytest.mark.parametrize("seed", range(24))
def test_fuzz_never_raises(seed):
    """Adversary-controlled bytes reach every branch here."""
    rng = random.Random(seed)
    a = QuicHelloAssembler()
    blob = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 400)))
    a.push(blob)
    decrypt_initial(blob)
    crypto_frames(blob)
    _parse_long_header(blob)

    b = bytearray(long_header())
    for _ in range(rng.randrange(1, 8)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    a.push(bytes(b))

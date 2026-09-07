"""QUIC Initial decryption — reaching the ClientHello inside HTTP/3.

Why this exists
---------------
Measured on a real 147 MB capture of ordinary browsing, **UDP/443 outnumbered
TCP/443 80,291 to 32,069**. Most HTTPS is HTTP/3 now, and a QUIC ClientHello
does not sit in the clear the way a TLS-over-TCP one does — it is inside an
encrypted Initial packet. An earlier version of this project recorded that as a
hard ceiling on TLS fingerprint coverage.

That was wrong, and the reason is worth stating precisely because it sounds like
it cannot be true: **QUIC Initial packets are decryptable by anyone observing
them.** RFC 9001 §5.2 derives the Initial keys from the Destination Connection
ID — which travels in the clear in the packet header — using a *published*
salt. There is no secret. The encryption exists to stop middleboxes ossifying
the handshake, not to hide it from an observer.

So this is not an attack, and it is not payload decryption in the sense the
problem statement forbids. We never touch application data: the 1-RTT keys that
protect it come from the TLS handshake and are unavailable to a passive
observer. We decrypt exactly one thing — the handshake that is deliberately
readable — and we stop there.

What it gives us
----------------
`Packet.tls_fp` for QUIC connections, as a JA4 fingerprint with transport `q`
instead of `t`. That closes the coverage gap the capture exposed, and it is the
JA4 spec's own reason for having a transport character at all.

What it does not do
-------------------
- **Only Initial packets.** Handshake and 1-RTT packets use keys we do not have
  and must not have.
- **Only QUIC v1 and v2.** A draft or future version with a different salt is
  counted and skipped, not guessed at.
- **No 0-RTT.** Early data uses a different secret.
- Retry and Version Negotiation packets are recognised and ignored.

Like `wire.py`, this reads adversary-controlled bytes, so every length is
bounds-checked and every failure returns `None` rather than raising.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Dict, List, Optional, Tuple

# RFC 9001 §5.2. These are constants of the protocol, not secrets.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
SALTS = {0x00000001: INITIAL_SALT_V1, 0x6B3343CF: INITIAL_SALT_V2}

# RFC 9001 labels differ between v1 and v2 - v2 changed them deliberately so a
# v1 implementation cannot silently half-work on v2 traffic.
LABELS = {
    0x00000001: (b"quic key", b"quic iv", b"quic hp"),
    0x6B3343CF: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
}

LONG_HEADER = 0x80
FIXED_BIT = 0x40
TYPE_MASK = 0x30
TYPE_INITIAL_V1 = 0x00
TYPE_INITIAL_V2 = 0x10          # v2 renumbered the packet types

MAX_CID = 20                    # RFC 9000: connection IDs are at most 20 bytes
MAX_CRYPTO = 16_384             # a ClientHello cannot exceed a TLS record
MAX_PENDING = 4_096
CRYPTO_FRAME = 0x06
PADDING_FRAME = 0x00
PING_FRAME = 0x01


# ------------------------------------------------------------------- HKDF

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1), which QUIC reuses."""
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, prev, counter = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(secret, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:length]


def _varint(buf: bytes, off: int) -> Optional[Tuple[int, int]]:
    """QUIC variable-length integer (RFC 9000 §16). Two bits of length prefix."""
    if off >= len(buf):
        return None
    first = buf[off]
    n = 1 << (first >> 6)
    if off + n > len(buf):
        return None
    val = first & 0x3F
    for i in range(1, n):
        val = (val << 8) | buf[off + i]
    return val, off + n


# ------------------------------------------------------------- packet parse

def _parse_long_header(d: bytes) -> Optional[dict]:
    """Split a QUIC long header without decrypting anything yet."""
    if len(d) < 7 or not (d[0] & LONG_HEADER) or not (d[0] & FIXED_BIT):
        return None
    version = struct.unpack_from("!I", d, 1)[0]
    if version == 0:
        return None                                   # version negotiation
    off = 5

    dcid_len = d[off]
    off += 1
    if dcid_len > MAX_CID or off + dcid_len > len(d):
        return None
    dcid = d[off:off + dcid_len]
    off += dcid_len

    if off >= len(d):
        return None
    scid_len = d[off]
    off += 1
    if scid_len > MAX_CID or off + scid_len > len(d):
        return None
    off += scid_len

    want = TYPE_INITIAL_V2 if version == 0x6B3343CF else TYPE_INITIAL_V1
    if (d[0] & TYPE_MASK) != want:
        return None                                   # Handshake / 0-RTT / Retry

    tok = _varint(d, off)
    if tok is None:
        return None
    token_len, off = tok
    if token_len > len(d):
        return None
    off += token_len

    ln = _varint(d, off)
    if ln is None:
        return None
    length, off = ln
    if length < 4 or off + length > len(d):
        return None
    return {"version": version, "dcid": dcid, "pn_offset": off, "length": length}


def _initial_keys(version: int, dcid: bytes) -> Optional[Tuple[bytes, bytes, bytes]]:
    salt = SALTS.get(version)
    if salt is None:
        return None
    initial = _hkdf_extract(salt, dcid)
    client = _hkdf_expand_label(initial, b"client in", 32)
    k_lbl, iv_lbl, hp_lbl = LABELS[version]
    return (_hkdf_expand_label(client, k_lbl, 16),
            _hkdf_expand_label(client, iv_lbl, 12),
            _hkdf_expand_label(client, hp_lbl, 16))


def decrypt_initial(datagram: bytes) -> Optional[bytes]:
    """Decrypt one client Initial packet, returning its frame payload.

    Returns None for anything that is not a client Initial we can key, which
    includes server Initials (they use the server secret), Retry packets, and
    unknown QUIC versions.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:                                # pragma: no cover
        return None

    hdr = _parse_long_header(datagram)
    if hdr is None:
        return None
    keys = _initial_keys(hdr["version"], hdr["dcid"])
    if keys is None:
        return None
    key, iv, hp = keys

    pn_off = hdr["pn_offset"]
    # Header protection samples 16 bytes starting 4 past the packet-number
    # offset, because the sampler cannot know the packet-number length yet.
    sample_off = pn_off + 4
    if sample_off + 16 > len(datagram):
        return None
    sample = datagram[sample_off:sample_off + 16]

    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()

    first = datagram[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    if pn_off + pn_len > len(datagram):
        return None
    pn_bytes = bytes(datagram[pn_off + i] ^ mask[1 + i] for i in range(pn_len))
    pn = int.from_bytes(pn_bytes, "big")

    header = bytearray(datagram[:pn_off + pn_len])
    header[0] = first
    header[pn_off:pn_off + pn_len] = pn_bytes

    body_start = pn_off + pn_len
    body_end = hdr["pn_offset"] + hdr["length"]
    if body_end <= body_start or body_end > len(datagram):
        return None
    ciphertext = datagram[body_start:body_end]

    nonce = bytearray(iv)
    pn_full = pn.to_bytes(12, "big")
    for i in range(12):
        nonce[i] ^= pn_full[i]

    try:
        return AESGCM(key).decrypt(bytes(nonce), ciphertext, bytes(header))
    except Exception:
        # Wrong keys, a server Initial, or a truncated capture. All expected.
        return None


# ------------------------------------------------------------ CRYPTO frames

def crypto_frames(payload: bytes) -> List[Tuple[int, bytes]]:
    """Extract (offset, data) from the CRYPTO frames in a decrypted payload.

    Only the frame types a client Initial legitimately carries are walked.
    Anything else stops the walk rather than being skipped blindly, because
    guessing a frame length is how a parser reads into the next frame's data.
    """
    out: List[Tuple[int, bytes]] = []
    off = 0
    n = len(payload)
    guard = 0
    while off < n and guard < 512:
        guard += 1
        t = payload[off]
        if t == PADDING_FRAME:
            off += 1
            continue
        if t == PING_FRAME:
            off += 1
            continue
        if t != CRYPTO_FRAME:
            break
        off += 1
        got = _varint(payload, off)
        if got is None:
            break
        c_off, off = got
        got = _varint(payload, off)
        if got is None:
            break
        c_len, off = got
        if c_len > MAX_CRYPTO or off + c_len > n or c_off > MAX_CRYPTO:
            break
        out.append((c_off, payload[off:off + c_len]))
        off += c_len
    return out


class QuicHelloAssembler:
    """Rebuilds a ClientHello from the CRYPTO frames of one QUIC connection.

    A QUIC ClientHello is routinely split across several Initial packets - the
    same lesson TCP taught us, in a different encoding. Keyed on the connection
    ID rather than the 4-tuple, because QUIC survives address changes.
    """

    __slots__ = ("_pending", "completed", "undecryptable", "unknown_version")

    def __init__(self) -> None:
        self._pending: Dict[bytes, Dict[int, bytes]] = {}
        self.completed = 0
        self.undecryptable = 0
        self.unknown_version = 0

    def push(self, datagram: bytes) -> Optional[bytes]:
        hdr = _parse_long_header(datagram)
        if hdr is None:
            return None
        if hdr["version"] not in SALTS:
            self.unknown_version += 1
            return None

        payload = decrypt_initial(datagram)
        if payload is None:
            self.undecryptable += 1
            return None

        frames = crypto_frames(payload)
        if not frames:
            return None

        key = hdr["dcid"]
        parts = self._pending.get(key)
        if parts is None:
            if len(self._pending) >= MAX_PENDING:
                self._pending.pop(next(iter(self._pending)))
            parts = self._pending[key] = {}
        for c_off, data in frames:
            parts[c_off] = data

        buf = bytearray()
        while True:
            chunk = parts.get(len(buf))
            if chunk is None:
                break
            buf += chunk
            if len(buf) > MAX_CRYPTO:
                self._pending.pop(key, None)
                return None

        # A TLS handshake message: type(1) + 3-byte length.
        if len(buf) < 4 or buf[0] != 0x01:
            return None
        need = 4 + int.from_bytes(buf[1:4], "big")
        if len(buf) < need:
            return None

        self._pending.pop(key, None)
        self.completed += 1
        # `wire.ja4` expects a TLS *record*, so wrap the handshake message in
        # one. QUIC carries handshake messages without record framing.
        body = bytes(buf[:need])
        return b"\x16\x03\x01" + struct.pack("!H", len(body)) + body

    def stats(self) -> dict:
        return {"quic_hellos": self.completed,
                "quic_undecryptable": self.undecryptable,
                "quic_unknown_version": self.unknown_version}


def looks_like_quic_initial(datagram: bytes) -> bool:
    """Cheap pre-filter so we do not attempt key derivation on every datagram."""
    return len(datagram) >= 7 and bool(datagram[0] & LONG_HEADER) \
        and bool(datagram[0] & FIXED_BIT)

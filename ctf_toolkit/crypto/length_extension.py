"""Hash length extension attacks for Merkle-Damgard hashes (MD5, SHA-1, SHA-256).

Secret-prefix MAC forgery: given ``H(secret || msg)``, ``len(secret)`` (or the
total length) and a chosen ``append``, compute ``H(secret || msg || glue || append)``
plus the exact tail bytes ``glue || append`` -- without knowing the secret.

``hashlib`` cannot inject an intermediate state, so the compression functions
below are implemented from the public specs (RFC 1321, FIPS 180-4) and accept an
arbitrary starting state together with the number of bytes already absorbed.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass, field
from typing import Sequence

__all__ = [
    "LengthExtensionResult",
    "glue_padding_md",
    "glue_padding_sha",
    "length_extend",
    "length_extension",
    "length_extension_candidates",
    "md5_extend",
    "md5_pad",
    "reference_digest",
    "sha1_extend",
    "sha256_extend",
]

_MASK32 = 0xFFFFFFFF


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


# ---------------------------------------------------------------------------
# Glue padding
# ---------------------------------------------------------------------------

def _glue_padding(total_len: int, byteorder: str) -> bytes:
    """Padding that a hash would append to a message of ``total_len`` bytes.

    Layout: 0x80, zero bytes until the length is 56 mod 64, then the 64-bit
    bit-length of the message (endianness depends on the algorithm).
    """
    pad_len = 64 - (total_len % 64)
    if pad_len < 9:
        pad_len += 64
    return b"\x80" + b"\x00" * (pad_len - 9) + (total_len * 8).to_bytes(8, byteorder)  # type: ignore[arg-type]


def glue_padding_md(message_byte_len: int) -> bytes:
    """Merkle-Damgard glue padding for MD5 (little-endian length field)."""
    return _glue_padding(message_byte_len, "little")


def glue_padding_sha(message_byte_len: int) -> bytes:
    """Merkle-Damgard glue padding for SHA-1 / SHA-256 (big-endian length field)."""
    return _glue_padding(message_byte_len, "big")


def md5_pad(message_byte_len: int) -> bytes:
    """Alias for glue_padding_md."""
    return glue_padding_md(message_byte_len)


def _continue(
    compress,
    state: tuple[int, ...],
    processed_len: int,
    data: bytes,
    glue_padding,
    pack_state,
) -> bytes:
    """Absorb ``data`` starting from ``state`` after ``processed_len`` bytes.

    ``processed_len`` must be block-aligned (it is, by construction: original
    message + its glue padding always ends on a 64-byte boundary). The final
    padding is computed for the full virtual length processed_len + len(data).
    """
    if processed_len % 64 != 0:
        raise ValueError("processed_len must be a multiple of 64")
    tail = data + glue_padding(processed_len + len(data))
    for off in range(0, len(tail), 64):
        state = compress(state, tail[off:off + 64])
    return pack_state(state)


# ---------------------------------------------------------------------------
# MD5 (RFC 1321)
# ---------------------------------------------------------------------------

_MD5_S = (
    [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4
    + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
)
_MD5_K = [int(abs(math.sin(i + 1)) * (1 << 32)) & _MASK32 for i in range(64)]
_MD5_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)


def _md5_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    a, b, c, d = state
    words = struct.unpack("<16I", block)
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | ~d)
            g = (7 * i) % 16
        f = (f + a + _MD5_K[i] + words[g]) & _MASK32
        a, d, c, b = d, c, b, (b + _rotl32(f, _MD5_S[i])) & _MASK32
    return (
        (state[0] + a) & _MASK32,
        (state[1] + b) & _MASK32,
        (state[2] + c) & _MASK32,
        (state[3] + d) & _MASK32,
    )


def _md5_hash(data: bytes) -> bytes:
    """Full MD5 of ``data`` from the standard initial state (test support)."""
    return _continue(
        _md5_compress, _MD5_INIT, 0, data, glue_padding_md,
        lambda s: struct.pack("<4I", *s),
    )


def md5_extend(orig_digest_hex: str, orig_total_len: int, append: bytes) -> tuple[str, bytes]:
    """Extend an MD5 digest.

    ``orig_digest_hex`` is ``md5(secret || msg)`` and ``orig_total_len`` is
    ``len(secret || msg)``. Returns ``(new_digest_hex, glue + append)`` where
    the new digest equals ``md5(secret || msg || glue || append)``.
    """
    glue = glue_padding_md(orig_total_len)
    raw = bytes.fromhex(orig_digest_hex.strip())
    state = struct.unpack("<4I", raw)
    new_digest = _continue(
        _md5_compress, state, orig_total_len + len(glue), append,
        glue_padding_md, lambda s: struct.pack("<4I", *s),
    )
    return new_digest.hex(), glue + append


# ---------------------------------------------------------------------------
# SHA-1 (FIPS 180-4)
# ---------------------------------------------------------------------------

_SHA1_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
_SHA1_K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)


def _sha1_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d)
        elif i < 40:
            f = b ^ c ^ d
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
        else:
            f = b ^ c ^ d
        temp = (_rotl32(a, 5) + f + e + _SHA1_K[i // 20] + w[i]) & _MASK32
        e, d, c, b, a = d, c, _rotl32(b, 30), a, temp
    return tuple((s + v) & _MASK32 for s, v in zip(state, (a, b, c, d, e)))


def _sha1_hash(data: bytes) -> bytes:
    """Full SHA-1 of ``data`` from the standard initial state (test support)."""
    return _continue(
        _sha1_compress, _SHA1_INIT, 0, data, glue_padding_sha,
        lambda s: struct.pack(">5I", *s),
    )


def sha1_extend(orig_digest_hex: str, orig_total_len: int, append: bytes) -> tuple[str, bytes]:
    """Extend a SHA-1 digest. Same contract as :func:`md5_extend`."""
    glue = glue_padding_sha(orig_total_len)
    raw = bytes.fromhex(orig_digest_hex.strip())
    state = struct.unpack(">5I", raw)
    new_digest = _continue(
        _sha1_compress, state, orig_total_len + len(glue), append,
        glue_padding_sha, lambda s: struct.pack(">5I", *s),
    )
    return new_digest.hex(), glue + append


# ---------------------------------------------------------------------------
# SHA-256 (FIPS 180-4)
# ---------------------------------------------------------------------------

def _first_primes(count: int) -> list[int]:
    primes: list[int] = []
    candidate = 2
    while len(primes) < count:
        if all(candidate % p for p in primes if p * p <= candidate):
            primes.append(candidate)
        candidate += 1
    return primes


_SHA256_INIT = tuple(
    int((math.sqrt(p) % 1) * (1 << 32)) & _MASK32 for p in _first_primes(8)
)
_SHA256_K = tuple(
    int(((p ** (1.0 / 3.0)) % 1) * (1 << 32)) & _MASK32 for p in _first_primes(64)
)


def _sha256_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        big_s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + big_s1 + ch + _SHA256_K[i] + w[i]) & _MASK32
        big_s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big_s0 + maj) & _MASK32
        h, g, f, e, d, c, b, a = (
            g, f, e, (d + t1) & _MASK32, c, b, a, (t1 + t2) & _MASK32,
        )
    return tuple((s + v) & _MASK32 for s, v in zip(state, (a, b, c, d, e, f, g, h)))


def _sha256_hash(data: bytes) -> bytes:
    """Full SHA-256 of ``data`` from the standard initial state (test support)."""
    return _continue(
        _sha256_compress, _SHA256_INIT, 0, data, glue_padding_sha,
        lambda s: struct.pack(">8I", *s),
    )


def sha256_extend(orig_digest_hex: str, orig_total_len: int, append: bytes) -> tuple[str, bytes]:
    """Extend a SHA-256 digest. Same contract as :func:`md5_extend`."""
    glue = glue_padding_sha(orig_total_len)
    raw = bytes.fromhex(orig_digest_hex.strip())
    state = struct.unpack(">8I", raw)
    new_digest = _continue(
        _sha256_compress, state, orig_total_len + len(glue), append,
        glue_padding_sha, lambda s: struct.pack(">8I", *s),
    )
    return new_digest.hex(), glue + append


# ---------------------------------------------------------------------------
# Dispatcher & High-Level Structured API
# ---------------------------------------------------------------------------

_EXTENDERS = {
    "md5": md5_extend,
    "sha1": sha1_extend,
    "sha256": sha256_extend,
}

_GLUE_FUNCS = {
    "md5": glue_padding_md,
    "sha1": glue_padding_sha,
    "sha256": glue_padding_sha,
}


def length_extend(
    algorithm: str, orig_digest_hex: str, orig_total_len: int, append: bytes
) -> tuple[str, bytes]:
    """Length-extension dispatcher for ``\"md5\"`` / ``\"sha1\"`` / ``\"sha256\"``.

    Returns ``(new_digest_hex, glue + append)``; see :func:`md5_extend`.
    Raises ``ValueError`` for an unsupported algorithm.
    """
    algo = algorithm.lower().replace("-", "")
    try:
        extender = _EXTENDERS[algo]
    except KeyError:
        raise ValueError(f"unsupported algorithm: {algorithm!r}") from None
    return extender(orig_digest_hex, orig_total_len, append)


@dataclass
class LengthExtensionResult:
    """Full structured output of a length-extension forgery."""

    algorithm: str
    message: bytes
    digest: str
    glue_padding: bytes
    appended: bytes
    secret_len: int
    blocks_consumed: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def forged_message(self) -> bytes:
        return self.message

    def payload(self) -> bytes:
        """Just the bytes to put on the wire: glue padding + appended data."""
        return self.glue_padding + self.appended

    def header(self) -> str:
        return self.digest


def length_extension(
    algorithm: str,
    secret_len: int,
    message: bytes | str,
    append: bytes | str,
    digest: bytes | str | None = None,
) -> LengthExtensionResult:
    """Forge `H(secret || message || glue || append)` from `H(secret || message)`.

    `message` is the authenticated payload *without* the secret. `digest` must be
    the leaked digest of `secret || message`; pass it as hex str or raw bytes.
    `secret_len` is the guessed secret length (the glue padding depends on it).
    """
    if digest is None:
        raise ValueError("digest of secret||message is required")
    if secret_len < 0:
        raise ValueError("secret_len must be >= 0")

    algo = algorithm.lower().replace("-", "")
    if algo not in _EXTENDERS:
        raise ValueError(f"unsupported algorithm: {algorithm!r}")

    msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    app_bytes = append.encode("utf-8") if isinstance(append, str) else bytes(append)
    digest_hex = digest.hex() if isinstance(digest, bytes) else digest.strip().lower()

    total_len = secret_len + len(msg_bytes)
    glue = _GLUE_FUNCS[algo](total_len)
    new_digest, _ = _EXTENDERS[algo](digest_hex, total_len, app_bytes)

    total_blocks = (total_len + len(glue) + len(app_bytes) + len(_GLUE_FUNCS[algo](total_len + len(glue) + len(app_bytes)))) // 64

    return LengthExtensionResult(
        algorithm=algo,
        message=msg_bytes + glue + app_bytes,
        digest=new_digest,
        glue_padding=glue,
        appended=app_bytes,
        secret_len=secret_len,
        blocks_consumed=total_blocks,
        notes=[
            f"resumed from digest after {total_len} bytes",
            f"glue padding {len(glue)}B for secret_len={secret_len}",
        ],
    )


def length_extension_candidates(
    algorithm: str,
    digest: bytes | str,
    message: bytes | str,
    append: bytes | str,
    secret_lens: Sequence[int] | range | None = None,
) -> list[LengthExtensionResult]:
    """Brute the unknown secret length (1..32 by default) and return every forgery."""
    if secret_lens is None:
        secret_lens = range(1, 33)
    out: list[LengthExtensionResult] = []
    for k in secret_lens:
        out.append(length_extension(algorithm, k, message, append, digest))
    return out


def reference_digest(algorithm: str, secret: bytes, message: bytes) -> str:
    """Ground truth used by tests and by self-check against hashlib."""
    algo = algorithm.lower().replace("-", "")
    return hashlib.new(algo, secret + message).hexdigest()

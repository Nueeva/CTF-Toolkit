"""Length-extension forgery for MD5, SHA-1 and SHA-256 (pure stdlib).

The Merkle-Damgard construction exposes its internal state as the digest, so a
server that authenticates `H(secret || message)` can be forged without knowing
`secret`: resume the compression function from the leaked digest, feed the glue
padding for `len(secret) + len(message)` bytes, then append the attacker payload.

The glue padding length must be computed from the *secret-prefixed* length, so
callers pass `secret_len` (a guess) rather than the secret itself.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Callable, Literal

__all__ = [
    "LengthExtensionResult",
    "length_extension",
    "length_extension_candidates",
    "md5_pad",
]

_MASK32 = 0xFFFFFFFF

_MD5_K = (
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A,
    0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340,
    0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8,
    0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA,
    0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92,
    0xFFEFF47D, 0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
)

_MD5_S = (
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
)

_SHA1_K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)

_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotl32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & _MASK32 if n else x & _MASK32


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


# --------------------------------------------------------------------------- #
# compression functions: one 64-byte block in, updated state out
# --------------------------------------------------------------------------- #

def _md5_compress(state: list[int], block: bytes) -> list[int]:
    a, b, c, d = state
    m = struct.unpack("<16I", block)
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
            f = c ^ (b | (~d & _MASK32))
            g = (7 * i) % 16
        f = (f + a + _MD5_K[i] + m[g]) & _MASK32
        a, b, c, d = d, (b + _rotl32(f, _MD5_S[i])) & _MASK32, b, c
    return [
        (state[0] + a) & _MASK32,
        (state[1] + b) & _MASK32,
        (state[2] + c) & _MASK32,
        (state[3] + d) & _MASK32,
    ]


def _sha1_compress(state: list[int], block: bytes) -> list[int]:
    h0, h1, h2, h3, h4 = state
    w = list(struct.unpack(">16I", block)) + [0] * 64
    for i in range(16, 80):
        w[i] = _rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d & _MASK32)
            k = _SHA1_K[0]
        elif i < 40:
            f = b ^ c ^ d
            k = _SHA1_K[1]
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = _SHA1_K[2]
        else:
            f = b ^ c ^ d
            k = _SHA1_K[3]
        temp = (_rotl32(a, 5) + f + e + k + w[i]) & _MASK32
        e, d, c, b, a = d, c, _rotl32(b, 30), a, temp
    return [
        (h0 + a) & _MASK32,
        (h1 + b) & _MASK32,
        (h2 + c) & _MASK32,
        (h3 + d) & _MASK32,
        (h4 + e) & _MASK32,
    ]


def _sha256_compress(state: list[int], block: bytes) -> list[int]:
    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK32
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ (~e & g & _MASK32)
        t1 = (h + s1 + ch + _SHA256_K[i] + w[i]) & _MASK32
        s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & _MASK32
        h, g, f, e, d, c, b, a = (
            g, f, e, (d + t1) & _MASK32, c, b, a, (t1 + t2) & _MASK32,
        )
    return [
        (state[0] + a) & _MASK32,
        (state[1] + b) & _MASK32,
        (state[2] + c) & _MASK32,
        (state[3] + d) & _MASK32,
        (state[4] + e) & _MASK32,
        (state[5] + f) & _MASK32,
        (state[6] + g) & _MASK32,
        (state[7] + h) & _MASK32,
    ]


@dataclass(frozen=True)
class _Spec:
    block: int
    length_endian: Literal["little", "big"]
    word_endian: Literal["little", "big"]
    state_words: int
    digest_len: int
    compress: Callable[[list[int], bytes], list[int]]


_SPECS: dict[str, _Spec] = {
    "md5": _Spec(64, "little", "little", 4, 16, _md5_compress),
    "sha1": _Spec(64, "big", "big", 5, 20, _sha1_compress),
    "sha256": _Spec(64, "big", "big", 8, 32, _sha256_compress),
}

_ALIASES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha256": "sha256",
    "sha-256": "sha256",
}


def _spec(algorithm: str) -> _Spec:
    key = _ALIASES.get(algorithm.lower().strip())
    if key is None:
        raise ValueError(
            f"unsupported algorithm {algorithm!r}; use one of {sorted(_ALIASES)}"
        )
    return _SPECS[key]


def _glue_pad(msg_len: int, spec: _Spec) -> bytes:
    """Padding bytes that close a message of `msg_len` bytes into whole blocks."""
    pad_len = (spec.block - ((msg_len + 1 + 8) % spec.block)) % spec.block
    return b"\x80" + b"\x00" * pad_len + (msg_len * 8).to_bytes(8, spec.length_endian)


def md5_pad(msg_len: int) -> bytes:
    """MD5 glue padding for a message of `msg_len` bytes (little-endian bit count)."""
    return _glue_pad(msg_len, _SPECS["md5"])


def _state_from_digest(spec: _Spec, digest: bytes) -> list[int]:
    if len(digest) != spec.digest_len:
        raise ValueError(
            f"digest is {len(digest)} bytes, expected {spec.digest_len}"
        )
    words = struct.unpack(
        f"{spec.word_endian[0]}{spec.state_words}I".replace("b", ">").replace("l", "<"),
        digest,
    )
    return list(words)


def _digest_from_state(spec: _Spec, state: list[int]) -> bytes:
    fmt = "<" if spec.word_endian == "little" else ">"
    return struct.pack(f"{fmt}{spec.state_words}I", *state)


def _absorb(spec: _Spec, state: list[int], data: bytes) -> tuple[list[int], int]:
    """Compress every whole block in `data`; returns (state, bytes consumed)."""
    n = 0
    while len(data) - n >= spec.block:
        state = spec.compress(state, data[n:n + spec.block])
        n += spec.block
    return state, n


@dataclass
class LengthExtensionResult:
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
    `secret_len` is the guessed key length (the glue padding depends on it).
    """
    spec = _spec(algorithm)
    msg = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    app = append.encode("utf-8") if isinstance(append, str) else bytes(append)

    if digest is None:
        raise ValueError("digest of secret||message is required")
    if isinstance(digest, str):
        digest_bytes = bytes.fromhex(digest.strip())
    else:
        digest_bytes = bytes(digest)

    if secret_len < 0:
        raise ValueError("secret_len must be >= 0")

    consumed = secret_len + len(msg)
    glue = _glue_pad(consumed, spec)
    consumed += len(glue)

    state = _state_from_digest(spec, digest_bytes)

    # run the appended payload from the forged midstate
    state, used = _absorb(spec, state, app)
    consumed += used
    tail = app[used:]

    # close the forged message with its own glue padding
    final = tail + _glue_pad(consumed + len(tail), spec)
    state, _ = _absorb(spec, state, final)

    return LengthExtensionResult(
        algorithm=algorithm.lower(),
        message=msg + glue + app,
        digest=_digest_from_state(spec, state).hex(),
        glue_padding=glue,
        appended=app,
        secret_len=secret_len,
        blocks_consumed=(consumed + len(tail)) // spec.block,
        notes=[
            f"resumed from midstate after {secret_len + len(msg)} bytes",
            f"glue padding {len(glue)}B for secret_len={secret_len}",
        ],
    )


def length_extension_candidates(
    algorithm: str,
    digest: bytes | str,
    message: bytes | str,
    append: bytes | str,
    secret_lens: range | list[int] | None = None,
) -> list[LengthExtensionResult]:
    """Brute the unknown key length (1..32 by default) and return every forgery.

    Each candidate yields a distinct wire payload; keep the one the server accepts.
    """
    if secret_lens is None:
        secret_lens = range(1, 33)
    out: list[LengthExtensionResult] = []
    for k in secret_lens:
        out.append(length_extension(algorithm, k, message, append, digest))
    return out


def reference_digest(algorithm: str, secret: bytes, message: bytes) -> str:
    """Ground truth used by tests and by self-check against hashlib."""
    name = _ALIASES.get(algorithm.lower().strip())
    if name is None:
        raise ValueError(f"unsupported algorithm {algorithm!r}")
    return hashlib.new(name, secret + message).hexdigest()

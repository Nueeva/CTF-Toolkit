"""Dependency-free AES (ECB/CBC, 128/192/256) with PKCS#7 and zero-padding removal.

CTF boxes routinely ship without pycryptodome installed, so the cipher is
implemented here rather than assumed. Tables are derived from GF(2^8) arithmetic
instead of being pasted, so a typo cannot silently corrupt a solve; the NIST
vectors in `selftest()` are asserted by the test suite.
"""

from __future__ import annotations

__all__ = [
    "aes_encrypt_ecb",
    "aes_decrypt_ecb",
    "aes_encrypt_cbc",
    "aes_decrypt_cbc",
    "expand_key",
    "strip_padding",
]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _build_tables() -> tuple[list[int], list[int]]:
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    sbox = [0] * 256
    for a in range(256):
        x = inv[a]
        s = x
        for shift in range(1, 5):
            s ^= ((x << shift) | (x >> (8 - shift))) & 0xFF
        sbox[a] = s ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_tables()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def expand_key(key: bytes) -> tuple[list[list[int]], int]:
    """Return round keys as 16-byte lists and the round count for the key size."""
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES key must be 16/24/32 bytes, got {len(key)}")
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    round_keys: list[list[int]] = []
    for r in range(nr + 1):
        flat: list[int] = []
        for c in range(4):
            flat.extend(words[4 * r + c])
        round_keys.append(flat)
    return round_keys, nr


def _add_round_key(state: list[int], rk: list[int]) -> None:
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = SBOX[state[i]]


def _inv_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def _shift_rows(state: list[int]) -> None:
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            state[r + 4 * c] = row[c]


def _inv_shift_rows(state: list[int]) -> None:
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            state[r + 4 * c] = row[c]


def _mix_columns(state: list[int]) -> None:
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i:i + 4]
        state[i + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        state[i + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        state[i + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        state[i + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)


def _inv_mix_columns(state: list[int]) -> None:
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i:i + 4]
        state[i + 0] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        state[i + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        state[i + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        state[i + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)


def encrypt_block(block: bytes, round_keys: list[list[int]], nr: int) -> bytes:
    state = list(block)
    _add_round_key(state, round_keys[0])
    for rnd in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[nr])
    return bytes(state)


def decrypt_block(block: bytes, round_keys: list[list[int]], nr: int) -> bytes:
    state = list(block)
    _add_round_key(state, round_keys[nr])
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)


def _blocks(data: bytes) -> list[bytes]:
    if len(data) % 16:
        raise ValueError("ciphertext length is not a multiple of the block size")
    return [data[i:i + 16] for i in range(0, len(data), 16)]


def aes_encrypt_ecb(data: bytes, key: bytes) -> bytes:
    rk, nr = expand_key(key)
    if len(data) % 16:
        pad = 16 - len(data) % 16
        data = data + bytes([pad]) * pad
    return b"".join(encrypt_block(b, rk, nr) for b in _blocks(data))


def aes_decrypt_ecb(data: bytes, key: bytes) -> bytes:
    rk, nr = expand_key(key)
    return b"".join(decrypt_block(b, rk, nr) for b in _blocks(data))


def aes_encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    rk, nr = expand_key(key)
    if len(data) % 16:
        pad = 16 - len(data) % 16
        data = data + bytes([pad]) * pad
    prev = iv
    out = bytearray()
    for block in _blocks(data):
        xored = bytes(a ^ b for a, b in zip(block, prev))
        prev = encrypt_block(xored, rk, nr)
        out.extend(prev)
    return bytes(out)


def aes_decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    rk, nr = expand_key(key)
    prev = iv
    out = bytearray()
    for block in _blocks(data):
        plain = decrypt_block(block, rk, nr)
        out.extend(a ^ b for a, b in zip(plain, prev))
        prev = block
    return bytes(out)


def strip_padding(data: bytes) -> list[tuple[str, bytes]]:
    """Return plausible unpadded renderings: PKCS#7 valid, zero-trimmed, raw."""
    variants: list[tuple[str, bytes]] = []
    if data:
        pad = data[-1]
        if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
            variants.append((f"pkcs7({pad})", data[:-pad]))
    trimmed = data.rstrip(b"\x00")
    if trimmed != data:
        variants.append(("zero-trimmed", trimmed))
    variants.append(("raw", data))
    return variants

from __future__ import annotations


def reverse_string(text: str) -> str:
    """Reverse a string."""
    return text[::-1]


def endian_swap(data: bytes, word_size: int = 4) -> bytes:
    """Swap byte endianness within chunks of word_size."""
    if word_size <= 0:
        raise ValueError("word_size must be positive")

    result = bytearray()
    for i in range(0, len(data), word_size):
        chunk = data[i : i + word_size]
        result.extend(chunk[::-1])
    return bytes(result)


def byte_shift(data: bytes, shift: int) -> bytes:
    """Shift each byte value by a constant integer offset modulo 256."""
    return bytes([(b + shift) & 0xFF for b in data])


def byte_shift_bruteforce(data: bytes) -> list[tuple[int, float, bytes]]:
    """Bruteforce byte shift offsets against printable ASCII heuristic."""
    candidates: list[tuple[int, float, bytes]] = []
    for s in range(256):
        dec = byte_shift(data, s)
        printable = sum(1 for b in dec if 32 <= b <= 126)
        score = (printable / len(dec)) * 100.0 if dec else 0.0
        if score > 50.0:
            candidates.append((s, score, dec))
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates


def xor_bytes(data: bytes, key: bytes | int) -> bytes:
    """XOR byte sequence with a single byte or repeating key."""
    if isinstance(key, int):
        return bytes([b ^ (key & 0xFF) for b in data])
    if not key:
        return data
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def xor_bruteforce_single(data: bytes) -> list[tuple[int, float, bytes]]:
    """Bruteforce single-byte XOR against English character frequency heuristic."""
    freq = {
        ord(c): weight
        for c, weight in zip(
            "etaoinshrdlcumwfgypbvkjxqz",
            [12.7, 9.1, 8.2, 7.5, 7.0, 6.7, 6.3, 6.0, 6.0, 4.3, 4.0, 2.8, 2.8, 2.4, 2.4, 2.2, 2.0, 2.0, 1.9, 1.5, 1.0, 0.8, 0.15, 0.15, 0.10, 0.07],
        )
    }

    candidates: list[tuple[int, float, bytes]] = []
    for k in range(256):
        dec = bytes([b ^ k for b in data])
        score = 0.0
        valid_ascii = True
        for b in dec:
            if b in freq:
                score += freq[b]
            elif b == ord(" "):
                score += 15.0
            elif b in b"_{}.-:!\n\r\t":
                score += 5.0
            elif b < 32 or b > 126:
                score -= 20.0
                valid_ascii = False

        if valid_ascii or score > 0:
            candidates.append((k, score, dec))

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates


def extract_binary_strings(
    data: bytes, min_length: int = 4, pattern: str | None = None
) -> list[str]:
    """Extract printable strings from raw binary data with optional regex matching."""
    import re

    regex = re.compile(rb"[ -~]{" + str(min_length).encode() + rb",}")
    matches = [m.decode("latin1") for m in regex.findall(data)]
    if pattern:
        pat_re = re.compile(pattern, re.IGNORECASE)
        matches = [m for m in matches if pat_re.search(m)]
    return matches



def invert_index_xor(data: bytes) -> bytes:
    """Invert index-dependent XOR operation: out[i] = data[i] ^ i."""
    return bytes([b ^ (i & 0xFF) for i, b in enumerate(data)])


def invert_index_sub(data: bytes) -> bytes:
    """Invert index-dependent subtraction: out[i] = (data[i] + i) mod 256."""
    return bytes([(b + i) & 0xFF for i, b in enumerate(data)])


def invert_bitwise_not(data: bytes) -> bytes:
    """Invert bitwise NOT operation: out[i] = ~data[i] mod 256."""
    return bytes([(~b) & 0xFF for b in data])


def rotate_byte_right(data: bytes, shift: int = 3) -> bytes:
    """Circular right rotation of each byte by shift bits."""
    s = shift % 8
    return bytes([((b >> s) | ((b << (8 - s)) & 0xFF)) for b in data])


def invert_scaled_index_xor(data: bytes, scale: int = 7, xor_key: int = 0x5A) -> bytes:
    """Invert scaled index XOR feedback: out[i] = data[i] ^ (scale * i) ^ xor_key."""
    return bytes([b ^ ((scale * i) & 0xFF) ^ (xor_key & 0xFF) for i, b in enumerate(data)])


def invert_scaled_linear_add(data: bytes, scale: int = 3) -> bytes:
    """Invert scaled linear addition: out[i] = (data[i] - scale * i) mod 256."""
    return bytes([(b - scale * i) & 0xFF for i, b in enumerate(data)])


def invert_square_index_xor(data: bytes) -> bytes:
    """Invert square index XOR: out[i] = data[i] ^ ((i * i) & 0xFF)."""
    return bytes([b ^ ((i * i) & 0xFF) for i, b in enumerate(data)])


def invert_add_xor(data: bytes, add_c: int = 5, xor_k: int = 0x33) -> bytes:
    """Invert add then XOR: out[i] = ((data[i] ^ xor_k) - add_c) mod 256."""
    return bytes([((b ^ xor_k) - add_c) & 0xFF for b in data])


def invert_byte_negation(data: bytes) -> bytes:
    """Invert byte negation: out[i] = (-data[i]) mod 256."""
    return bytes([(-b) & 0xFF for b in data])


def invert_index_key_xor(data: bytes, xor_k: int = 0x11) -> bytes:
    """Invert indexed key XOR: out[i] = data[i] ^ (i & 0xFF) ^ xor_k."""
    return bytes([b ^ (i & 0xFF) ^ (xor_k & 0xFF) for i, b in enumerate(data)])


def invert_index_add_xor(data: bytes, xor_k: int = 0x77) -> bytes:
    """Invert index add then XOR: out[i] = ((data[i] ^ xor_k) - i) mod 256."""
    return bytes([((b ^ (xor_k & 0xFF)) - i) & 0xFF for i, b in enumerate(data)])


def invert_index_add(data: bytes) -> bytes:
    """Invert index addition: out[i] = (data[i] - i) mod 256."""
    return bytes([(b - i) & 0xFF for i, b in enumerate(data)])


def reverse_and_shift_bytes(data: bytes, shift: int = 3) -> bytes:
    """Invert reversed and shifted bytes: out = (data - shift)[::-1]."""
    return bytes([(b - shift) & 0xFF for b in data])[::-1]


def rotate_and_xor_byte(data: bytes, rot_left: int = 3, xor_k: int = 0x3C) -> bytes:
    """Invert left-rotate then XOR: out[i] = ROR(data[i] ^ xor_k, rot_left)."""
    s = rot_left % 8
    res = bytearray()
    for b in data:
        v = (b ^ xor_k) & 0xFF
        res.append(((v >> s) | ((v << (8 - s)) & 0xFF)))
    return bytes(res)



def invert_odd_multiplier(data: bytes, multiplier: int = 73) -> bytes:
    """Invert odd multiplication modulo 256."""
    inv = pow(multiplier, -1, 256)
    return bytes([(b * inv) & 0xFF for b in data])


def gray_decode(data: bytes) -> bytes:
    """Invert 8-bit binary-reflected Gray code to normal binary bytes."""
    res = bytearray()
    for g in data:
        b = g
        while g > 0:
            g >>= 1
            b ^= g
        res.append(b & 0xFF)
    return bytes(res)


def invert_rol_xor(data: bytes, rot_left: int = 2, xor_k: int = 0x1F) -> bytes:
    """Invert ROL then XOR: out[i] = ROR(data[i] ^ xor_k, rot_left)."""
    s = rot_left % 8
    res = bytearray()
    for b in data:
        t = b ^ (xor_k & 0xFF)
        res.append(((t >> s) | ((t << (8 - s)) & 0xFF)))
    return bytes(res)


def invert_ror_add(data: bytes, rot_right: int = 3, add_c: int = 9) -> bytes:
    """Invert ROR then ADD: out[i] = ROL((data[i] - add_c) mod 256, rot_right)."""
    s = rot_right % 8
    res = bytearray()
    for b in data:
        t = (b - add_c) & 0xFF
        res.append(((t << s) | (t >> (8 - s))) & 0xFF)
    return bytes(res)


def invert_compound_index_add(data: bytes, scale: int = 5, offset: int = 1) -> bytes:
    """Invert compound linear addition: out[i] = (data[i] - scale * i - offset) mod 256."""
    return bytes([(b - scale * i - offset) & 0xFF for i, b in enumerate(data)])


def invert_alternating_xor(data: bytes, val_even: int = 0xAA, val_odd: int = 0x55) -> bytes:
    """Invert alternating XOR: out[i] = data[i] ^ (val_odd if i & 1 else val_even)."""
    return bytes([b ^ (val_odd if (i & 1) else val_even) for i, b in enumerate(data)])


def invert_cbc_xor(data: bytes, iv: int = 0, xor_k: int = 0x5A) -> bytes:
    """Invert CBC-style feedback XOR: out[i] = data[i] ^ prev ^ xor_k; prev = data[i]."""
    res = bytearray()
    prev = iv & 0xFF
    for b in data:
        res.append(b ^ prev ^ (xor_k & 0xFF))
        prev = b
    return bytes(res)


def invert_cumulative_xor(data: bytes, initial_prev: int = 0x3C) -> bytes:
    """Invert cumulative prefix XOR: out[i] = data[i] ^ prev; prev = out[i]."""
    res = bytearray()
    prev = initial_prev & 0xFF
    for b in data:
        c = (b ^ prev) & 0xFF
        res.append(c)
        prev = c
    return bytes(res)


def lcg_keystream(seed: int, length: int, a: int = 0x41C64E6D, c: int = 0x3039, m: int = 0x7FFFFFFF) -> bytes:
    """Generate keystream bytes using 32-bit linear congruential generator."""
    res = bytearray()
    curr = seed
    for _ in range(length):
        curr = (curr * a + c) & m
        res.append((curr >> 16) & 0xFF)
    return bytes(res)


def invert_sbox(data: bytes, sbox: bytes) -> bytes:
    """Invert substitution box (S-box) lookup."""
    inv = {sbox[i]: i for i in range(len(sbox))}
    return bytes([inv[b] for b in data])


def caesar_ascii(text: str, shift: int, base: int = 32, modulus: int = 95) -> str:
    """Caesar cipher transformation over printable ASCII character range."""
    res = []
    for c in text:
        code = ord(c)
        if base <= code < base + modulus:
            res.append(chr((code - base + shift) % modulus + base))
        else:
            res.append(c)
    return "".join(res)


def rotate_left(data: bytes, k: int) -> bytes:
    """Cyclic left rotation of byte sequence (equivalent to C++ std::rotate(begin, begin + k, end))."""
    if not data:
        return data
    k = k % len(data)
    return data[k:] + data[:k]


def rotate_right(data: bytes, k: int) -> bytes:
    """Cyclic right rotation of byte sequence (inversion of left rotation)."""
    if not data:
        return data
    k = k % len(data)
    return data[-k:] + data[:-k]


def swap_adjacent(data: bytes) -> bytes:
    """Swap adjacent pairs of bytes: (data[0], data[1]), (data[2], data[3]), etc."""
    b = bytearray(data)
    for i in range(0, len(b) - 1, 2):
        b[i], b[i + 1] = b[i + 1], b[i]
    return bytes(b)


def bit_reverse_bytes(data: bytes) -> bytes:
    """Reverse bit order for each byte individually (bit 0 <-> bit 7, etc.)."""
    def _rev8(v: int) -> int:
        r = 0
        for j in range(8):
            if (v >> j) & 1:
                r |= 1 << (7 - j)
        return r
    return bytes([_rev8(b) for b in data])


def fibonacci_keystream(length: int, a: int = 1, b: int = 1) -> bytes:
    """Generate keystream of length bytes from Fibonacci recurrence modulo 256."""
    res = bytearray()
    curr_a, curr_b = a, b
    for _ in range(length):
        res.append(curr_a & 0xFF)
        curr_a, curr_b = curr_b, (curr_a + curr_b) & 0xFF
    return bytes(res)


def triangular_keystream(length: int) -> bytes:
    """Generate keystream of triangular numbers T(i) = i*(i+1)//2 modulo 256."""
    return bytes([((i * (i + 1) // 2) % 256) for i in range(length)])


def interleave_sequences(seq1: bytes | str, seq2: bytes | str) -> bytes | str:
    """Interleave two sequences alternatingly: seq1[0], seq2[0], seq1[1], seq2[1], ..."""
    is_bytes = isinstance(seq1, bytes)
    res = []
    i = 0
    while i < len(seq1) or i < len(seq2):
        if i < len(seq1):
            res.append(seq1[i])
        if i < len(seq2):
            res.append(seq2[i])
        i += 1
    if is_bytes:
        return bytes(res)
    return "".join(res)


def deinterleave_sequence(seq: bytes | str) -> tuple[bytes | str, bytes | str]:
    """Deinterleave sequence into even and odd index subsequences."""
    is_bytes = isinstance(seq, bytes)
    even = seq[0::2]
    odd = seq[1::2]
    if is_bytes:
        return bytes(even), bytes(odd)
    return "".join(even), "".join(odd)



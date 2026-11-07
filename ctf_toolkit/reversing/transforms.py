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

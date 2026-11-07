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

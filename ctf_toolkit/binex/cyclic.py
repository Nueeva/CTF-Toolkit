from __future__ import annotations

import itertools


UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGIT = "0123456789"


def cyclic_create(length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be >= 0")
    out = bytearray()
    for a, b, c in itertools.product(UPPER, LOWER, DIGIT):
        out.extend((a + b + c).encode())
        if len(out) >= length:
            return bytes(out[:length])
    return bytes(out[:length])


def cyclic_find(needle: bytes, max_len: int = 100_000) -> int:
    if not needle:
        return -1
    haystack = cyclic_create(max_len)
    return haystack.find(needle)

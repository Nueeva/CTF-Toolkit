from __future__ import annotations

UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGIT = "0123456789"
DEFAULT_ALPHABET = UPPER + LOWER + DIGIT


def _de_bruijn_sequence(alphabet: str, n: int) -> str:
    if n <= 0:
        raise ValueError("n must be >= 1")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet harus unik")
    if len(alphabet) < 2:
        raise ValueError("alphabet minimal 2 karakter")
    k = len(alphabet)
    a = [0] * (k * n)
    sequence: list[int] = []

    def _db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                sequence.extend(a[1 : p + 1])
            return
        a[t] = a[t - p]
        _db(t + 1, p)
        for j in range(a[t - p] + 1, k):
            a[t] = j
            _db(t + 1, t)

    _db(1, 1)
    return "".join(alphabet[idx] for idx in sequence)


def cyclic_create(length: int, alphabet: str = DEFAULT_ALPHABET, n: int = 3) -> bytes:
    if length < 0:
        raise ValueError("length must be >= 0")
    if length == 0:
        return b""
    sequence = _de_bruijn_sequence(alphabet, n)
    if not sequence:
        return b""
    repeats = (length // len(sequence)) + 1
    pattern = (sequence * repeats)[:length]
    return pattern.encode()


def cyclic_find(needle: bytes, max_len: int = 100_000, alphabet: str = DEFAULT_ALPHABET, n: int = 3) -> int:
    if not needle:
        return -1
    haystack = cyclic_create(max_len, alphabet=alphabet, n=n)
    return haystack.find(needle)

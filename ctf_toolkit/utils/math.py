from __future__ import annotations

from typing import Iterable


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1 and g != -1:
        raise ValueError("inverse modular tidak ada")
    return x % m


def crt(remainders: Iterable[int], moduli: Iterable[int]) -> tuple[int, int]:
    rs = list(remainders)
    ns = list(moduli)
    if len(rs) != len(ns) or not rs:
        raise ValueError("input CRT tidak valid")

    x = 0
    n_prod = 1
    for n in ns:
        n_prod *= n

    for r_i, n_i in zip(rs, ns):
        p = n_prod // n_i
        inv = modinv(p % n_i, n_i)
        x += r_i * inv * p

    return x % n_prod, n_prod


def integer_nthroot(value: int, n: int) -> tuple[int, bool]:
    if value < 0 or n <= 0:
        raise ValueError("input integer_nthroot tidak valid")
    if value in (0, 1):
        return value, True

    low, high = 0, value
    while low <= high:
        mid = (low + high) // 2
        power = mid**n
        if power == value:
            return mid, True
        if power < value:
            low = mid + 1
        else:
            high = mid - 1
    return high, high**n == value

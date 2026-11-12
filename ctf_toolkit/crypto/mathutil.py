"""Integer arithmetic used by the RSA/stream solvers.

Every routine here is deterministic and bounded: callers pass a deadline so a
pathological modulus degrades into "not solved in budget" instead of a hang.
"""

from __future__ import annotations

import math
import random
import time
from typing import Callable, Iterable

SMALL_PRIMES: list[int] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
]


class BudgetExceeded(RuntimeError):
    """Raised when a solver overruns its slice of the wall clock."""


def check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() > deadline:
        raise BudgetExceeded("time budget exhausted")


def egcd(a: int, b: int) -> tuple[int, int, int]:
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m} (gcd={g})")
    return x % m


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer k-th root; returns (root, exact)."""
    if n < 0:
        raise ValueError("negative radicand")
    if n in (0, 1) or k == 1:
        return n, True
    if k == 2:
        import math
        x = math.isqrt(n)
        return x, x * x == n
    # General k-th root via bit-length binary search
    bits = (n.bit_length() + k - 1) // k
    low = 1 << (bits - 1)
    high = 1 << (bits + 1)
    while low <= high:
        mid = (low + high) // 2
        p = pow(mid, k)
        if p == n:
            return mid, True
        elif p < n:
            low = mid + 1
        else:
            high = mid - 1
    return high, pow(high, k) == n


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def trial_division(n: int, limit: int = 1_000_000, deadline: float | None = None) -> int | None:
    for p in SMALL_PRIMES:
        if n % p == 0:
            return p
    f = SMALL_PRIMES[-1] + 2
    while f <= limit:
        if n % f == 0:
            return f
        f += 2
        if f % 100001 == 1:
            check_deadline(deadline)
    return None


def fermat_factor(n: int, max_iter: int = 5_000_000, deadline: float | None = None) -> tuple[int, int] | None:
    """Fast when |p - q| is small relative to n (the classic CTF close-prime case)."""
    if n % 2 == 0:
        return (2, n // 2)
    a, exact = iroot(n, 2)
    if exact:
        return (a, a)
    a += 1
    for i in range(max_iter):
        b2 = a * a - n
        b, exact = iroot(b2, 2)
        if exact:
            return (a - b, a + b)
        a += 1
        if i & 0x3FF == 0:
            check_deadline(deadline)
    return None


def pollard_rho(n: int, rounds: int = 32, deadline: float | None = None) -> int | None:
    if n % 2 == 0:
        return 2
    for _ in range(rounds):
        c = random.randrange(1, n)
        x = random.randrange(0, n)
        y, d = x, 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            check_deadline(deadline)
        if d != n:
            return d
    return None


def pollard_pm1(n: int, bound: int = 200_000, deadline: float | None = None) -> int | None:
    """Works when p-1 is B-smooth, which CTF authors reach for constantly."""
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        if j % 64 == 0:
            d = math.gcd(a - 1, n)
            if 1 < d < n:
                return d
            check_deadline(deadline)
    d = math.gcd(a - 1, n)
    return d if 1 < d < n else None


def factor_integer(n: int, deadline: float | None = None) -> tuple[int, int]:
    """Cascade: cheap paths first, each one bailing on the shared deadline."""
    check_deadline(deadline)
    if n <= 0:
        raise ValueError("modulus must be positive")
    if n < 4:
        raise ValueError("modulus too small to carry two factors")
    f = trial_division(n, 200_000, deadline)
    if f and 1 < f < n:
        return (f, n // f)
    check_deadline(deadline)
    got = fermat_factor(n, max_iter=200_000, deadline=deadline)
    if got:
        return got
    check_deadline(deadline)
    got = pollard_rho(n, rounds=24, deadline=deadline)
    if got and 1 < got < n:
        return (got, n // got)
    check_deadline(deadline)
    got = pollard_pm1(n, bound=50_000, deadline=deadline)
    if got and 1 < got < n:
        return (got, n // got)
    raise ValueError("factorisation budget exhausted on all strategies")


def wiener_attack(e: int, n: int) -> int | None:
    """Recover d when d is small enough that k/d approximates e/n."""
    a, b = e, n
    num0, num1 = 0, 1
    den0, den1 = 1, 0
    while b:
        q = a // b
        a, b = b, a - q * b
        num0, num1 = num1, q * num1 + num0
        den0, den1 = den1, q * den1 + den0
        k, d = num1, den1
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root, exact = iroot(disc, 2)
        if exact and (s + root) % 2 == 0:
            return d
    return None


def long_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def bytes_to_long(data: bytes) -> int:
    return int.from_bytes(data, "big")


def candidate_texts(value: int) -> list[tuple[str, bytes]]:
    """Byte renderings of a recovered integer, ordered by how CTF authors pack flags."""
    out: list[tuple[str, bytes]] = [(f"big({value.bit_length()}b)", long_to_bytes(value))]
    width = (value.bit_length() + 7) // 8
    if width > 1:
        out.append(("little", value.to_bytes(width, "little")))
    for pad in (8, 16, 32, 64, 128, 256):
        if width < pad:
            out.append((f"big-pad{pad}", value.to_bytes(pad, "big")))
    return out

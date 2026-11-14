"""GF(2^8) arithmetic, CRT in the integers, and polynomial ops over GF(2).

Every routine here is pure-Python integer math so the AES solver, Reed-Solomon
recovery and CRC/linear-algebra paths share one correct substrate.
"""

from __future__ import annotations

from typing import Iterable, Sequence

__all__ = [
    "gf256_mul",
    "gf256_inv",
    "gf256_pow",
    "gf256_tables",
    "gf_find_generator",
    "rs_syndrome",
    "rs_berlekamp_massey",
    "rs_chien_search",
    "rs_forney_roots",
    "crt",
    "crt_combine",
    "poly2_mod",
    "poly2_mul",
    "poly2_divmod",
    "poly2_gcd",
]

_AES_EXP: list[int] = [0] * 512
_AES_LOG: list[int] = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _AES_EXP[i] = x
        _AES_LOG[x] = i
        # multiply by the field generator 0x03: xtime(x) XOR x
        x = (x ^ (x << 1)) & 0x1FF
        if x & 0x100:
            x ^= 0x11B
        x &= 0xFF
    for i in range(255, 512):
        _AES_EXP[i] = _AES_EXP[i - 255]


_init_tables()


def gf256_tables() -> tuple[list[int], list[int]]:
    """Return (exp, log) tables for the AES field, generator 0x03."""
    return _AES_EXP[:], _AES_LOG[:]


def gf256_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) with the AES reduction polynomial 0x11B."""
    if a == 0 or b == 0:
        return 0
    return _AES_EXP[_AES_LOG[a] + _AES_LOG[b]]


def gf256_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no multiplicative inverse in GF(2^8)")
    return _AES_EXP[255 - _AES_LOG[a]]


def gf256_pow(a: int, n: int) -> int:
    if n < 0:
        return gf256_pow(gf256_inv(a), -n)
    result, base = 1, a
    while n:
        if n & 1:
            result = gf256_mul(result, base)
        base = gf256_mul(base, base)
        n >>= 1
    return result


def gf_find_generator() -> int:
    """Smallest primitive element of the AES field; 0x03 for 0x11B."""
    for cand in range(2, 256):
        seen = set()
        x = 1
        for _ in range(255):
            seen.add(x)
            x = gf256_mul(x, cand)
        if len(seen) == 255 and x == 1:
            return cand
    raise RuntimeError("no primitive element found")


# --------------------------------------------------------------------------- #
# Reed-Solomon over GF(2^8): syndromes -> BM -> Chien -> Forney
# --------------------------------------------------------------------------- #

def rs_syndrome(block: Sequence[int], nsym: int) -> list[int]:
    """Compute the 2t..nsym syndromes S_i = r(alpha^i), i = 0..nsym-1."""
    return [rs_eval(block, gf256_pow(0x02, i + 1)) for i in range(nsym)]


def rs_eval(poly: Sequence[int], x: int) -> int:
    """Evaluate a big-endian coefficient polynomial at x in GF(2^8)."""
    acc = 0
    for coef in poly:
        acc = gf256_mul(acc, x) ^ (coef & 0xFF)
    return acc


def rs_berlekamp_massey(syndromes: Sequence[int]) -> list[int]:
    """Berlekamp-Massey over GF(2^8); returns the error locator, lowest degree first."""
    C = [1]
    B = [1]
    L = 0
    m = 1
    b = 1
    for n in range(len(syndromes)):
        d = syndromes[n]
        for i in range(1, L + 1):
            if i < len(C):
                d ^= gf256_mul(C[i], syndromes[n - i])
        if d == 0:
            m += 1
            continue
        coef = gf256_mul(d, gf256_inv(b))
        T = C[:]
        need = len(B) + m
        if len(C) < need:
            C += [0] * (need - len(C))
        for j in range(len(B)):
            C[j + m] ^= gf256_mul(coef, B[j])
        if 2 * L <= n:
            L = n + 1 - L
            B = T
            b = d
            m = 1
        else:
            m += 1
    return C[: L + 1]


def rs_chien_search(locator: Sequence[int], n: int, generator: int = 0x02) -> list[int]:
    """Find error positions for a block of length n using the locator polynomial."""
    positions: list[int] = []
    deg = len(locator) - 1
    for i in range(n):
        # evaluate locator at alpha^-i
        x_inv = gf256_pow(generator, (255 - i) % 255)
        if rs_eval(locator[::-1], x_inv) == 0:
            positions.append(i)
    if len(positions) != deg:
        return positions  # caller decides whether this is recoverable
    return positions


def rs_forney_roots(syndromes: Sequence[int], positions: Sequence[int], n: int) -> list[int]:
    """Forney: error magnitudes for the located positions (1-indexed exponent form)."""
    locator = rs_berlekamp_massey(syndromes)
    omega = [0] * max(1, len(syndromes))
    for i, s in enumerate(syndromes):
        for j, c in enumerate(locator):
            if i + j < len(omega):
                omega[i + j] ^= gf256_mul(c, s)
    magnitudes: list[int] = []
    for pos in positions:
        x_i = gf256_pow(0x02, n - 1 - pos)
        x_i_inv = gf256_inv(x_i)
        num = rs_eval(omega[::-1], x_i_inv)
        den = 1
        for pos2 in positions:
            if pos2 == pos:
                continue
            x_j = gf256_pow(0x02, n - 1 - pos2)
            den = gf256_mul(den, 1 ^ gf256_mul(x_i_inv, x_j))
        magnitudes.append(gf256_mul(num, gf256_inv(den)) if den else 0)
    return magnitudes


# --------------------------------------------------------------------------- #
# Integer CRT
# --------------------------------------------------------------------------- #

def crt(remainders: Iterable[int], moduli: Iterable[int]) -> tuple[int, int]:
    """Chinese Remainder Theorem over the integers; returns (x, product)."""
    rs = list(remainders)
    ms = list(moduli)
    if len(rs) != len(ms) or not rs:
        raise ValueError("remainders and moduli must be non-empty and equal length")
    x, m = 0, 1
    for r, mod in zip(rs, ms):
        g, p, _ = _egcd(m, mod)
        if (r - x) % g:
            raise ValueError("inconsistent CRT system")
        lcm = m // g * mod
        t = ((r - x) // g * p) % (mod // g)
        x = (x + m * t) % lcm
        m = lcm
    return x % m, m


def crt_combine(pairs: Sequence[tuple[int, int]]) -> tuple[int, int]:
    """CRT from (remainder, modulus) pairs."""
    return crt([p[0] for p in pairs], [p[1] for p in pairs])


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


# --------------------------------------------------------------------------- #
# GF(2) polynomials, represented as ints (LSB = x^0)
# --------------------------------------------------------------------------- #

def poly2_deg(p: int) -> int:
    return p.bit_length() - 1


def poly2_mod(a: int, m: int) -> int:
    if m == 0:
        raise ZeroDivisionError("polynomial modulus is zero")
    dm = poly2_deg(m)
    while a and poly2_deg(a) >= dm:
        a ^= m << (poly2_deg(a) - dm)
    return a


def poly2_mul(a: int, b: int) -> int:
    out = 0
    i = 0
    while b:
        if b & 1:
            out ^= a << i
        b >>= 1
        i += 1
    return out


def poly2_divmod(a: int, b: int) -> tuple[int, int]:
    if b == 0:
        raise ZeroDivisionError("polynomial divisor is zero")
    q = 0
    db = poly2_deg(b)
    while a and poly2_deg(a) >= db:
        shift = poly2_deg(a) - db
        q ^= 1 << shift
        a ^= b << shift
    return q, a


def poly2_gcd(a: int, b: int) -> int:
    while b:
        a, b = b, poly2_mod(a, b)
    return a

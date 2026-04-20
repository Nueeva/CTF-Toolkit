from __future__ import annotations

from math import isqrt

from ctf_toolkit.utils.math import crt, egcd, integer_nthroot, modinv


def rsa_encrypt(m: int, n: int, e: int) -> int:
    return pow(m, e, n)


def rsa_decrypt(c: int, n: int, d: int) -> int:
    return pow(c, d, n)


def common_modulus_attack(c1: int, e1: int, c2: int, e2: int, n: int) -> int:
    g, a, b = egcd(e1, e2)
    if abs(g) != 1:
        raise ValueError("e1 and e2 must be coprime")

    def _pow_signed(base: int, exp: int, mod: int) -> int:
        if exp >= 0:
            return pow(base, exp, mod)
        inv = modinv(base, mod)
        return pow(inv, -exp, mod)

    m1 = _pow_signed(c1, a, n)
    m2 = _pow_signed(c2, b, n)
    return (m1 * m2) % n


def hastad_broadcast(ciphertexts: list[int], moduli: list[int], e: int) -> int:
    if len(ciphertexts) < e or len(ciphertexts) != len(moduli):
        raise ValueError("insufficient number of (c, n) pairs")
    c_combined, _ = crt(ciphertexts, moduli)
    root, exact = integer_nthroot(c_combined, e)
    if not exact:
        raise ValueError("e-th root is not exact; data may not satisfy Hastad assumptions")
    return root


def fermat_factor(n: int, max_iter: int = 1_000_000) -> tuple[int, int] | None:
    if n % 2 == 0:
        return (2, n // 2)

    a = isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p * q == n and p > 1:
                return (min(p, q), max(p, q))
        a += 1
    return None


def phi_from_primes(primes: list[int]) -> int:
    if not primes:
        raise ValueError("empty prime factors list")
    phi = 1
    for p in primes:
        phi *= p - 1
    return phi


def private_exponent_from_factors(e: int, factors: list[int]) -> int:
    phi = phi_from_primes(factors)
    return modinv(e, phi)

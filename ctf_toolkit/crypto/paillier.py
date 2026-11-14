"""Paillier homomorphic cryptosystem primitives and solvers (pure stdlib).

Supports:
- Key generation, encryption, and decryption
- Additive homomorphism: D(c1 * c2 mod n^2) = (m1 + m2) mod n
- Scalar multiplication: D(c^k mod n^2) = (k * m) mod n
- Decryption from known prime factors (p, q)
- Automated challenge solving from ciphertext and factored modulus
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "PaillierPublicKey",
    "PaillierPrivateKey",
    "paillier_keygen",
    "paillier_encrypt",
    "paillier_decrypt",
    "paillier_homomorphic_add",
    "paillier_homomorphic_mul",
    "paillier_solve_known_factors",
    "paillier_auto_solve",
]


def _l_function(u: int, n: int) -> int:
    """L(u) = (u - 1) // n."""
    return (u - 1) // n


@dataclass(frozen=True)
class PaillierPublicKey:
    n: int
    g: int

    @property
    def n2(self) -> int:
        return self.n * self.n

    def encrypt(self, m: int, r: Optional[int] = None) -> int:
        return paillier_encrypt(m, self.n, self.g, r)

    def add(self, c1: int, c2: int) -> int:
        return paillier_homomorphic_add(c1, c2, self.n)

    def mul(self, c: int, k: int) -> int:
        return paillier_homomorphic_mul(c, k, self.n)


@dataclass(frozen=True)
class PaillierPrivateKey:
    p: int
    q: int
    n: int
    g: int

    @property
    def lam(self) -> int:
        return math.lcm(self.p - 1, self.q - 1)

    def decrypt(self, c: int) -> int:
        return paillier_decrypt(c, self.p, self.q, self.n, self.g)


def paillier_keygen(p: int, q: int, g: Optional[int] = None) -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Generate public and private Paillier keys from primes p and q."""
    if p <= 1 or q <= 1 or p == q:
        raise ValueError("p and q must be distinct primes > 1")
    n = p * q
    if g is None:
        g = n + 1
    pub = PaillierPublicKey(n, g)
    priv = PaillierPrivateKey(p, q, n, g)
    return pub, priv


def paillier_encrypt(m: int, n: int, g: Optional[int] = None, r: Optional[int] = None) -> int:
    """Encrypt message m under Paillier public key (n, g).

    c = g^m * r^n mod n^2
    """
    if g is None:
        g = n + 1
    n2 = n * n
    if r is None:
        # Generate coprime r in [1, n-1]
        r = random.randrange(2, n)
        while math.gcd(r, n) != 1:
            r = random.randrange(2, n)
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c


def paillier_decrypt(c: int, p: int, q: int, n: Optional[int] = None, g: Optional[int] = None) -> int:
    """Decrypt ciphertext c given private prime factors p and q."""
    if n is None:
        n = p * q
    if g is None:
        g = n + 1
    n2 = n * n
    lam = math.lcm(p - 1, q - 1)
    # L(c^lambda mod n^2)
    u_c = pow(c, lam, n2)
    l_c = _l_function(u_c, n)

    # mu = L(g^lambda mod n^2)^-1 mod n
    u_g = pow(g, lam, n2)
    l_g = _l_function(u_g, n)
    mu = pow(l_g, -1, n)

    m = (l_c * mu) % n
    return m


def paillier_homomorphic_add(c1: int, c2: int, n: int) -> int:
    """Homomorphic addition of two encrypted ciphertexts: c = c1 * c2 mod n^2."""
    n2 = n * n
    return (c1 * c2) % n2


def paillier_homomorphic_mul(c: int, k: int, n: int) -> int:
    """Homomorphic scalar multiplication: c_k = c^k mod n^2."""
    n2 = n * n
    return pow(c, k, n2)


def paillier_solve_known_factors(c: int, p: int, q: int, g: Optional[int] = None) -> int:
    """Decryption wrapper when p and q factors are provided."""
    return paillier_decrypt(c, p, q, p * q, g)


def paillier_auto_solve(c: int, n: int, p: Optional[int] = None, q: Optional[int] = None, g: Optional[int] = None) -> int | None:
    """Solve Paillier challenge automatically by factoring n if needed."""
    if p is not None and q is not None:
        return paillier_decrypt(c, p, q, n, g)

    # Attempt factor if n is moderate
    from ctf_toolkit.crypto.rsa import factor_integer_auto
    res = factor_integer_auto(n)
    if res and isinstance(res, tuple) and len(res) == 2:
        factors, _ = res
        if len(factors) == 2:
            return paillier_decrypt(c, int(factors[0]), int(factors[1]), n, g)

    return None

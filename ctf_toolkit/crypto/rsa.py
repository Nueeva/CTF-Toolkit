from __future__ import annotations

from math import isqrt

from ctf_toolkit.utils.math import crt, egcd, integer_nthroot, modinv


def rsa_encrypt(m: int, n: int, e: int) -> int:
    return pow(m, e, n)


def rsa_decrypt(c: int, n: int, d: int) -> int:
    return pow(c, d, n)


def int_to_bytes(val: int) -> bytes:
    """Convert a large non-negative integer to bytes."""
    if val == 0:
        return b"\x00"
    length = (val.bit_length() + 7) // 8
    return val.to_bytes(length, byteorder="big")


def rsa_solve_pqec(p: int, q: int, e: int, c: int) -> bytes:
    """Decrypt textbook RSA given prime factors p, q, public exponent e, and ciphertext c."""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    m = pow(c, d, n)
    return int_to_bytes(m)


def rsa_solve_phi_e_c(n: int, phi: int, e: int, c: int) -> bytes:
    """Decrypt textbook RSA given modulus n, Euler totient phi, public exponent e, and ciphertext c."""
    d = modinv(e, phi)
    m = pow(c, d, n)
    return int_to_bytes(m)


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


def integer_nth_root(val: int, n: int) -> int:
    """Compute exact or floor integer nth root of a positive integer."""
    if val < 0:
        raise ValueError("Cannot compute root of negative integer")
    if val == 0:
        return 0
    low = 0
    high = 1 << ((val.bit_length() + n - 1) // n * n)
    while low < high:
        mid = (low + high) // 2
        if mid ** n < val:
            low = mid + 1
        else:
            high = mid
    return low if low ** n == val else low - 1


def rsa_cube_root(ciphertext: int) -> int:
    """Recover plaintext for unpadded e=3 RSA when m^3 < n."""
    return integer_nth_root(ciphertext, 3)


def rsa_multiprime_decrypt(factors: list[int], e: int, c: int) -> int:
    """Decrypt RSA ciphertext given multi-prime factors of n."""
    n = 1
    phi = 1
    for p in factors:
        n *= p
        phi *= (p - 1)
    d = pow(e, -1, phi)
    return pow(c, d, n)


def pollard_p_minus_1(n: int, B: int = 1000) -> int | None:
    """Factor n using Pollard's p - 1 algorithm if p - 1 is B-smooth."""
    import math
    a = 2
    for j in range(2, B + 1):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None


def rsa_crt_reconstruct(c: int, p: int, q: int, dp: int, dq: int, qinv: int) -> int:
    """Reconstruct RSA plaintext using Garner's algorithm for CRT."""
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    h = (qinv * (m1 - m2)) % p
    return m2 + h * q


def shamir_reconstruct_secret(shares: list[tuple[int, int]], p: int) -> int:
    """Reconstruct secret from Shamir's Secret Sharing shares at x=0."""
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        num, den = 1, 1
        for m, (xm, _) in enumerate(shares):
            if m != j:
                num = (num * -xm) % p
                den = (den * (xj - xm)) % p
        secret = (secret + yj * num * pow(den, -1, p)) % p
    return secret


def wiener_attack(e: int, n: int) -> int | None:
    """Wiener continued fractions attack to recover small private exponent d < (1/3) * n^(1/4)."""
    import math

    # Continued fractions expansion of e / n
    cf: list[int] = []
    num, den = e, n
    while den != 0:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den

    # Compute convergents
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    for q in cf:
        h = q * h1 + h0
        k = q * k1 + k0
        h0, h1 = h1, h
        k0, k1 = k1, k
        if h == 0 or k == 0:
            continue
        if (e * k - 1) % h != 0:
            continue
        phi = (e * k - 1) // h
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            sq = math.isqrt(disc)
            if sq * sq == disc and (s + sq) % 2 == 0:
                p = (s + sq) // 2
                q_val = (s - sq) // 2
                if p * q_val == n:
                    return k
    return None

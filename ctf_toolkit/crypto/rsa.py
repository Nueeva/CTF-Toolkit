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


def rsa_factor_small(
    n: int,
    e: int = 65537,
    c: int | None = None,
    limit: int = 1_000_000,
) -> tuple[int, int] | bytes | None:
    """
    Factor RSA modulus n with a small prime factor p <= limit.
    If ciphertext c is given, returns decrypted plaintext bytes; otherwise returns (p, q).
    """
    if n % 2 == 0:
        p, q = 2, n // 2
        return rsa_solve_pqec(p, q, e, c) if c is not None else (p, q)
    d = 3
    bound = min(limit, isqrt(n))
    while d <= bound:
        if n % d == 0:
            p, q = d, n // d
            return rsa_solve_pqec(p, q, e, c) if c is not None else (p, q)
        d += 2
    return None


def rsa_fermat(n: int, e: int = 65537, c: int | None = None, max_iter: int = 1_000_000) -> tuple[int, int] | bytes | None:
    """Factor RSA modulus n via Fermat factorization; decrypts c if provided."""
    factors = fermat_factor(n, max_iter=max_iter)
    if factors is None:
        return None
    p, q = factors
    return rsa_solve_pqec(p, q, e, c) if c is not None else (p, q)


def rsa_wiener(e: int, n: int, c: int | None = None) -> int | bytes | None:
    """Recover private exponent d via Wiener continued-fraction attack; decrypts c if provided."""
    d = wiener_attack(e, n)
    if d is None:
        return None
    if c is not None:
        return int_to_bytes(pow(c, d, n))
    return d


def hastad_unpadded(ciphertext: int, e: int = 3) -> bytes:
    """Recover plaintext bytes from unpadded small-e RSA when m^e < n."""
    m = integer_nth_root(ciphertext, e)
    return int_to_bytes(m)


def _merge_cofactor(factor: int, cofactor: int) -> tuple[int, int] | list[int] | None:
    """Combine one found factor with its cofactor into a full factorization.

    Returns a (p, q) pair when the cofactor is prime; for a composite
    cofactor (multi-prime modulus) recursively factors it and returns the
    full list. Returns None when the cofactor cannot be factored, so the
    caller falls through to the next strategy instead of reporting a
    factor pair whose second element is secretly composite.
    """
    if cofactor <= 1:
        return None
    try:
        import sympy

        if sympy.isprime(cofactor):
            return (min(factor, cofactor), max(factor, cofactor))
    except Exception:
        pass
    try:
        sub_factors, _sub_strategy = factor_integer_auto(cofactor)
        flat: list[int] = []
        if isinstance(sub_factors, (list, tuple)):
            flat.extend(int(x) for x in sub_factors)
        if flat and all(cofactor % f == 0 for f in flat):
            merged = sorted([factor] + flat)
            if len(merged) == 2:
                return (merged[0], merged[1])
            return merged
    except Exception:
        pass
    return None


def factor_integer_auto(n: int) -> tuple[tuple[int, int] | list[int], str]:
    """
    Attempt automated factorization of composite modulus `n` using an adaptive cascade:
    1. Small prime trial division (up to 1,000,000)
    2. Fermat's factorization for close primes
    3. Pollard's p - 1 algorithm for B-smooth primes
    4. Pollard's rho algorithm for medium-sized factors
    5. SymPy factorint fallback

    Returns a `(factors, strategy)` pair: `factors` is a (p, q) tuple or a
    list of prime factors; `strategy` names the method that succeeded
    ("trial_division", "fermat", "pollard_p_minus_1", "pollard_rho", "sympy").
    """
    if n <= 1:
        return [n], "trivial"

    # 1. Trial division up to 1,000,000 (peel every small factor;
    # rsa_factor_small returns a (factor, cofactor) pair, not a lone prime)
    peeled: list[int] = []
    rest = n
    while rest > 1:
        pair = rsa_factor_small(rest, limit=1_000_000)
        if not isinstance(pair, tuple) or pair[0] >= rest:
            break
        peeled.append(pair[0])
        rest = pair[1]
    if peeled:
        import sympy as _sympy

        full: list[int] = []
        if rest == 1:
            full = peeled
        elif _sympy.isprime(rest):
            full = peeled + [rest]
        if len(full) >= 2:
            full.sort()
            if len(full) == 2:
                return (full[0], full[1]), "trial_division"
            return full, "trial_division"

    # 2. Fermat factor
    p_fermat = fermat_factor(n, max_iter=200_000)
    if p_fermat is not None:
        p, q = p_fermat if isinstance(p_fermat, tuple) else (p_fermat, n // p_fermat)
        return (min(p, q), max(p, q)), "fermat"

    # 3. Pollard p - 1
    p_pollard = pollard_p_minus_1(n, B=500_000)
    if p_pollard is not None and 1 < p_pollard < n:
        q = n // p_pollard
        merged = _merge_cofactor(p_pollard, q)
        if merged is not None:
            return merged, "pollard_p_minus_1"

    # 4. Pollard's rho
    def _pollard_rho(val: int) -> int | None:
        import math
        x = 2
        y = 2
        d = 1
        c = 1
        f = lambda z: (z * z + c) % val
        for _ in range(500_000):
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), val)
            if d == val:
                return None
            if d > 1:
                return d
        return None

    p_rho = _pollard_rho(n)
    if p_rho is not None and 1 < p_rho < n:
        q = n // p_rho
        merged = _merge_cofactor(p_rho, q)
        if merged is not None:
            return merged, "pollard_rho"

    # 5. Sympy fallback
    try:
        import sympy
        factors_dict = sympy.factorint(n)
        res = []
        for prime, exp in factors_dict.items():
            res.extend([prime] * exp)
        if len(res) == 2:
            return (min(res), max(res)), "sympy"
        return res, "sympy"
    except Exception:
        pass

    raise ValueError(f"Unable to factor integer {n} using automated methods")


def solve_rsa_auto(n: int, e: int, c: int) -> bytes:
    """Automatically factor modulus n and decrypt ciphertext c into plaintext bytes."""
    factors, _strategy = factor_integer_auto(n)
    # Normalize the factors element to a flat list of primes (it is either
    # a (p, q) tuple or a list of prime factors).
    flat: list[int] = []
    if isinstance(factors, (list, tuple)):
        for f in factors:
            if isinstance(f, (list, tuple)):
                flat.extend(int(x) for x in f)
            elif isinstance(f, int):
                flat.append(f)
    if len(flat) == 2:
        p, q = flat
        phi = (p - 1) * (q - 1)
        d = modinv(e, phi)
        m = pow(c, d, n)
        return int_to_bytes(m)
    if len(flat) > 2:
        return int_to_bytes(rsa_multiprime_decrypt(flat, e, c))
    raise ValueError(f"Unsupported factor shape: {factors}")


# --------------------------------------------------------------------------- #
# Bleichenbacher '06 RSA Signature Forgery (low exponent e=3 PKCS#1 v1.5)
# --------------------------------------------------------------------------- #

_SHA256_ASN1 = bytes.fromhex("3031300d060960864801650304020105000420")
_SHA1_ASN1 = bytes.fromhex("3021300906052b0e03021a05000414")
_MD5_ASN1 = bytes.fromhex("3020300c06082a864886f70d020505000410")


def bleichenbacher_forge_signature(
    message: bytes | str,
    key_size_bits: int = 1024,
    hash_algo: str = "sha256",
    e: int = 3,
) -> int:
    """Forge a PKCS#1 v1.5 RSA signature under low public exponent (e=3)

    Exploits verifiers that check the prefix `00 01 FF ... 00 ASN.1 HASH` and
    ignore trailing garbage bytes at the end of the unpadded buffer.
    """
    import hashlib

    msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    algo = hash_algo.lower().replace("-", "")
    if algo == "sha256":
        asn1 = _SHA256_ASN1
        h = hashlib.sha256(msg_bytes).digest()
    elif algo == "sha1":
        asn1 = _SHA1_ASN1
        h = hashlib.sha1(msg_bytes).digest()
    elif algo == "md5":
        asn1 = _MD5_ASN1
        h = hashlib.md5(msg_bytes).digest()
    else:
        raise ValueError(f"unsupported hash algorithm: {hash_algo!r}")

    key_bytes = key_size_bits // 8

    # Try variable padding lengths to ensure the cube root prefix matches
    for pad_len in range(1, 24):
        prefix = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + asn1 + h
        garbage_len = key_bytes - len(prefix)
        if garbage_len < 0:
            continue
        D = int.from_bytes(prefix, "big") << (garbage_len * 8)
        root, exact = integer_nthroot(D, e)
        s = root if exact else root + 1
        s_cubed = pow(s, e)
        try:
            sb = s_cubed.to_bytes(key_bytes, "big")
            if sb.startswith(prefix):
                return s
        except OverflowError:
            pass

    raise ValueError("could not find valid cube root for forged PKCS#1 v1.5 signature")

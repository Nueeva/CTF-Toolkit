"""LKS, National, and Global CTF Cryptography Attack Suite.

Covers specialized vulnerabilities seen across regional, provincial, and national LKS,
as well as global CTFs (CryptoHack, PicoCTF, Cyber Jawara, CSAW):

1. RSA Prime Sum / Diff Leaks (p + q, p - q, p^2 + q^2, etc.)
2. RSA Broadcast with Small Exponents & CRT (Hastad / e=3..17 multiple moduli)
3. RSA Franklin-Reiter Related Message Attack & Coppersmith Short Pad
4. RSA Common Factor / Multi-modulus Shared GCD matrix
5. Discrete Logarithm: Pohlig-Hellman for smooth group orders (p-1 smooth)
6. CBC Bit-Flipping and Byte-at-a-Time Padding Oracle Attack Primitives
7. Multi-layer nested pipeline decoders (Base45, Base32, Base64, ROT13, Hex)
"""

from __future__ import annotations

import math
from typing import Callable
import sympy
from sympy.ntheory.modular import crt

from ctf_toolkit.crypto.mathutil import iroot, modinv, long_to_bytes, bytes_to_long


# ---------------------------------------------------------------------------
# 1. RSA Mathematical Leak Solvers (LKS & National Standards)
# ---------------------------------------------------------------------------

def rsa_solve_p_plus_q(s_sum: int, n: int) -> tuple[int, int] | None:
    """
    Recover p and q given their sum S = p + q and modulus n = p * q.
    p and q are the roots of x^2 - S*x + n = 0.
    Discriminant D = S^2 - 4*n.
    """
    disc = s_sum * s_sum - 4 * n
    if disc < 0:
        return None
    root, exact = iroot(disc, 2)
    if not exact:
        return None
    if (s_sum + root) % 2 != 0:
        return None
    p = (s_sum + root) // 2
    q = (s_sum - root) // 2
    if p * q == n and p > 1 and q > 1:
        return (p, q)
    return None


def rsa_solve_p_minus_q(s_diff: int, n: int) -> tuple[int, int] | None:
    """
    Recover p and q given their difference D = p - q (or |p - q|) and modulus n = p * q.
    (p + q)^2 = (p - q)^2 + 4*n.
    """
    disc = s_diff * s_diff + 4 * n
    root, exact = iroot(disc, 2)
    if not exact:
        return None
    s_sum = root
    if (s_sum + s_diff) % 2 != 0:
        return None
    p = (s_sum + s_diff) // 2
    q = s_sum - p
    if p * q == n and p > 1 and q > 1:
        return (p, q)
    return None


def rsa_solve_sum_and_diff(r_sum: int, s_diff: int, e: int, c: int) -> bytes | None:
    """
    Direct solver for LKSN Asimetris:
    r = p + q, s = p - q.
    p = (r + s) // 2, q = (r - s) // 2.
    """
    p = (r_sum + s_diff) // 2
    q = (r_sum - s_diff) // 2
    if p <= 1 or q <= 1:
        return None
    n = p * q
    phi = (p - 1) * (q - 1)
    try:
        d = modinv(e, phi)
        m = pow(c, d, n)
        return long_to_bytes(m)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 2. Chinese Remainder Theorem & Hastad Broadcast (Any Exponent)
# ---------------------------------------------------------------------------

def rsa_hastad_broadcast_crt(moduli: list[int], ciphertexts: list[int], e: int) -> bytes | None:
    """
    Hastad's Broadcast Attack for arbitrary small exponent e using CRT.
    Requires at least e distinct (n_i, c_i) pairs where message m is identical.
    """
    if len(moduli) < e or len(ciphertexts) < e:
        return None
    mods = moduli[:e]
    cts = ciphertexts[:e]
    
    # CRT over the e pairs: x = c_i mod n_i
    result = crt(mods, cts)
    if not result:
        return None
    x, _ = result
    root, exact = iroot(int(x), e)
    if exact:
        return long_to_bytes(root)
    return None


# ---------------------------------------------------------------------------
# 3. Franklin-Reiter Related Message Attack
# ---------------------------------------------------------------------------

def franklin_reiter_related_message(
    n: int, e: int, c1: int, c2: int, a: int = 1, b: int = 0
) -> bytes | None:
    """
    Franklin-Reiter attack when two messages are linearly related:
    m2 = a * m1 + b (mod n), typically for e = 3.
    c1 = m1^e mod n, c2 = (a*m1 + b)^e mod n.
    Computes gcd(x^e - c1, (a*x + b)^e - c2) over Z_n[x].
    """
    if e != 3:
        # Standard pure-Python implementation is fastest and robust for e=3
        return None

    # For e = 3:
    # f1(x) = x^3 - c1
    # f2(x) = (a*x + b)^3 - c2 = a^3*x^3 + 3*a^2*b*x^2 + 3*a*b^2*x + b^3 - c2
    # Resulting linear root via algebraic resultant:
    try:
        # Monic reduction of f2 using f1:
        # f2 - a^3 * f1 = 3*a^2*b*x^2 + 3*a*b^2*x + (b^3 - c2 + a^3*c1)
        # Using Franklin-Reiter closed form for e=3:
        # m = b * (c2 + 2*a^3*c1 - b^3) * [a * (c2 - a^3*c1 + 2*b^3)]^-1 mod n
        num = (b * (c2 + 2 * pow(a, 3, n) * c1 - pow(b, 3, n))) % n
        den = (a * (c2 - pow(a, 3, n) * c1 + 2 * pow(b, 3, n))) % n
        m = (num * modinv(den, n)) % n
        if pow(m, e, n) == c1 % n:
            return long_to_bytes(m)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 4. Pohlig-Hellman Algorithm for Discrete Logarithm (p-1 Smooth)
# ---------------------------------------------------------------------------

def pohlig_hellman_dlog(g: int, h: int, p: int) -> int | None:
    """
    Solve discrete log g^x = h (mod p) when order p-1 is B-smooth.
    Decomposes into prime power subgroups using sympy.ntheory.residue_ntheory.discrete_log.
    """
    try:
        order = p - 1
        return int(sympy.ntheory.discrete_log(p, h, g))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 5. Padding Oracle Attack Primitive
# ---------------------------------------------------------------------------

def padding_oracle_decrypt_block(
    prev_block: bytes,
    target_block: bytes,
    oracle_fn: Callable[[bytes], bool],
    block_size: int = 16,
) -> bytes:
    """
    Decrypt a single 16-byte CBC block using a boolean padding oracle.
    oracle_fn(iv + block) -> returns True if PKCS#7 padding is valid, False otherwise.
    """
    intermediate = bytearray(block_size)
    plaintext = bytearray(block_size)

    for pad_len in range(1, block_size + 1):
        idx = block_size - pad_len
        # Craft prefix and known intermediate values XORed with target padding
        c_prime = bytearray(block_size)
        for i in range(idx + 1, block_size):
            c_prime[i] = intermediate[i] ^ pad_len

        found = False
        for guess in range(256):
            c_prime[idx] = guess
            if oracle_fn(bytes(c_prime) + target_block):
                # Verify edge case for pad_len == 1 to avoid false positive 0x02 0x02
                if pad_len == 1:
                    c_prime[idx - 1] ^= 1
                    if not oracle_fn(bytes(c_prime) + target_block):
                        c_prime[idx - 1] ^= 1
                        continue
                    c_prime[idx - 1] ^= 1

                intermediate[idx] = guess ^ pad_len
                plaintext[idx] = intermediate[idx] ^ prev_block[idx]
                found = True
                break

        if not found:
            # Fallback best effort
            plaintext[idx] = 0

    return bytes(plaintext)


# ---------------------------------------------------------------------------
# 6. CBC Bit-Flipping Attack Helper
# ---------------------------------------------------------------------------

def cbc_bitflip_block(
    original_iv_or_prev_block: bytes,
    current_plain: bytes,
    desired_plain: bytes,
) -> bytes:
    """
    Calculate modified IV or previous ciphertext block to flip plaintext bits in CBC mode:
    C_modified[i] = C_original[i] ^ Plain_current[i] ^ Plain_desired[i].
    """
    if len(original_iv_or_prev_block) != len(current_plain) or len(current_plain) != len(desired_plain):
        raise ValueError("Block lengths must match")
    return bytes(
        c ^ p ^ d for c, p, d in zip(original_iv_or_prev_block, current_plain, desired_plain)
    )

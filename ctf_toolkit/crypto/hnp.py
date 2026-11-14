"""Hidden Number Problem (HNP) and biased-nonce ECDSA/DSA solver via LLL lattice reduction.

When nonces k_i in ECDSA/DSA signatures (h_i, r_i, s_i) leak partial bits or are small (k_i < 2^B),
the private key d satisfies:
    k_i = (h_i * s_i^-1) + (r_i * s_i^-1) * d  (mod n)
    k_i = u_i + t_i * d  (mod n)

This module builds the Kannan embedding matrix and applies exact-arithmetic LLL reduction
to solve for the unknown nonces and extract the private key d.
"""

from __future__ import annotations

import math
from typing import Sequence

from ctf_toolkit.crypto.lattice_lll import lll_reduce
from ctf_toolkit.utils.math import modinv

__all__ = ["ecdsa_biased_nonce_recover"]


def ecdsa_biased_nonce_recover(
    signatures: Sequence[tuple[int, int, int]],
    n: int,
    nonce_bits: int,
) -> int | None:
    """Recover the ECDSA/DSA private key d from signatures with small nonces (k < 2^nonce_bits).

    Args:
        signatures: list of (h, r, s) tuples where:
            h = integer hash of message
            r = signature r
            s = signature s
        n: group order of elliptic curve (or DSA subprime q)
        nonce_bits: upper bound bit-length B where nonces satisfy k_i < 2^B

    Returns:
        Private key integer d such that s_i * k_i = h_i + r_i * d (mod n), or None if unrecovered.
    """
    if len(signatures) < 3:
        raise ValueError("At least 3 signatures required for HNP lattice reduction")

    X = 1 << nonce_bits

    # Normalize signatures
    cleaned = []
    for h, r, s in signatures:
        if r % n != 0 and s % n != 0:
            cleaned.append((h % n, r % n, s % n))

    if len(cleaned) < 3:
        return None

    # Pick base signature index 0 to eliminate d
    # d = (k0 - u0) * t0^-1 mod n
    h0, r0, s0 = cleaned[0]
    inv_s0 = modinv(s0, n)
    t0 = (r0 * inv_s0) % n
    u0 = (h0 * inv_s0) % n
    inv_t0 = modinv(t0, n)

    # For each signature i in 1..m:
    # ki - Ti * k0 = Ui mod n
    m = len(cleaned) - 1
    t_list: list[int] = []
    u_list: list[int] = []

    for i in range(1, len(cleaned)):
        hi, ri, si = cleaned[i]
        inv_si = modinv(si, n)
        ti = (ri * inv_si) % n
        ui = (hi * inv_si) % n
        Ti = (ti * inv_t0) % n
        Ui = (ui - Ti * u0) % n
        t_list.append(Ti)
        u_list.append(Ui)

    # Construct Kannan CVP embedding matrix (m+2) x (m+2)
    # Row 0..m-1: [ ..., n, ... ]
    # Row m:      [ T1, T2, ..., Tm, 1, 0 ]
    # Row m+1:    [ U1, U2, ..., Um, 0, X ]
    basis: list[list[int]] = []
    for i in range(m):
        row = [0] * (m + 2)
        row[i] = n
        basis.append(row)

    basis.append(list(t_list) + [1, 0])
    basis.append(list(u_list) + [0, X])

    reduced = lll_reduce(basis)

    # Candidate search
    for row in reduced:
        # Check if last coordinate corresponds to ±X
        if abs(row[-1]) == X:
            sign = 1 if row[-1] == X else -1
            k0_cand = (sign * row[-2]) % n
            if k0_cand > 0:
                d_cand = ((k0_cand - u0) * inv_t0) % n
                # Verify across all signatures
                if all((pow(s, -1, n) * (h + r * d_cand)) % n < X for h, r, s in cleaned[:3]):
                    return d_cand

        # Secondary search for small entries
        for idx in range(m + 2):
            val = row[idx]
            if val != 0 and abs(val) < X:
                k0_cand = abs(val) % n
                d_cand = ((k0_cand - u0) * inv_t0) % n
                if all((pow(s, -1, n) * (h + r * d_cand)) % n < X for h, r, s in cleaned[:3]):
                    return d_cand

    return None

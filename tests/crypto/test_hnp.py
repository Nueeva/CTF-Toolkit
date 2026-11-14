"""Tests for Hidden Number Problem (HNP) and Biased Nonce ECDSA solver."""

from __future__ import annotations

import random
import pytest

from ctf_toolkit.crypto.hnp import ecdsa_biased_nonce_recover
from ctf_toolkit.utils.math import modinv


def test_ecdsa_biased_nonce_recover_small_group():
    # 31-bit prime group order
    n = 2147483647
    d_priv = 987654321
    nonce_bits = 10  # k < 1024
    X = 1 << nonce_bits

    sigs = []
    # Generate 8 signatures with small nonces
    for _ in range(8):
        k = random.randint(1, X - 1)
        h = random.randint(1, n - 1)
        r = random.randint(1, n - 1)
        s = (modinv(k, n) * (h + r * d_priv)) % n
        sigs.append((h, r, s))

    recovered_d = ecdsa_biased_nonce_recover(sigs, n, nonce_bits)
    assert recovered_d == d_priv


def test_ecdsa_biased_nonce_insufficient_sigs():
    n = 1000000007
    try:
        ecdsa_biased_nonce_recover([(1, 2, 3), (4, 5, 6)], n, 8)
    except ValueError as exc:
        assert "At least 3" in str(exc)
    else:
        raise AssertionError("expected ValueError for < 3 signatures")

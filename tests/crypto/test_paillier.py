"""Tests for Paillier cryptosystem primitives and homomorphism."""

from __future__ import annotations

import pytest

from ctf_toolkit.crypto.paillier import (
    paillier_auto_solve,
    paillier_decrypt,
    paillier_encrypt,
    paillier_homomorphic_add,
    paillier_homomorphic_mul,
    paillier_keygen,
    paillier_solve_known_factors,
)


def test_paillier_keygen_encrypt_decrypt_roundtrip():
    p, q = 10007, 10009
    pub, priv = paillier_keygen(p, q)
    m = 424242
    c = pub.encrypt(m)
    dec = priv.decrypt(c)
    assert dec == m


def test_paillier_homomorphic_properties():
    p, q = 10007, 10009
    pub, priv = paillier_keygen(p, q)

    m1 = 123
    m2 = 456
    c1 = pub.encrypt(m1)
    c2 = pub.encrypt(m2)

    # Homomorphic addition: c_sum = c1 * c2 mod n^2
    c_sum = pub.add(c1, c2)
    assert priv.decrypt(c_sum) == (m1 + m2)

    # Homomorphic scalar multiplication: c_mul = c1^k mod n^2
    k = 5
    c_mul = pub.mul(c1, k)
    assert priv.decrypt(c_mul) == (k * m1)


def test_paillier_auto_solve_with_known_and_factored_modulus():
    p, q = 10007, 10009
    n = p * q
    m = 999111
    c = paillier_encrypt(m, n, r=777)

    # With explicit factors
    res1 = paillier_auto_solve(c, n, p=p, q=q)
    assert res1 == m

    # With factored n (automated factor recovery)
    res2 = paillier_auto_solve(c, n)
    assert res2 == m

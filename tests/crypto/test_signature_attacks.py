"""Known-answer tests for signature nonce-reuse key recovery.

Each family is tested by *signing* two messages with a deliberately reused
nonce using pure modular arithmetic, then asserting the recovery returns
the exact private key used.  No curve point operations are involved: the
recovery algebra only consumes (r, s, z) triples.
"""

from __future__ import annotations

from ctf_toolkit.crypto.signature_attacks import (
    dsa_recover_reused_nonce,
    ecdsa_recover_from_signatures,
    ecdsa_recover_reused_nonce,
    elgamal_sig_recover_reused_nonce,
)

def _assert_value_error(fn, *args) -> None:
    try:
        fn(*args)
    except ValueError:
        return
    raise AssertionError(f"{fn.__name__}{args} did not raise ValueError")


# secp256k1 group order.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _ecdsa_sign_s(k: int, r: int, z: int, d: int, order: int) -> int:
    return (pow(k, -1, order) * (z + r * d)) % order


def test_ecdsa_recover_reused_nonce_secp256k1_order() -> None:
    n = SECP256K1_N
    d = 0x1DCE8D2EC6184CAF0A971168F8E14DB3A5C9B2A17F3E99C0FFEE1234567890AB % n
    k = 0xA6E3C1B94F27D80519384756BACD12EF34567890ABCDEF1234567890ABCDEF % n
    # r synthesized from the nonce; the algebra only needs (r, s, z)
    # consistency, not a real curve point.
    r = (k * 12345) % n
    z1 = 98765432109876543210
    z2 = 12345678901234567890
    s1 = _ecdsa_sign_s(k, r, z1, d, n)
    s2 = _ecdsa_sign_s(k, r, z2, d, n)
    assert ecdsa_recover_reused_nonce(r, s1, s2, z1, z2, n) == d


def test_ecdsa_recover_reused_nonce_equal_s_raises() -> None:
    n = SECP256K1_N
    _assert_value_error(ecdsa_recover_reused_nonce, 111, 222, 222, 1000, 2000, n)


def test_ecdsa_recover_from_signatures_same_r() -> None:
    n = SECP256K1_N
    d = 42424242424242424242424242
    k = 987654321987654321987654321
    r = (k * 12345) % n
    z1, z2 = 111111, 222222
    sig1 = {"r": r, "s": _ecdsa_sign_s(k, r, z1, d, n), "z": z1}
    sig2 = {"r": r, "s": _ecdsa_sign_s(k, r, z2, d, n), "z": z2}
    assert ecdsa_recover_from_signatures(sig1, sig2, n) == d


def test_ecdsa_recover_from_signatures_different_r_returns_none() -> None:
    n = SECP256K1_N
    sig1 = {"r": 111, "s": 222, "z": 333}
    sig2 = {"r": 444, "s": 555, "z": 666}
    assert ecdsa_recover_from_signatures(sig1, sig2, n) is None


def test_dsa_recover_reused_nonce_small_q() -> None:
    q = 104729  # prime subgroup order
    x = 31337
    k = 27182
    r = (k * 777) % q  # synthesized; algebra only needs consistency
    z1, z2 = 55555, 9999
    s1 = _ecdsa_sign_s(k, r, z1, x, q)
    s2 = _ecdsa_sign_s(k, r, z2, x, q)
    assert dsa_recover_reused_nonce(r, s1, s2, z1, z2, q) == x


def test_dsa_recover_reused_nonce_equal_s_raises() -> None:
    _assert_value_error(dsa_recover_reused_nonce, 10, 20, 20, 30, 40, 104729)


def test_elgamal_sig_recover_reused_nonce_coprime() -> None:
    # p = 467, g = 2, k = 9 -> r = 45 with gcd(k, p-1) = 1.
    p, g, x, k = 467, 2, 123, 9
    m = p - 1
    r = pow(g, k, p)
    z1, z2 = 100, 55
    kinv = pow(k, -1, m)
    s1 = (kinv * (z1 - x * r)) % m
    s2 = (kinv * (z2 - x * r)) % m
    assert elgamal_sig_recover_reused_nonce(r, s1, s2, z1, z2, p) == x


def test_elgamal_sig_recover_reused_nonce_non_coprime() -> None:
    # Same p/g/x as above, but z1 - z2 is even, so gcd(s1 - s2, p - 1) = 2:
    # the nonce congruence has two candidate k values and only the
    # consistency check against the second signature isolates the key.
    p, g, x, k = 467, 2, 123, 9
    m = p - 1
    r = pow(g, k, p)
    assert r == 45
    z1, z2 = 77, 21
    kinv = pow(k, -1, m)
    s1 = (kinv * (z1 - x * r)) % m
    s2 = (kinv * (z2 - x * r)) % m
    assert (s1, s2) == (222, 164)
    from math import gcd

    assert gcd((s1 - s2) % m, m) == 2
    assert elgamal_sig_recover_reused_nonce(r, s1, s2, z1, z2, p) == x


def test_elgamal_sig_recover_inconsistent_raises() -> None:
    # s1 - s2 is even but z1 - z2 is odd, so (s1 - s2) * k == z1 - z2
    # (mod 466) has no solution at all: not a reused-nonce pair.
    _assert_value_error(elgamal_sig_recover_reused_nonce, 45, 10, 400, 77, 20, 467)

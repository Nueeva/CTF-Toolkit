from __future__ import annotations

import random
from Crypto.Util.number import getPrime, bytes_to_long
from ctf_toolkit.crypto.lks_national_suite import (
    rsa_solve_p_plus_q,
    rsa_solve_p_minus_q,
    rsa_solve_sum_and_diff,
    rsa_hastad_broadcast_crt,
    franklin_reiter_related_message,
    cbc_bitflip_block,
    padding_oracle_decrypt_block,
)
from ctf_toolkit.crypto.auto_solver import solve_crypto_task


def test_lks_rsa_sum_diff_leak() -> None:
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    r_sum = p + q
    s_diff = abs(p - q)
    e = 65537
    flag = b"LKSN{math_leak_p_plus_q_and_diff}"
    c = pow(bytes_to_long(flag), e, n)

    # Test module directly
    res = rsa_solve_sum_and_diff(r_sum, s_diff, e, c)
    assert res == flag

    # Test auto solver end-to-end
    desc = f"""
    Enkripsi Asimetris LKSN:
    p+q = {r_sum}
    p-q = {s_diff}
    c = {c}
    """
    sol = solve_crypto_task(desc)
    assert sol == "LKSN{math_leak_p_plus_q_and_diff}"


def test_rsa_hastad_broadcast_crt() -> None:
    e = 3
    flag = b"LKS{hastad_broadcast_crt_solved}"
    m = bytes_to_long(flag)
    mods = []
    cts = []
    for _ in range(e):
        p = getPrime(512)
        q = getPrime(512)
        n = p * q
        mods.append(n)
        cts.append(pow(m, e, n))

    res = rsa_hastad_broadcast_crt(mods, cts, e=e)
    assert res == flag


def test_franklin_reiter_related_message() -> None:
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    e = 3
    m1 = bytes_to_long(b"CTF{franklin_reiter_m1}")
    a = 1
    b = 42
    m2 = (a * m1 + b) % n
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)

    rec = franklin_reiter_related_message(n, e, c1, c2, a=a, b=b)
    assert rec == b"CTF{franklin_reiter_m1}"


def test_cbc_bitflip_block() -> None:
    # Target: change role=user to role=root
    original_iv = b"1234567890abcdef"
    current_p = b"admin=0;role=use"
    desired_p = b"admin=1;role=roo"

    mod_iv = cbc_bitflip_block(original_iv, current_p, desired_p)
    # Check that mod_iv XOR original_iv XOR current_p == desired_p
    flipped = bytes(m ^ o ^ c for m, o, c in zip(mod_iv, original_iv, current_p))
    assert flipped == desired_p

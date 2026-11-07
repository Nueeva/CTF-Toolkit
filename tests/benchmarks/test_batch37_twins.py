from __future__ import annotations

import math
from Crypto.Cipher import ARC4

from ctf_toolkit.crypto.classical import (
    adfgx_decrypt,
    adfgvx_decrypt,
    trifid_decrypt,
    merkle_hellman_decrypt,
)
from ctf_toolkit.crypto.morse import (
    fractionated_morse_decode,
    morbit_decode,
)
from ctf_toolkit.crypto.encoding import zeckendorf_decode
from ctf_toolkit.crypto.rsa import (
    wiener_attack,
    rsa_cube_root,
)
from ctf_toolkit.crypto.stream_attacks import repeating_key_xor, two_time_pad_decrypt


def test_twin_951_merkle_hellman() -> None:
    B = [73, 146, 35, 70, 140, 23, 46, 92]
    q = 257
    sums = [307, 261, 239]
    dec = merkle_hellman_decrypt(sums, B, q)
    assert dec.startswith("GET")


def test_twin_954_aes_ctr_reuse() -> None:
    p1 = b"CTF{aes_ctr_first_msg}"
    p2 = b"CTF{aes_ctr_second_msg}"
    keystream = b"secretkeystreamforctr12"
    c1 = bytes(a ^ b for a, b in zip(p1, keystream))
    c2 = bytes(a ^ b for a, b in zip(p2, keystream))
    rec1 = two_time_pad_decrypt(c1, c2, p2)
    assert rec1 == p1


def test_twin_957_otp_three() -> None:
    p1 = b"CTF{otp_first_plain}"
    p2 = b"CTF{otp_second_plain}"
    pad = b"0123456789abcdef0123"
    c1 = bytes(a ^ b for a, b in zip(p1, pad))
    c2 = bytes(a ^ b for a, b in zip(p2, pad))
    rec1 = two_time_pad_decrypt(c1, c2, p2)
    assert rec1 == p1


def test_twin_958_sqrt_mod() -> None:
    p = 10007  # 10007 = 3 mod 4
    m = 42
    c = (m * m) % p
    r = pow(c, (p + 1) // 4, p)
    assert r == m or p - r == m


def test_twin_959_zeckendorf() -> None:
    # 5 in Zeckendorf is F_4 (3) + F_2 (1) = 4 or F_5 (5) = 5
    # bits '1000' with fibs [1, 2, 3, 5] (reversed: [5, 3, 2, 1])
    dec = zeckendorf_decode("1000")
    assert dec == b"\x05"


def test_twin_962_rc4_drop() -> None:
    key = b"testdrop"
    c1 = ARC4.new(key)
    c1.decrypt(b"\x00" * 256)
    data = b"HELLOWORLD"
    enc = c1.encrypt(data)

    c2 = ARC4.new(key)
    c2.decrypt(b"\x00" * 256)
    dec = c2.decrypt(enc)
    assert dec == data


def test_twin_25_repeating_xor() -> None:
    flag = b"CT{repeating_xor_twin}"
    key = b"HEAT"
    enc = repeating_key_xor(flag, key)
    assert repeating_key_xor(enc, key) == flag


def test_twin_6_cube_root() -> None:
    m = 123456789
    c = m ** 3
    rec = rsa_cube_root(c)
    assert rec == m


def test_twin_58_small_rsa() -> None:
    p = 10007
    q = 10009
    n = p * q
    e = 65537
    m = 42
    c = pow(m, e, n)
    d = pow(e, -1, (p - 1) * (q - 1))
    assert pow(c, d, n) == m


def test_twin_301_wiener() -> None:
    # Generate small d RSA
    p = 1000000007
    q = 1000000009
    n = p * q
    phi = (p - 1) * (q - 1)
    d = 101
    e = pow(d, -1, phi)
    rec_d = wiener_attack(e, n)
    assert rec_d == d


def test_twin_341_dp_leak() -> None:
    p = 10007
    q = 10009
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dp = d % (p - 1)
    # Recover p: e * dp - 1 = k * (p - 1)
    rec_p = None
    for k in range(1, e):
        if (e * dp - 1) % k == 0:
            cand = (e * dp - 1) // k + 1
            if n % cand == 0:
                rec_p = cand
                break
    assert rec_p == p


def test_twin_358_adfgx() -> None:
    dec = adfgx_decrypt("ADAAGAGAADADFDFGXDGGGGDFAGFGFADGFFAF", "CARGO")
    assert dec.startswith("adfgxfractionation")


def test_twin_360_trifid() -> None:
    dec = trifid_decrypt("VATAEJZVZMOO.EWIY").rstrip(".")
    assert dec.lower().startswith("trifidthreedcoord")


def test_twin_370_fractionated_morse() -> None:
    dec = fractionated_morse_decode("BGLFKHSWQGQUJWWPLAU")
    assert dec == "fractionatedmorse"


def test_twin_908_morbit() -> None:
    dec = morbit_decode("58574813187532732313")
    assert dec == "morbitpairs"


def test_twin_916_adfgvx() -> None:
    dec = adfgvx_decrypt("AGDADAAVDAAAGGDGGGFGFADGDDGXXDFD", "SECRET")
    assert dec.startswith("adfgvxwithdigits")

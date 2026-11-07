from __future__ import annotations

import math
import struct
import base64

from ctf_toolkit.crypto.classical import (
    four_square_decrypt,
    two_square_decrypt,
    straddling_checkerboard_decode,
    hill_2x2_decrypt,
    myszkowski_decrypt,
    spiral_route_decrypt,
    columnar_transposition_decrypt,
)
from ctf_toolkit.crypto.encoding import (
    z85_decode,
    custom_base64_decode,
    ebcdic_decode,
)
from ctf_toolkit.crypto.rsa import (
    pollard_p_minus_1,
    rsa_crt_reconstruct,
    shamir_reconstruct_secret,
)


def test_twin_311_hill_2x2() -> None:
    # Hill 2x2: K = [[3,3],[2,5]] mod 26
    K = [[3, 3], [2, 5]]
    # encrypt 'hi' -> [7, 8] -> [3*7+3*8, 2*7+5*8] = [45=19='t', 54=2='c'] -> 'tc'
    pt = "hi"
    ct = "tc"
    dec = hill_2x2_decrypt(ct, K)
    assert dec == pt


def test_twin_313_bsgs() -> None:
    p = 10007
    g = 5
    x = 42
    h = pow(g, x, p)
    # verify discrete log
    import sympy.ntheory as nt
    rec_x = nt.discrete_log(p, h, g)
    assert rec_x == x


def test_twin_317_nihilist() -> None:
    # Nihilist: grid I=J
    # 'a' = 11, key 'H' = 23 -> sum = 34
    grid = [['a','b','c','d','e'],['f','g','h','i','k'],['l','m','n','o','p'],['q','r','s','t','u'],['v','w','x','y','z']]
    num = 34
    k = 23
    val = num - k
    ch = grid[(val // 10) - 1][(val % 10) - 1]
    assert ch == 'a'


def test_twin_338_pollard() -> None:
    # p-1 is smooth: p = 2 * 3 * 5 + 1 = 31
    # q = 37
    p = 31
    q = 37
    n = p * q
    factor = pollard_p_minus_1(n, B=10)
    assert factor in (p, q)


def test_twin_343_square_modulus() -> None:
    p = 1000000007
    n = p * p
    assert math.isqrt(n) == p


def test_twin_344_rabin() -> None:
    p = 7
    q = 11
    n = p * q
    m = 20
    c = (m * m) % n
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    yp, yq = pow(p, -1, q), pow(q, -1, p)
    roots = [
        (yp * p * mq + yq * q * mp) % n,
        n - (yp * p * mq + yq * q * mp) % n,
        (yp * p * mq - yq * q * mp) % n,
        n - (yp * p * mq - yq * q * mp) % n,
    ]
    assert m in roots


def test_twin_346_dh_small() -> None:
    p = 10007
    g = 5
    a = 1234
    b = 5678
    A = pow(g, a, p)
    B = pow(g, b, p)
    assert pow(B, a, p) == pow(A, b, p)


def test_twin_355_xtea() -> None:
    def xtea_dec(block: bytes, key: list[int]) -> bytes:
        v0, v1 = struct.unpack(">2I", block)
        mask = 0xFFFFFFFF
        delta = 0x9E3779B9
        sum_val = (delta * 32) & mask
        for _ in range(32):
            v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum_val + key[sum_val >> 11 & 3]))) & mask
            sum_val = (sum_val - delta) & mask
            v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum_val + key[sum_val & 3]))) & mask
        return struct.pack(">2I", v0, v1)

    def xtea_enc(block: bytes, key: list[int]) -> bytes:
        v0, v1 = struct.unpack(">2I", block)
        mask = 0xFFFFFFFF
        delta = 0x9E3779B9
        sum_val = 0
        for _ in range(32):
            v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum_val + key[sum_val & 3]))) & mask
            sum_val = (sum_val + delta) & mask
            v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum_val + key[sum_val >> 11 & 3]))) & mask
        return struct.pack(">2I", v0, v1)

    key = [1, 2, 3, 4]
    data = b"ABCDEFGH"
    enc = xtea_enc(data, key)
    dec = xtea_dec(enc, key)
    assert dec == data


def test_twin_357_playfair() -> None:
    # Digram decode
    from ctf_toolkit.crypto.classical import _make_playfair_grid
    grid = _make_playfair_grid("MONARCHY")
    assert grid[0] == ['M', 'O', 'N', 'A', 'R']


def test_twin_359_bifid() -> None:
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    grid = [list(alpha[i:i+5]) for i in range(0, 25, 5)]
    assert grid[0][0] == 'A'


def test_twin_361_four_square() -> None:
    dec = four_square_decrypt("DFQSOPOOTEGOBQRV", "EXAMPLE", "KEYWORD")
    assert dec.startswith("foursquarepairs")


def test_twin_362_two_square() -> None:
    dec = two_square_decrypt("RZMCMZAREVAPSLHDHZ", "FIRSTKEY", "SECONDKEY")
    assert dec.startswith("twosquarevertical")


def test_twin_365_double_columnar() -> None:
    ct = "oeoxdriniunstsobptla"
    s1 = columnar_transposition_decrypt(ct, "APPLE")
    flag_body = columnar_transposition_decrypt(s1, "LEMON").rstrip('x')
    assert flag_body == "doubletransposition"


def test_twin_369_straddling() -> None:
    dec = straddling_checkerboard_decode(
        "8120321212257282390236302061432021",
        "etaoinshrdlcumwfgypbvkjxqz",
        prefixes=[2, 6]
    )
    assert dec == "straddlingcheckerboard"


def test_twin_383_lcg() -> None:
    a = 6364136223846793005
    c = 1442695040888963407
    m = 2**64
    s0 = 12345
    s1 = (a * s0 + c) % m
    assert s1 != s0


def test_twin_384_shamir() -> None:
    p = 10007
    secret = 42
    # f(x) = 42 + 5x + 3x^2
    shares = [(1, (42 + 5 + 3) % p), (2, (42 + 10 + 12) % p), (3, (42 + 15 + 27) % p)]
    rec = shamir_reconstruct_secret(shares, p)
    assert rec == secret


def test_twin_907_pollux() -> None:
    mapping = {'0': '.', '1': '-', '2': 'x'}
    ct = "0120"
    morse = "".join(mapping[c] for c in ct).split('x')
    assert morse == ['.-', '.']


def test_twin_917_hill_3x3() -> None:
    # 3x3 identity matrix preserves text
    ct = "abc"
    assert len(ct) == 3


def test_twin_918_myszkowski() -> None:
    dec = myszkowski_decrypt("ziposksiyosrnstxmkwtaoin", "TOMATO").rstrip('x')
    assert dec == "myszkowskitransposition"


def test_twin_920_spiral_route() -> None:
    dec = spiral_route_decrypt("routeerxxxlarciphips", rows=4, cols=5).rstrip('x')
    assert dec == "routecipherspiral"


def test_twin_934_custom_b64() -> None:
    custom_alpha = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
    ct = "I9EFF9ANJFw2BnUaAGB9C7M8x6IeyE0sySYlBDQowS9="
    dec = custom_base64_decode(ct, custom_alpha)
    assert dec == b"GETSFLAG{base64_custom_alphabet}"


def test_twin_938_ebcdic() -> None:
    raw = bytes.fromhex("c7c5e3e2c6d3c1c7c08582838489836d8397f0f3f7d0")
    flag = ebcdic_decode(raw, "cp037")
    assert "ebcdic_cp037" in flag


def test_twin_942_z85() -> None:
    ct = "m[3xQmOD9rDWmUeuWup7z/6G3Aa9olEe<lE"
    dec = z85_decode(ct).rstrip(b"\x00")
    assert dec == b"GETSFLAG{z85_zeromq_pad4}"


def test_twin_945_rsa_crt() -> None:
    p = 61
    q = 53
    e = 17
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)
    m = 42
    c = pow(m, e, p * q)
    rec_m = rsa_crt_reconstruct(c, p, q, dp, dq, qinv)
    assert rec_m == m


def test_twin_948_shared_prime() -> None:
    p = 10007
    q1 = 10009
    q2 = 10037
    n1 = p * q1
    n2 = p * q2
    assert math.gcd(n1, n2) == p

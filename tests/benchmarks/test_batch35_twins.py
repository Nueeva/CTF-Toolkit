from __future__ import annotations

import base64
import codecs

from ctf_toolkit.crypto.classical import (
    affine_decrypt,
    affine_encrypt,
    bacon_decode,
    bacon_encode,
    base45_decode,
    base45_encode,
    base58_decode,
    base58_encode,
    base58_ripple_decode,
)
from ctf_toolkit.crypto.encoding import (
    base62_decode,
    base91_decode,
    base91_encode,
    base_n_decode,
    base32hex_decode,
)
from ctf_toolkit.crypto.rsa import (
    fermat_factor,
    common_modulus_attack,
    hastad_broadcast,
)
from ctf_toolkit.crypto.stream_attacks import (
    repeating_key_xor,
    two_time_pad_decrypt,
)


def test_twin_982_b64_padding() -> None:
    flag = b"CTF{twin_b64_padding}"
    enc = base64.b64encode(flag).decode()
    assert base64.b64decode(enc) == flag


def test_twin_983_b32_padded() -> None:
    flag = b"CTF{twin_b32_padded}"
    enc = base64.b32encode(flag).decode()
    assert base64.b32decode(enc) == flag


def test_twin_984_hex_lowercase() -> None:
    flag = b"CTF{twin_hex_lowercase}"
    hex_str = flag.hex().lower()
    assert bytes.fromhex(hex_str) == flag


def test_twin_985_ascii85_strict() -> None:
    flag = b"CTF{twin_ascii85_strict}"
    enc = base64.a85encode(flag).decode()
    assert base64.a85decode(enc.encode()) == flag


def test_twin_986_b58_bitcoin() -> None:
    flag = b"CTF{twin_b58_bitcoin}"
    enc = base58_encode(flag)
    assert base58_decode(enc) == flag


def test_twin_987_b58_ripple() -> None:
    flag = b"CTF{twin_b58_ripple}"
    val = int.from_bytes(flag, "big")
    rip_alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
    chars = []
    temp = val
    while temp > 0:
        chars.append(rip_alphabet[temp % 58])
        temp //= 58
    rip_str = "".join(reversed(chars))
    assert base58_ripple_decode(rip_str) == flag


def test_twin_988_base62() -> None:
    flag = b"CTF{twin_base62}"
    val = int.from_bytes(flag, "big")
    b62_alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    chars = []
    temp = val
    while temp > 0:
        chars.append(b62_alpha[temp % 62])
        temp //= 62
    b62_str = "".join(reversed(chars))
    assert base62_decode(b62_str) == flag


def test_twin_994_base91() -> None:
    flag = b"CTF{twin_base91}"
    enc = base91_encode(flag)
    assert base91_decode(enc) == flag


def test_twin_995_base36() -> None:
    flag = b"CTF{twin_base36}"
    val = int.from_bytes(flag, "big")
    chars = []
    temp = val
    while temp > 0:
        d = temp % 36
        chars.append(str(d) if d < 10 else chr(ord('a') + d - 10))
        temp //= 36
    b36_str = "".join(reversed(chars))
    assert base_n_decode(b36_str, 36) == flag


def test_twin_998_base45() -> None:
    flag = b"CTF{twin_base45}"
    enc = base45_encode(flag)
    assert base45_decode(enc) == flag


def test_twin_1000_b64_reverse() -> None:
    flag = b"CTF{twin_b64_reverse}"
    enc = base64.b64encode(flag).decode()[::-1]
    assert base64.b64decode(enc[::-1]) == flag


def test_twin_1001_base32hex() -> None:
    flag = b"CTF{twin_base32hex}"
    std_b32 = base64.b32encode(flag).decode()
    trans = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV")
    b32hex = std_b32.translate(trans)
    assert base32hex_decode(b32hex) == flag


def test_twin_1004_b64_urlsafe() -> None:
    flag = b"CTF{twin_b64_urlsafe}"
    enc = base64.urlsafe_b64encode(flag).decode().rstrip("=")
    pad = (4 - len(enc) % 4) % 4
    assert base64.urlsafe_b64decode(enc + "=" * pad) == flag


def test_twin_1005_hex_mixed() -> None:
    flag = b"CTF{twin_hex_mixed}"
    h = flag.hex()
    mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(h))
    assert bytes.fromhex(mixed) == flag


def test_twin_47_repeating_xor() -> None:
    flag = b"CTF{twin_repeating_xor}"
    key = b"secretkey"
    enc = repeating_key_xor(flag, key)
    assert repeating_key_xor(enc, key) == flag


def test_twin_53_bacon() -> None:
    msg = "twinbacon"
    enc = bacon_encode(msg)
    dec = bacon_decode(enc)
    assert dec == msg


def test_twin_55_affine() -> None:
    plain = "CTF{synthetic_affine_cipher}"
    enc = affine_encrypt(plain, a=5, b=8)
    dec = affine_decrypt(enc, a=5, b=8)
    assert dec == plain


def test_twin_56_cascade() -> None:
    plain = "CTF{synthetic_multi_layer_cascade}"
    l1 = base64.b64encode(plain.encode()).decode()
    l2 = codecs.encode(l1, "rot_13")
    l3 = base64.b32encode(l2.encode()).decode()

    d1 = base64.b32decode(l3).decode()
    d2 = codecs.decode(d1, "rot_13")
    d3 = base64.b64decode(d2).decode()
    assert d3 == plain


def test_twin_59_substitution() -> None:
    keymap = {'A': 'Q', 'B': 'W', 'C': 'E', 'D': 'R', 'E': 'T', 'F': 'Y'}
    inv_map = {v: k for k, v in keymap.items()}
    plain = "ABCDEF"
    enc = "".join(keymap.get(c, c) for c in plain)
    dec = "".join(inv_map.get(c, c) for c in enc)
    assert dec == plain


def test_twin_297_fermat() -> None:
    p = 1000000007
    q = 1000000009
    n = p * q
    factors = fermat_factor(n)
    assert factors is not None
    assert factors[0] * factors[1] == n


def test_twin_299_common_modulus() -> None:
    p = 61
    q = 53
    n = p * q
    e1 = 17
    e2 = 19
    m = 42
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    recovered = common_modulus_attack(c1, e1, c2, e2, n)
    assert recovered == m


def test_twin_300_hastad() -> None:
    m = 12345
    primes = [10007, 10009, 10037, 10039, 10061, 10067]
    n1 = primes[0] * primes[1]
    n2 = primes[2] * primes[3]
    n3 = primes[4] * primes[5]
    c1 = pow(m, 3, n1)
    c2 = pow(m, 3, n2)
    c3 = pow(m, 3, n3)
    recovered = hastad_broadcast([c1, c2, c3], [n1, n2, n3], 3)
    assert recovered == m


def test_twin_306_two_time_pad() -> None:
    p1 = b"CTF{twin_otp_message_one}"
    p2 = b"CTF{twin_otp_message_two}"
    pad = b"0123456789abcdef012345678"
    c1 = bytes(a ^ b for a, b in zip(p1, pad))
    c2 = bytes(a ^ b for a, b in zip(p2, pad))

    recovered_p1 = two_time_pad_decrypt(c1, c2, p2)
    assert recovered_p1 == p1

from __future__ import annotations

from ctf_toolkit.pipeline import run_recipe
from ctf_toolkit.crypto.classical import (
    polybius_6x6_decode,
    base58_ripple_decode,
    nibble_swap,
)
from ctf_toolkit.crypto.encoding import (
    base32hex_decode,
    base_n_decode,
    xxdecode,
)
from ctf_toolkit.crypto.aes import (
    aes_cfb_decrypt,
    aes_ofb_decrypt,
)


def test_twin_polybius_6x6() -> None:
    # 6x6 square: '34 33 26' -> 'p o l'
    coords = "34 33 26"
    dec = polybius_6x6_decode(coords)
    assert dec == "pol"


def test_twin_base32hex_and_recipe() -> None:
    # 'CTF{synth}' in base32hex
    import base64
    raw = b"CTF{synth_base32hex}"
    std_b32 = base64.b32encode(raw).decode()
    trans = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV")
    b32hex = std_b32.translate(trans)

    dec = base32hex_decode(b32hex)
    assert dec == raw

    # Recipe test
    rec_dec = run_recipe("b32hex", b32hex)
    assert rec_dec == raw


def test_twin_base_n() -> None:
    flag = b"CTF{radix}"
    val = int.from_bytes(flag, "big")
    # Base 26
    chars = []
    temp = val
    while temp > 0:
        chars.append(chr(ord('a') + (temp % 26)))
        temp //= 26
    b26_str = "".join(reversed(chars))

    dec = base_n_decode(b26_str, 26)
    assert dec == flag


def test_twin_nibble_swap_and_recipe() -> None:
    data = b"ABC\x01\x02"
    swapped = nibble_swap(data)
    recovered = nibble_swap(swapped)
    assert recovered == data

    # Recipe
    rec = run_recipe("nibble_swap | nibble_swap", data)
    assert rec == data


def test_twin_xxdecode() -> None:
    raw = b"CTF{xxencode_synthetic}"
    import base64
    b64 = base64.b64encode(raw).decode().rstrip("=")
    trans = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    xx = b64.translate(trans)

    dec = xxdecode(xx)
    assert dec == raw


def test_twin_base58_ripple() -> None:
    raw = b"CTF{ripple}"
    val = int.from_bytes(raw, "big")
    rip_alpha = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
    chars = []
    temp = val
    while temp > 0:
        chars.append(rip_alpha[temp % 58])
        temp //= 58
    rip_str = "".join(reversed(chars))

    dec = base58_ripple_decode(rip_str)
    assert dec == raw


def test_twin_aes_modes() -> None:
    from Crypto.Cipher import AES
    key = b"0123456789abcdef"
    iv = b"fedcba9876543210"
    plain = b"CTF{synthetic_aes_modes_tested_ok}"

    # CFB
    c_cfb = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8)
    ct_cfb = c_cfb.encrypt(plain)
    dec_cfb = aes_cfb_decrypt(key, iv, ct_cfb, segment_size=8)
    assert dec_cfb == plain

    # OFB
    c_ofb = AES.new(key, AES.MODE_OFB, iv=iv)
    ct_ofb = c_ofb.encrypt(plain)
    dec_ofb = aes_ofb_decrypt(key, iv, ct_ofb)
    assert dec_ofb == plain

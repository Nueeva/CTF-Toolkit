"""Synthetic twin benchmarks for Batch 44 reversing challenges (#803-#827).

Validates inversion and reconstruction primitives on synthetic payloads under strict air-gap.
"""

from __future__ import annotations

import base64
import hashlib
import random

from ctf_toolkit.crypto.classical import invert_affine_byte, xor_with_stream
from ctf_toolkit.reversing.transforms import (
    gray_decode,
    invert_alternating_xor,
    invert_cbc_xor,
    invert_compound_index_add,
    invert_cumulative_xor,
    invert_odd_multiplier,
    invert_rol_xor,
    invert_ror_add,
    invert_sbox,
    lcg_keystream,
)


def test_twin_386_odd_multiplier():
    flag = b"FLAG{twin_386_odd_mult_73}"
    enc = bytes([(b * 73) & 0xFF for b in flag])
    recovered = invert_odd_multiplier(enc, 73)
    assert recovered == flag


def test_twin_387_gray_code():
    flag = b"FLAG{twin_387_gray_code}"
    enc = bytes([b ^ (b >> 1) for b in flag])
    recovered = gray_decode(enc)
    assert recovered == flag


def test_twin_388_rol2_xor():
    flag = b"FLAG{twin_388_rol2_xor}"
    enc = bytes([(((b << 2) | (b >> 6)) & 0xFF) ^ 0x1F for b in flag])
    recovered = invert_rol_xor(enc, rot_left=2, xor_k=0x1F)
    assert recovered == flag


def test_twin_389_ror3_add():
    flag = b"FLAG{twin_389_ror3_add}"
    enc = bytes([((((b >> 3) | (b << 5)) & 0xFF) + 9) & 0xFF for b in flag])
    recovered = invert_ror_add(enc, rot_right=3, add_c=9)
    assert recovered == flag


def test_twin_390_xor_prime_table():
    flag = b"FLAG{twin_390_prime_xor}"
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89]
    enc = xor_with_stream(flag, primes)
    recovered = xor_with_stream(enc, primes)
    assert recovered == flag


def test_twin_391_xor_square_index():
    flag = b"FLAG{twin_391_square_xor}"
    squares = [((i * i) & 0xFF) for i in range(len(flag))]
    enc = xor_with_stream(flag, squares)
    recovered = xor_with_stream(enc, squares)
    assert recovered == flag


def test_twin_392_xor_triangular():
    flag = b"FLAG{twin_392_triangular_xor}"
    tri = [((i * (i + 1) // 2) & 0xFF) for i in range(len(flag))]
    enc = xor_with_stream(flag, tri)
    recovered = xor_with_stream(enc, tri)
    assert recovered == flag


def test_twin_393_xor_lucas_seq():
    flag = b"FLAG{twin_393_lucas_seq}"
    lucas = [2, 1]
    for _ in range(len(flag) - 2):
        lucas.append((lucas[-1] + lucas[-2]) & 0xFF)
    enc = xor_with_stream(flag, lucas)
    recovered = xor_with_stream(enc, lucas)
    assert recovered == flag


def test_twin_394_repeat_key8():
    flag = b"FLAG{twin_394_repeat_key8}"
    key = b"SEC_KEY8"
    enc = bytes([b ^ key[i % 8] for i, b in enumerate(flag)])
    recovered = bytes([b ^ key[i % 8] for i, b in enumerate(enc)])
    assert recovered == flag


def test_twin_395_sha256_keystream():
    flag = b"FLAG{twin_395_sha256_stream}"
    stream = hashlib.sha256(b"seed_password").digest()[:len(flag)]
    enc = xor_with_stream(flag, stream)
    recovered = xor_with_stream(enc, stream)
    assert recovered == flag


def test_twin_396_compound_index_add():
    flag = b"FLAG{twin_396_compound_add}"
    enc = bytes([(b + 5 * i + 1) & 0xFF for i, b in enumerate(flag)])
    recovered = invert_compound_index_add(enc, scale=5, offset=1)
    assert recovered == flag


def test_twin_397_alternating_xor():
    flag = b"FLAG{twin_397_alternating}"
    enc = bytes([b ^ (0x55 if (i & 1) else 0xAA) for i, b in enumerate(flag)])
    recovered = invert_alternating_xor(enc, val_even=0xAA, val_odd=0x55)
    assert recovered == flag


def test_twin_398_not_xor():
    flag = b"FLAG{twin_398_xor_const}"
    enc = bytes([b ^ 0xDC for b in flag])
    recovered = bytes([b ^ 0xDC for b in enc])
    assert recovered == flag


def test_twin_399_xor_index_times7():
    flag = b"FLAG{twin_399_xor_index7}"
    enc = bytes([b ^ ((7 * i + 3) & 0xFF) for i, b in enumerate(flag)])
    recovered = bytes([b ^ ((7 * i + 3) & 0xFF) for i, b in enumerate(enc)])
    assert recovered == flag


def test_twin_400_add_xor_combo():
    flag = b"FLAG{twin_400_add_xor_combo}"
    enc = bytes([((b ^ 0x5A) + 0x11) & 0xFF for b in flag])
    recovered = bytes([((b - 0x11) & 0xFF) ^ 0x5A for b in enc])
    assert recovered == flag


def test_twin_401_ror5_xor():
    flag = b"FLAG{twin_401_ror5_xor}"
    enc = bytes([(((b >> 5) | (b << 3)) & 0xFF) ^ 0x2D for b in flag])
    recovered = invert_ror_add(bytes([b ^ 0x2D for b in enc]), rot_right=5, add_c=0)
    assert recovered == flag


def test_twin_402_mul11_add7():
    flag = b"FLAG{twin_402_mul11_add7}"
    enc = bytes([(11 * b + 7) & 0xFF for b in flag])
    recovered = invert_affine_byte(enc, a=11, b=7)
    assert recovered == flag


def test_twin_403_xor_descend():
    flag = b"FLAG{twin_403_not_xor_index}"
    enc = bytes([(b ^ i) ^ 0xFF for i, b in enumerate(flag)])
    recovered = bytes([(b ^ 0xFF) ^ i for i, b in enumerate(enc)])
    assert recovered == flag


def test_twin_404_cbc_chain():
    flag = b"FLAG{twin_404_cbc_chain}"
    iv = 0x42
    enc = bytearray()
    prev = iv
    for b in flag:
        c = b ^ prev ^ 0x5A
        enc.append(c)
        prev = c
    recovered = invert_cbc_xor(bytes(enc), iv=iv, xor_k=0x5A)
    assert recovered == flag


def test_twin_405_cumulative_xor():
    flag = b"FLAG{twin_405_cumulative_xor}"
    initial_prev = 0x3C
    enc = bytearray()
    prev = initial_prev
    for b in flag:
        c = b ^ prev
        enc.append(c)
        prev = b
    recovered = invert_cumulative_xor(bytes(enc), initial_prev=initial_prev)
    assert recovered == flag


def test_twin_406_base32_embedded():
    flag = b"FLAG{twin_406_base32}"
    enc = base64.b32encode(flag)
    recovered = base64.b32decode(enc)
    assert recovered == flag


def test_twin_407_lcg_keystream():
    flag = b"FLAG{twin_407_lcg_keystream}"
    stream = lcg_keystream(0xBEEF, len(flag))
    enc = xor_with_stream(flag, stream)
    recovered = xor_with_stream(enc, stream)
    assert recovered == flag


def test_twin_408_vigenere_byte():
    flag = b"FLAG{twin_408_vigenere_key}"
    key = b"VIG_KEY!"
    enc = bytes([b ^ key[i % len(key)] for i, b in enumerate(flag)])
    recovered = bytes([b ^ key[i % len(key)] for i, b in enumerate(enc)])
    assert recovered == flag


def test_twin_409_reverse_xor_add():
    flag = b"FLAG{twin_409_reverse_xor_add}"
    reversed_flag = flag[::-1]
    enc = bytes([((b ^ 0x5A) + 3) & 0xFF for b in reversed_flag])
    recovered = bytes([((b - 3) & 0xFF) ^ 0x5A for b in enc])[::-1]
    assert recovered == flag


def test_twin_410_sbox_table():
    flag = b"FLAG{twin_410_sbox_lookup}"
    rng = random.Random(1337)
    sbox = list(range(256))
    rng.shuffle(sbox)
    enc = bytes([sbox[b] for b in flag])
    recovered = invert_sbox(enc, bytes(sbox))
    assert recovered == flag

"""Synthetic twin benchmarks for Batch 43 reversing challenges (#778-#802).

Validates inversion and reconstruction primitives under strict air-gap.
"""

from __future__ import annotations

import base64
import zlib
from ctf_toolkit.crypto.classical import (
    interleave_byte_arrays,
    invert_affine_byte,
    invert_substitution_map,
    rc4_crypt,
    xor_with_stream,
)
from ctf_toolkit.reversing.transforms import (
    byte_shift,
    invert_add_xor,
    invert_byte_negation,
    invert_index_add,
    invert_index_add_xor,
    invert_index_key_xor,
    invert_square_index_xor,
    reverse_and_shift_bytes,
    reverse_string,
    rotate_and_xor_byte,
    xor_bytes,
)


def test_twin_178_nibble_dance():
    flag = b"FLAG{twin_178_nibble_dance}"
    target = bytes(((b >> 4) | ((b << 4) & 0xFF)) for b in flag)
    recovered = bytes(((b >> 4) | ((b << 4) & 0xFF)) for b in target)
    assert recovered == flag


def test_twin_179_simple_sub():
    flag = b"FLAG{twin_179_simple_sub}"
    target = bytes((b - 7) & 0xFF for b in flag)
    assert byte_shift(target, 7) == flag


def test_twin_180_square_index():
    flag = b"FLAG{twin_180_square_index}"
    target = bytes(b ^ ((i * i) & 0xFF) for i, b in enumerate(flag))
    assert invert_square_index_xor(target) == flag


def test_twin_181_two_step_mix():
    flag = b"FLAG{twin_181_two_step_mix}"
    target = bytes(((b + 5) ^ 0x33) & 0xFF for b in flag)
    assert invert_add_xor(target, add_c=5, xor_k=0x33) == flag


def test_twin_182_xor_ninefive():
    flag = b"FLAG{twin_182_xor_ninefive}"
    target = bytes(b ^ 0x9F for b in flag)
    assert xor_bytes(target, 0x9F) == flag


def test_twin_183_negate_bytes():
    flag = b"FLAG{twin_183_negate_bytes}"
    target = bytes((-b) & 0xFF for b in flag)
    assert invert_byte_negation(target) == flag


def test_twin_184_key_and_index():
    flag = b"FLAG{twin_184_key_and_index}"
    target = bytes(b ^ (i & 0xFF) ^ 0x11 for i, b in enumerate(flag))
    assert invert_index_key_xor(target, xor_k=0x11) == flag


def test_twin_185_add_then_xor():
    flag = b"FLAG{twin_185_add_then_xor}"
    target = bytes(((b + i) ^ 0x77) & 0xFF for i, b in enumerate(flag))
    assert invert_index_add_xor(target, xor_k=0x77) == flag


def test_twin_192_javascript_rev():
    flag = "FLAG{twin_192_javascript_rev}"
    enc = [ord(c) ^ 42 for c in flag]
    recovered = "".join(chr(x ^ 42) for x in enc)
    assert recovered == flag


def test_twin_319_golang_xor_runtime():
    flag = b"FLAG{twin_319_golang_xor}"
    target = bytes(b ^ 0x5A for b in flag)
    assert xor_bytes(target, 0x5A) == flag


def test_twin_320_golang_reversed_slice():
    flag = "FLAG{twin_320_golang_reversed}"
    raw = flag[::-1]
    assert reverse_string(raw) == flag


def test_twin_321_cpp_string_index_add():
    flag = b"FLAG{twin_321_cpp_index_add}"
    target = bytes((b + i) & 0xFF for i, b in enumerate(flag))
    assert invert_index_add(target) == flag


def test_twin_322_cpp_map_substitution():
    flag = b"FLAG{twin_322_cpp_map_sub}"
    table = bytes((i * 37 + 13) % 256 for i in range(256))
    target = bytes(table[b] for b in flag)
    assert invert_substitution_map(target, table) == flag


def test_twin_323_cpp_reverse_then_shift():
    flag = b"FLAG{twin_323_cpp_rev_shift}"
    target = bytes((b + 3) & 0xFF for b in flag[::-1])
    assert reverse_and_shift_bytes(target, shift=3) == flag


def test_twin_324_c_base64_embedded():
    flag = "FLAG{twin_324_c_base64_embed}"
    b64_str = base64.b64encode(flag.encode()).decode()
    assert base64.b64decode(b64_str).decode() == flag


def test_twin_325_c_rc4_decrypt():
    flag = b"FLAG{twin_325_c_rc4_decrypt}"
    key = b"secret_twin_key"
    ciphertext = rc4_crypt(key, flag)
    assert rc4_crypt(key, ciphertext) == flag


def test_twin_326_c_rol3_then_xor3c():
    flag = b"FLAG{twin_326_c_rol3_xor3c}"
    target = bytes(((((b << 3) & 0xFF) | (b >> 5)) ^ 0x3C) for b in flag)
    assert rotate_and_xor_byte(target, rot_left=3, xor_k=0x3C) == flag


def test_twin_327_c_base64_then_xor():
    flag = b"FLAG{twin_327_b64_then_xor}"
    b64_bytes = base64.b64encode(flag)
    blob = bytes(b ^ 0x11 for b in b64_bytes)
    recovered = base64.b64decode(bytes(b ^ 0x11 for b in blob))
    assert recovered == flag


def test_twin_328_c_interleaved_two_arrays():
    flag = b"FLAG{twin_328_interleaved_arr}"
    A = flag[0::2]
    B = flag[1::2]
    assert interleave_byte_arrays(A, B, len(flag)) == flag


def test_twin_329_c_fibonacci_keyed_xor():
    flag = b"FLAG{twin_329_fibo_key_xor}"
    fib = [0, 1]
    while len(fib) < len(flag):
        fib.append((fib[-1] + fib[-2]) % 256)
    K = bytes(fib[:len(flag)])
    target = bytes(f ^ k for f, k in zip(flag, K))
    assert xor_with_stream(target, K) == flag


def test_twin_331_c_antidebug_ptrace_static():
    flag = b"FLAG{twin_331_antidebug_xor}"
    target = bytes(b ^ 0x42 for b in flag)
    assert xor_bytes(target, 0x42) == flag


def test_twin_332_c_xor33_sum_gate():
    flag = b"FLAG{twin_332_xor33_sum}"
    target = bytes(b ^ 0x33 for b in flag)
    assert xor_bytes(target, 0x33) == flag


def test_twin_334_py_pyc_xor_consts():
    flag = b"FLAG{twin_334_pyc_xor_consts}"
    target = tuple(b ^ 0x77 for b in flag)
    recovered = bytes(t ^ 0x77 for t in target)
    assert recovered == flag


def test_twin_335_py_marshal_zlib_wrapped():
    flag = "FLAG{twin_335_zlib_wrapped}"
    comp = zlib.compress(flag.encode())
    b64_enc = base64.b64encode(comp).decode()
    dec = zlib.decompress(base64.b64decode(b64_enc)).decode()
    assert dec == flag


def test_twin_385_c_affine_17x_plus5():
    flag = b"FLAG{twin_385_c_affine_17x}"
    target = bytes((17 * b + 5) % 256 for b in flag)
    assert invert_affine_byte(target, a=17, b=5, mod=256) == flag

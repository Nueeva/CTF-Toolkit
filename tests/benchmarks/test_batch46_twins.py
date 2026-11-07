import base64
import zlib
import hashlib
from ctf_toolkit.reversing.transforms import (
    xor_bytes,
    invert_sbox,
    gray_decode,
    fibonacci_keystream,
    triangular_keystream,
    interleave_sequences,
    deinterleave_sequence,
    invert_odd_multiplier,
)


def test_twin_1021_pyc_gray():
    flag = "FLAG{twin_1021_pyc_gray}"
    enc = bytes([b ^ (b >> 1) for b in flag.encode()])
    assert gray_decode(enc).decode() == flag


def test_twin_1022_pyc_not_xor():
    flag = "FLAG{twin_1022_pyc_not_xor}"
    enc = bytes([( ~(b ^ 0x33) ) & 0xFF for b in flag.encode()])
    recovered = bytes([( (~b & 0xFF) ^ 0x33 ) for b in enc]).decode()
    assert recovered == flag


def test_twin_1023_pyc_affine256():
    flag = "FLAG{twin_1023_pyc_affine256}"
    a, c = 17, 9
    enc = bytes([(a * b + c) % 256 for b in flag.encode()])
    a_inv = pow(a, -1, 256)
    recovered = bytes([((b - c) * a_inv) % 256 for b in enc]).decode()
    assert recovered == flag


def test_twin_1024_pyc_index_add():
    flag = "FLAG{twin_1024_pyc_index_add}"
    enc = bytes([(b + 3 * i + 1) % 256 for i, b in enumerate(flag.encode())])
    recovered = bytes([(b - 3 * i - 1) % 256 for i, b in enumerate(enc)]).decode()
    assert recovered == flag


def test_twin_1028_pyc_zlib_hex():
    flag = "FLAG{twin_1028_pyc_zlib_hex}"
    compressed = zlib.compress(flag.encode())
    hx = compressed.hex()
    assert zlib.decompress(bytes.fromhex(hx)).decode() == flag


def test_twin_1030_pyc_translate():
    flag = "FLAG{twin_1030_pyc_translate}"
    sbox = bytes([(i * 43 + 29) % 256 for i in range(256)])
    enc = bytes([sbox[b] for b in flag.encode()])
    assert invert_sbox(enc, sbox).decode() == flag


def test_twin_1031_pyc_interleave():
    flag = "FLAG{twin_1031_pyc_interleave}"
    even, odd = deinterleave_sequence(flag)
    assert interleave_sequences(even, odd) == flag


def test_twin_1032_pyc_marshal_nested():
    flag = "FLAG{twin_1032_pyc_marshal_nested}"
    b64 = base64.b64encode(flag.encode()).decode()
    assert base64.b64decode(b64.encode()).decode() == flag


def test_twin_1033_pyc_key8_xor():
    flag = "FLAG{twin_1033_pyc_key8_xor}"
    key = b"Reverse!"
    enc = xor_bytes(flag.encode(), key)
    assert xor_bytes(enc, key).decode() == flag


def test_twin_1034_pyc_sha_ks():
    flag = "FLAG{twin_1034_pyc_sha_ks}"
    ks = hashlib.sha256(b"rv4seed").digest()
    enc = bytes([b ^ k for b, k in zip(flag.encode(), ks)])
    assert bytes([b ^ k for b, k in zip(enc, ks)]).decode() == flag


def test_twin_1035_pyc_triangular():
    flag = "FLAG{twin_1035_pyc_triangular}"
    ks = triangular_keystream(len(flag))
    enc = bytes([b ^ k for b, k in zip(flag.encode(), ks)])
    assert bytes([b ^ k for b, k in zip(enc, ks)]).decode() == flag


def test_twin_1037_pyc_mul_odd():
    flag = "FLAG{twin_1037_pyc_mul_odd}"
    multiplier = 37
    enc = bytes([(b * multiplier) % 256 for b in flag.encode()])
    assert invert_odd_multiplier(enc, multiplier).decode() == flag


def test_twin_1042_py_bytes_translate():
    flag = "FLAG{twin_1042_py_bytes_translate}"
    tbl = bytes([(i + 47) % 256 for i in range(256)])
    enc = flag.encode().translate(tbl)
    inv = {tbl[i]: i for i in range(256)}
    assert bytes([inv[b] for b in enc]).decode() == flag


def test_twin_1045_py_zlib_b64_2():
    flag = "FLAG{twin_1045_py_zlib_b64_2}"
    compressed = zlib.compress(flag.encode())
    b64 = base64.b64encode(compressed).decode()
    assert zlib.decompress(base64.b64decode(b64)).decode() == flag


def test_twin_1065_c_prime_table():
    flag = "FLAG{twin_1065_c_prime_table}"
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109]
    ks = bytes([primes[i] for i in range(len(flag))])
    enc = bytes([b ^ k for b, k in zip(flag.encode(), ks)])
    assert bytes([b ^ k for b, k in zip(enc, ks)]).decode() == flag


def test_twin_1066_c_square_table():
    flag = "FLAG{twin_1066_c_square_table}"
    ks = bytes([(i * i) % 256 for i in range(len(flag))])
    enc = bytes([b ^ k for b, k in zip(flag.encode(), ks)])
    assert bytes([b ^ k for b, k in zip(enc, ks)]).decode() == flag


def test_twin_1068_c_fib_table():
    flag = "FLAG{twin_1068_c_fib_table}"
    ks = fibonacci_keystream(len(flag))
    enc = bytes([b ^ k for b, k in zip(flag.encode(), ks)])
    assert bytes([b ^ k for b, k in zip(enc, ks)]).decode() == flag


def test_twin_1072_cpp_add_index():
    flag = "FLAG{twin_1072_cpp_add_index}"
    enc = bytes([(b + i) % 256 for i, b in enumerate(flag.encode())])
    assert bytes([(b - i) % 256 for i, b in enumerate(enc)]).decode() == flag


def test_twin_1073_cpp_reverse_xor():
    flag = "FLAG{twin_1073_cpp_reverse_xor}"
    rev = flag.encode()[::-1]
    enc = xor_bytes(rev, 0x5C)
    # Invert:
    dec = xor_bytes(enc, 0x5C)
    assert dec[::-1].decode() == flag


def test_twin_1077_go_add_idx2():
    flag = "FLAG{twin_1077_go_add_idx2}"
    enc = bytes([(b + i) % 256 for i, b in enumerate(flag.encode())])
    assert bytes([(b - i) % 256 for i, b in enumerate(enc)]).decode() == flag


def test_twin_1080_go_two_key():
    flag = "FLAG{twin_1080_go_two_key}"
    keys = [0x3A, 0x7C]
    enc = bytes([b ^ keys[i % 2] for i, b in enumerate(flag.encode())])
    assert bytes([b ^ keys[i % 2] for i, b in enumerate(enc)]).decode() == flag


def test_twin_1093_java_xor5a_check():
    flag = "FLAG{twin_1093_java_xor5a_check}"
    enc = xor_bytes(flag.encode(), 0x5A)
    assert xor_bytes(enc, 0x5A).decode() == flag


def test_twin_1094_java_xor2a_check():
    flag = "FLAG{twin_1094_java_xor2a_check}"
    enc = xor_bytes(flag.encode(), 0x2A)
    assert xor_bytes(enc, 0x2A).decode() == flag


def test_twin_1095_java_xor6d_check():
    flag = "FLAG{twin_1095_java_xor6d_check}"
    enc = xor_bytes(flag.encode(), 0x6D)
    assert xor_bytes(enc, 0x6D).decode() == flag


def test_twin_1096_java_add13_check():
    flag = "FLAG{twin_1096_java_add13_check}"
    enc = bytes([(b + 13) % 256 for b in flag.encode()])
    assert bytes([(b - 13) % 256 for b in enc]).decode() == flag

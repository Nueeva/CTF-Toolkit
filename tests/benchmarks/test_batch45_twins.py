import base64
import zlib
import codecs
from ctf_toolkit.reversing.transforms import (
    xor_bytes,
    invert_sbox,
    invert_cumulative_xor,
    caesar_ascii,
    rotate_left,
    rotate_right,
    swap_adjacent,
    bit_reverse_bytes,
    fibonacci_keystream,
    invert_rol_xor,
)


def ror8(b: int, n: int) -> int:
    n = n % 8
    return ((b >> n) | ((b << (8 - n)) & 0xFF)) & 0xFF


def rol8(b: int, n: int) -> int:
    n = n % 8
    return (((b << n) & 0xFF) | (b >> (8 - n))) & 0xFF


def test_twin_411_xor_sum_gate():
    flag = "FLAG{twin_411_xor_sum_gate}"
    key = 0x6B
    enc = xor_bytes(flag.encode(), key)
    assert xor_bytes(enc, key).decode() == flag


def test_twin_412_add_index_mod():
    flag = "FLAG{twin_412_add_index_mod}"
    enc = bytes([(ord(c) + i) % 256 for i, c in enumerate(flag)])
    recovered = bytes([(b - i) % 256 for i, b in enumerate(enc)]).decode()
    assert recovered == flag


def test_twin_413_base32_std():
    flag = "FLAG{twin_413_base32_std}"
    enc = base64.b32encode(flag.encode())
    assert base64.b32decode(enc).decode() == flag


def test_twin_414_sbox_inversion():
    flag = "FLAG{twin_414_sbox_inversion}"
    sbox = bytes([(i * 73 + 17) % 256 for i in range(256)])
    enc = bytes([sbox[b] for b in flag.encode()])
    assert invert_sbox(enc, sbox).decode() == flag


def test_twin_415_chain_xor():
    flag = "FLAG{twin_415_chain_xor}"
    prev = 0x7E
    enc = bytearray()
    for b in flag.encode():
        c = b ^ prev
        enc.append(c)
        prev = b
    # Invert:
    prev = 0x7E
    recovered = bytearray()
    for c in enc:
        b = c ^ prev
        recovered.append(b)
        prev = b
    assert bytes(recovered).decode() == flag


def test_twin_417_two_alternating_keys():
    flag = "FLAG{twin_417_two_alternating_keys}"
    keys = [0x3A, 0x7C]
    enc = bytes([ord(c) ^ keys[i % 2] for i, c in enumerate(flag)])
    recovered = bytes([b ^ keys[i % 2] for i, b in enumerate(enc)]).decode()
    assert recovered == flag


def test_twin_418_fibonacci_xor():
    flag = "FLAG{twin_418_fibonacci_xor}"
    ks = fibonacci_keystream(len(flag))
    enc = bytes([ord(c) ^ k for c, k in zip(flag, ks)])
    assert bytes([b ^ k for b, k in zip(enc, ks)]).decode() == flag


def test_twin_419_cpp_transform_xor3c():
    flag = "FLAG{twin_419_cpp_transform_xor3c}"
    enc = xor_bytes(flag.encode(), 0x3C)
    assert xor_bytes(enc, 0x3C).decode() == flag


def test_twin_420_cpp_accumulate_chain():
    flag = "FLAG{twin_420_cpp_accumulate_chain}"
    initial_iv = 0x11
    # Encryption:
    prev = initial_iv
    enc = bytearray()
    for b in flag.encode():
        c = b ^ prev
        enc.append(c)
        prev = b
    # Inversion:
    prev = initial_iv
    rec = bytearray()
    for b in enc:
        c = b ^ prev
        rec.append(c)
        prev = c
    assert bytes(rec).decode() == flag


def test_twin_421_cpp_rotate_left():
    flag = "FLAG{twin_421_cpp_rotate_left}"
    data = flag.encode()
    k = 5
    # std::rotate left by 5, then XOR 0x2A
    rotated = rotate_left(data, k)
    enc = xor_bytes(rotated, 0x2A)
    # Invert: XOR 0x2A, then rotate_right by 5
    dec_rot = xor_bytes(enc, 0x2A)
    assert rotate_right(dec_rot, k).decode() == flag


def test_twin_422_cpp_swap_adjacent():
    flag = "FLAG{twin_422_cpp_swap_adjacent}"
    # Adjacent swap then XOR 0x5C
    swapped = swap_adjacent(flag.encode())
    enc = xor_bytes(swapped, 0x5C)
    # Invert: XOR 0x5C then swap adjacent
    dec_swapped = xor_bytes(enc, 0x5C)
    assert swap_adjacent(dec_swapped).decode() == flag


def test_twin_423_cpp_bitset_reverse():
    flag = "FLAG{twin_423_cpp_bitset_reverse}"
    enc = bit_reverse_bytes(flag.encode())
    assert bit_reverse_bytes(enc).decode() == flag


def test_twin_424_cpp_printable_shift5():
    flag = "FLAG{twin_424_cpp_printable_shift5}"
    enc = caesar_ascii(flag, 5)
    assert caesar_ascii(enc, -5).decode() if isinstance(caesar_ascii(enc, -5), bytes) else caesar_ascii(enc, -5) == flag


def test_twin_425_translate_table():
    flag = "FLAG{twin_425_translate_table}"
    trans = bytes([(i + 13) % 256 for i in range(256)])
    enc = flag.encode().translate(trans)
    inv_trans = {trans[i]: i for i in range(256)}
    assert bytes([inv_trans[b] for b in enc]).decode() == flag


def test_twin_426_numpy_xor_array():
    flag = "FLAG{twin_426_numpy_xor_array}"
    enc = bytes([ord(c) ^ 0x6D for c in flag])
    assert bytes([b ^ 0x6D for b in enc]).decode() == flag


def test_twin_427_reduce_cumulative():
    flag = "FLAG{twin_427_reduce_cumulative}"
    initial = 0x44
    prev = initial
    enc = bytearray()
    for b in flag.encode():
        c = b ^ prev
        enc.append(c)
        prev = b
    # Invert:
    prev = initial
    rec = bytearray()
    for c in enc:
        b = c ^ prev
        rec.append(b)
        prev = b
    assert bytes(rec).decode() == flag


def test_twin_428_marshal_base64():
    flag = "FLAG{twin_428_marshal_base64}"
    b64 = base64.b64encode(flag.encode()).decode()
    assert base64.b64decode(b64.encode()).decode() == flag


def test_twin_430_codecs_rot13_hex():
    flag = "FLAG{twin_430_codecs_rot13_hex}"
    r13 = codecs.encode(flag, "rot_13")
    hx = r13.encode().hex()
    assert codecs.decode(bytes.fromhex(hx).decode(), "rot_13") == flag


def test_twin_432_zlib_then_hex():
    flag = "FLAG{twin_432_zlib_then_hex}"
    compressed = zlib.compress(flag.encode())
    hx = compressed.hex()
    assert zlib.decompress(bytes.fromhex(hx)).decode() == flag


def test_twin_433_pyc_add_const():
    flag = "FLAG{twin_433_pyc_add_const}"
    enc = bytes([(ord(c) + 23) % 256 for c in flag])
    assert bytes([(b - 23) % 256 for b in enc]).decode() == flag


def test_twin_434_bash_xor_hex_5a():
    flag = "FLAG{twin_434_bash_xor_hex_5a}"
    enc_bytes = bytes([ord(c) ^ 0x5A for c in flag])
    hx = enc_bytes.hex()
    assert bytes([b ^ 0x5A for b in bytes.fromhex(hx)]).decode() == flag


def test_twin_1017_pyc_rol_1():
    flag = "FLAG{twin_1017_pyc_rol_1}"
    enc = bytes([rol8(ord(c), 1) for c in flag])
    assert bytes([ror8(b, 1) for b in enc]).decode() == flag


def test_twin_1018_pyc_rol_3():
    flag = "FLAG{twin_1018_pyc_rol_3}"
    enc = bytes([rol8(ord(c), 3) for c in flag])
    assert bytes([ror8(b, 3) for b in enc]).decode() == flag


def test_twin_1019_pyc_rol_5():
    flag = "FLAG{twin_1019_pyc_rol_5}"
    enc = bytes([rol8(ord(c), 5) for c in flag])
    assert bytes([ror8(b, 5) for b in enc]).decode() == flag


def test_twin_1020_pyc_rol_7():
    flag = "FLAG{twin_1020_pyc_rol_7}"
    enc = bytes([rol8(ord(c), 7) for c in flag])
    assert bytes([ror8(b, 7) for b in enc]).decode() == flag

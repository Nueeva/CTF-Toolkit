from ctf_toolkit.crypto.classical import (
    bin_to_gray,
    gray_to_bin,
    gray_encode_bytes,
    gray_decode_bytes,
    repeating_key_xor,
)


def test_gray_code_integers():
    # Known Gray code conversions:
    # 0 -> 0, 1 -> 1, 2 -> 3, 3 -> 2, 4 -> 6, 5 -> 7, 6 -> 5, 7 -> 4
    expected = [(0, 0), (1, 1), (2, 3), (3, 2), (4, 6), (5, 7), (6, 5), (7, 4)]
    for b, g in expected:
        assert bin_to_gray(b) == g, f"bin_to_gray({b}) failed"
        assert gray_to_bin(g) == b, f"gray_to_bin({g}) failed"


def test_gray_code_bytes_roundtrip():
    data = b"GETSFLAG{c_gray_transform_test}"
    encoded = gray_encode_bytes(data)
    decoded = gray_decode_bytes(encoded)
    assert decoded == data
    assert encoded != data


def test_repeating_key_xor_roundtrip():
    plaintext = b"GETSFLAG{repeating_xor_roundtrip_test}"
    key = b"VIGENEREKEY123"
    ciphertext = repeating_key_xor(plaintext, key)
    recovered = repeating_key_xor(ciphertext, key)
    assert recovered == plaintext
    assert ciphertext != plaintext


def test_repeating_key_xor_empty_key():
    try:
        repeating_key_xor(b"hello", b"")
        assert False, "Should raise ValueError on empty key"
    except ValueError:
        pass

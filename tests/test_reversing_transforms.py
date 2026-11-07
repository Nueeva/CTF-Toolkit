from ctf_toolkit.reversing.transforms import (
    endian_swap,
    reverse_string,
    xor_bytes,
    xor_bruteforce_single,
)


def test_reverse_string():
    assert reverse_string("abc") == "cba"


def test_endian_swap():
    assert endian_swap(bytes.fromhex("11223344"), word_size=4) == bytes.fromhex("44332211")


def test_xor_bytes():
    enc = xor_bytes(b"hello", 0x2A)
    dec = xor_bytes(enc, 0x2A)
    assert dec == b"hello"


def test_xor_bruteforce_single():
    secret = b"FLAG{test_xor}"
    enc = xor_bytes(secret, 0x55)
    candidates = xor_bruteforce_single(enc)
    top_key, _, top_dec = candidates[0]
    assert top_key == 0x55
    assert top_dec == secret

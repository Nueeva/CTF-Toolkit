from ctf_toolkit.crypto.classical import atbash, caesar_decrypt, caesar_encrypt
from ctf_toolkit.crypto.rsa import fermat_factor


def test_caesar_roundtrip():
    assert caesar_decrypt(caesar_encrypt("hello", 13), 13) == "hello"


def test_atbash():
    assert atbash("ABC") == "ZYX"


def test_fermat_factor_small():
    result = fermat_factor(77)
    assert result is not None
    p, q = result
    assert p * q == 77

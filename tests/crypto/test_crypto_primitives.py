from ctf_toolkit.crypto.classical import beaufort_decrypt, beaufort_encrypt, autokey_decrypt, autokey_encrypt
from ctf_toolkit.crypto.rc4 import rc4_crypt
from ctf_toolkit.crypto.rsa import rsa_cube_root, rsa_multiprime_decrypt


def test_beaufort_roundtrip():
    plaintext = "beaufortreciprocal"
    key = "HEAT"
    ciphertext = beaufort_encrypt(plaintext, key)
    recovered = beaufort_decrypt(ciphertext, key)
    assert recovered == plaintext


def test_autokey_roundtrip():
    plaintext = "vigenereautokeyplain"
    primer = "FLAG"
    ciphertext = autokey_encrypt(plaintext, primer)
    recovered = autokey_decrypt(ciphertext, primer)
    assert recovered == plaintext


def test_rc4_roundtrip():
    data = b"GETSFLAG{rc4_test_roundtrip}"
    key = b"s3cr3t-rc4-key"
    ciphertext = rc4_crypt(key, data)
    recovered = rc4_crypt(key, ciphertext)
    assert recovered == data
    assert ciphertext != data


def test_rsa_cube_root():
    m = 12345678901234567890
    c = m ** 3
    assert rsa_cube_root(c) == m


def test_rsa_multiprime_decrypt():
    p = 61
    q = 53
    r = 47
    e = 17
    m = 42
    n = p * q * r
    c = pow(m, e, n)
    assert rsa_multiprime_decrypt([p, q, r], e, c) == m

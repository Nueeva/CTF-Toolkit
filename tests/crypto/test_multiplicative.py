from ctf_toolkit.crypto.classical import (
    multiplicative_encrypt,
    multiplicative_decrypt,
)


def test_multiplicative_cipher_known_vector() -> None:
    plain = "multiplicativecipher"
    cipher = "gkzdebzeoadercoebxcp"
    # 7x mod 26
    enc = multiplicative_encrypt(plain, a=7)
    assert enc == cipher
    dec = multiplicative_decrypt(cipher, a=7)
    assert dec == plain


def test_multiplicative_cipher_roundtrip() -> None:
    msg = "TheQuickBrownFoxJumpsOverTheLazyDog"
    for a in [3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
        encrypted = multiplicative_encrypt(msg, a=a)
        decrypted = multiplicative_decrypt(encrypted, a=a)
        assert decrypted == msg


def test_multiplicative_cipher_non_coprime() -> None:
    # gcd(2, 26) = 2 != 1
    try:
        multiplicative_encrypt("hello", a=2)
        assert False, "Should raise ValueError"
    except ValueError:
        pass

    try:
        multiplicative_decrypt("hello", a=13)
        assert False, "Should raise ValueError"
    except ValueError:
        pass

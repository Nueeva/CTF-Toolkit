from ctf_toolkit.crypto.des import des_ecb_decrypt, des_ecb_encrypt


def test_des_ecb_known_vector() -> None:
    key = bytes.fromhex("0ecee728bf87a4c1")
    ct = bytes.fromhex("1461920f18c7f9cd5a9adb1a82b155914d3a1a8a57a73b1d876302981837bd63")
    pt = des_ecb_decrypt(ct, key=key)
    assert pt == b"GETSFLAG{des_ecb_legacy}"


def test_des_ecb_roundtrip() -> None:
    key = b"12345678"
    msg = b"A quick brown fox jumps over the lazy dog."
    enc = des_ecb_encrypt(msg, key=key)
    dec = des_ecb_decrypt(enc, key=key)
    assert dec == msg


def test_des_invalid_key() -> None:
    try:
        des_ecb_decrypt(b"12345678", key=b"short")
        assert False, "Should raise ValueError for invalid key length"
    except ValueError:
        pass

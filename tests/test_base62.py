from ctf_toolkit.crypto.encoding import base62_decode, base62_encode


def test_base62_known_vector() -> None:
    token = "45lqGSN8UiCdFHfeuCfZ6sQc8p9fSIJ0MRkB2HUXkr"
    decoded = base62_decode(token)
    assert decoded == b"GETSFLAG{base62_alnum_encoding}"


def test_base62_roundtrip() -> None:
    plaintext = b"CyberSecurityCTF"
    encoded = base62_encode(plaintext)
    decoded = base62_decode(encoded)
    assert decoded == plaintext


def test_base62_leading_zeros() -> None:
    raw = b"\x00\x00\x01\x02\x03"
    enc = base62_encode(raw)
    assert enc.startswith("00")
    dec = base62_decode(enc)
    assert dec == raw

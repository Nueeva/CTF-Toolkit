from ctf_toolkit.crypto.classical import base58_decode, base58_encode


def test_base58_roundtrip():
    raw = b"Hello World!"
    enc = base58_encode(raw)
    dec = base58_decode(enc)
    assert dec == raw


def test_base58_ctf_vector():
    vector = "zbC44VxnMv1EkovM3531JTjaEsE"
    decoded = base58_decode(vector)
    assert decoded == b"GETSFLAG{mca_base58}"


def test_base58_leading_zeros():
    raw = b"\x00\x00\x01\x02\x03"
    enc = base58_encode(raw)
    assert enc.startswith("11")
    dec = base58_decode(enc)
    assert dec == raw

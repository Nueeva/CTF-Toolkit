from ctf_toolkit.crypto.classical import base45_decode, base45_encode


def test_base45_roundtrip():
    # RFC 9285 examples:
    # "Hello!!" -> "%69 VD92EX0"
    raw = b"Hello!!"
    enc = base45_encode(raw)
    assert enc == "%69 VD92EX0"
    dec = base45_decode(enc)
    assert dec == raw


def test_base45_ctf_vector():
    vector = "K09WTA-*8GB8-QFHECXZCSX6HFEV2C:.DV3EZEDX3D"
    decoded = base45_decode(vector)
    assert decoded == b"GETSFLAG{base45_qr_encoding}"

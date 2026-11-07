from ctf_toolkit.crypto.classical import scytale_decrypt, scytale_encrypt


def test_scytale_roundtrip():
    msg = "scytalewrappedround"
    enc = scytale_encrypt(msg, diameter=4)
    dec = scytale_decrypt(enc, diameter=4, strip_pad=True)
    assert dec == msg


def test_scytale_known_vector():
    # sareu cladn yeprd twpox
    ct = "sareucladnyeprdtwpox"
    dec = scytale_decrypt(ct, diameter=4, strip_pad=True)
    assert dec == "scytalewrappedround"

from ctf_toolkit.crypto.classical import gronsfeld_decrypt, gronsfeld_encrypt


def test_gronsfeld_roundtrip():
    msg = "gronsfelddigits"
    key = "31415"
    enc = gronsfeld_encrypt(msg, key)
    assert enc == "jssoxifpeilhmux"
    dec = gronsfeld_decrypt(enc, key)
    assert dec == msg


def test_gronsfeld_mixed_case():
    msg = "Gronsfeld Ctx 123"
    key = [3, 1, 4]
    enc = gronsfeld_encrypt(msg, key)
    dec = gronsfeld_decrypt(enc, key)
    assert dec == msg

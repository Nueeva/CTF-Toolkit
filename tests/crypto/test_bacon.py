from ctf_toolkit.crypto.classical import bacon_decode, bacon_encode


def test_bacon_roundtrip():
    msg = "helloworld"
    enc = bacon_encode(msg)
    dec = bacon_decode(enc)
    assert dec == msg


def test_bacon_ctf_vector():
    cipher = "AAAAB AAAAA AAABA ABBBA ABBAB AAAAB ABAAA ABBAB AAAAA BAAAB BBAAA BAABA BAABB AABAA AABBA"
    dec = bacon_decode(cipher)
    assert dec == "baconbinarysteg"

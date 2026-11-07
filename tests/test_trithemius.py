from ctf_toolkit.crypto.classical import trithemius_decrypt, trithemius_encrypt


def test_trithemius_known_vector() -> None:
    cipher = "tskwljspcbcsush"
    dec = trithemius_decrypt(cipher)
    assert dec == "trithemiusshift"


def test_trithemius_roundtrip() -> None:
    text = "Polygraphia Johannes Trithemius 1518"
    enc = trithemius_encrypt(text)
    dec = trithemius_decrypt(enc)
    assert dec == text


def test_trithemius_step() -> None:
    text = "AAAA"
    enc = trithemius_encrypt(text, step=2)
    # A + 0 -> A, A + 2 -> C, A + 4 -> E, A + 6 -> G
    assert enc == "ACEG"
    dec = trithemius_decrypt(enc, step=2)
    assert dec == text

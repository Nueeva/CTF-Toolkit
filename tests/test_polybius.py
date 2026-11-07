from ctf_toolkit.crypto.classical import polybius_decode, polybius_encode


def test_polybius_decode():
    # 35 34 31 54 12 24 45 43 -> polybiu
    coords = "35 34 31 54 12 24 45 43"
    assert polybius_decode(coords) == "polybius"


def test_polybius_encode():
    assert polybius_encode("hello") == "23 15 31 31 34"

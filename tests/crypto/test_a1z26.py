from ctf_toolkit.crypto.classical import a1z26_decode, a1z26_encode
from ctf_toolkit.crypto.encoding import smart_decode


def test_a1z26_decode():
    raw = "1-2-3-4-5"
    assert a1z26_decode(raw) == "abcde"

    raw_spaces = "8 5 12 12 15"
    assert a1z26_decode(raw_spaces) == "hello"


def test_a1z26_encode():
    assert a1z26_encode("hello") == "8-5-12-12-15"
    assert a1z26_encode("abc", separator=" ") == "1 2 3"


def test_smart_decode_a1z26():
    res = smart_decode("3-20-6-1-12-19-5-3-15-12-15-18")
    assert res.get("a1z26") == "ctfalsecolor"

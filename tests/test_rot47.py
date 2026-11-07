from ctf_toolkit.crypto.classical import rot47
from ctf_toolkit.crypto.encoding import smart_decode


def test_rot47_known_vector() -> None:
    cipher = "vt%$u{pvLC@Ecf0AC:?E23=60D9:7EN"
    res = rot47(cipher)
    assert res == "GETSFLAG{rot47_printable_shift}"


def test_rot47_roundtrip() -> None:
    text = "The quick brown fox jumps over the lazy dog! 1234567890"
    enc = rot47(text)
    dec = rot47(enc)
    assert dec == text


def test_rot47_smart_decode() -> None:
    cipher = "vt%$u{pvLC@Ecf0AC:?E23=60D9:7EN"
    res = smart_decode(cipher)
    assert "rot47" in res
    assert res["rot47"] == "GETSFLAG{rot47_printable_shift}"

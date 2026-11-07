from ctf_toolkit.crypto.classical import rot18


def test_rot18_known_vector() -> None:
    cipher = "ebgbarrvtugzvk63"
    plain = rot18(cipher)
    assert plain == "rotoneeightmix18"


def test_rot18_involution() -> None:
    original = "Hello World 12345!"
    enc = rot18(original)
    dec = rot18(enc)
    assert dec == original


def test_rot18_digits_and_letters() -> None:
    # 0 -> 5, 5 -> 0, a -> n, n -> a, A -> N, N -> A
    assert rot18("0123456789") == "5678901234"
    assert rot18("abcdefghijklmnopqrstuvwxyz") == "nopqrstuvwxyzabcdefghijklm"

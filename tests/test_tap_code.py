from ctf_toolkit.crypto.classical import tap_code_decode, tap_code_encode


def test_tap_code_known_vector() -> None:
    cipher = "4.4 1.1 3.5 1.3 3.4 1.4 1.5 3.5 3.4 3.1 5.4 1.2 2.4 4.5 4.3"
    result = tap_code_decode(cipher)
    assert result == "tapcodepolybius"


def test_tap_code_roundtrip() -> None:
    plaintext = "SECRET"
    encoded = tap_code_encode(plaintext)
    decoded = tap_code_decode(encoded)
    assert decoded == "secret"


def test_tap_code_k_mapping() -> None:
    # In 5x5 Tap Code, K maps to C (1.3)
    encoded = tap_code_encode("KNOCK")
    decoded = tap_code_decode(encoded)
    assert decoded == "cnocc"


def test_tap_code_dot_format() -> None:
    # 4.4 1.1 3.5 -> T A P
    dot_cipher = ".... ....  . .  ... ....."
    decoded = tap_code_decode(dot_cipher)
    assert decoded == "tap"

from ctf_toolkit.crypto.classical import nato_phonetic_decode, nato_phonetic_encode


def test_nato_phonetic_known_vector() -> None:
    cipher = "November Alpha Tango Oscar Papa Hotel Oscar November Echo Tango India Charlie Alpha Lima Papa Hotel Alpha"
    decoded = nato_phonetic_decode(cipher)
    assert decoded == "natophoneticalpha"


def test_nato_phonetic_roundtrip() -> None:
    plaintext = "SECRET"
    encoded = nato_phonetic_encode(plaintext)
    decoded = nato_phonetic_decode(encoded)
    assert decoded == "secret"


def test_nato_phonetic_special_cases() -> None:
    # X-ray and Xray
    cipher = "X-ray Yankee Zulu"
    decoded = nato_phonetic_decode(cipher)
    assert decoded == "xyz"

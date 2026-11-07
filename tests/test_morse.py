from ctf_toolkit.crypto.morse import morse_decode, morse_encode


def test_morse_roundtrip():
    text = "HELLO WORLD"
    enc = morse_encode(text)
    dec = morse_decode(enc)
    assert dec == text


def test_morse_punctuation():
    text = "FLAG{TEST_1}"
    enc = morse_encode(text)
    dec = morse_decode(enc)
    assert dec == text

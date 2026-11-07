from ctf_toolkit.osint_misc.uudecode import decode_uu, encode_uu


def test_uu_roundtrip():
    payload = b"Hello, UUencode world! CTF testing 123.\n"
    enc = encode_uu(payload, filename="test.txt")
    dec = decode_uu(enc)
    assert dec == payload


def test_uu_known_vector():
    raw_uue = "begin 644 secret.txt\n><V5C<F5T/4=%5%-&3$%'>VUC85]U=65N8V]D97T*\n`\nend\n"
    dec = decode_uu(raw_uue)
    assert b"GETSFLAG{mca_uuencode}" in dec

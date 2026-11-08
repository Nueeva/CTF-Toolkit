from ctf_toolkit.crypto.encoding import decode_hexdump


def test_decode_hexdump_spaces() -> None:
    raw_dump = "43 61 74 61 74 61 6e"
    res = decode_hexdump(raw_dump)
    assert res == b"Catatan"


def test_decode_hexdump_with_offset_and_sidebar() -> None:
    raw_dump = """
    00000000: 4745 5453 464c 4147 7b74 6573 747d       GETSFLAG{test}
    """
    res = decode_hexdump(raw_dump)
    assert res == b"GETSFLAG{test}"


def test_decode_hexdump_ctf_vector() -> None:
    raw_dump = "47 45 54 53 46 4c 41 47 7b 68 65 78 5f 70 6c 61 69 6e 5f 68 65 78 64 75 6d 70 7d"
    res = decode_hexdump(raw_dump)
    assert res == b"GETSFLAG{hex_plain_hexdump}"

from ctf_toolkit.osint_misc.netstrings import encode_netstring, parse_netstrings


def test_parse_netstrings():
    data = b"5:hello,4:meta,23:GETSFLAG{mca_netstring},3:bye,"
    items = parse_netstrings(data)
    assert items == ["hello", "meta", "GETSFLAG{mca_netstring}", "bye"]


def test_encode_netstring():
    assert encode_netstring("test") == b"4:test,"

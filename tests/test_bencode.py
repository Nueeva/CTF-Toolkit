from ctf_toolkit.osint_misc.bencode import bdecode, parse_torrent


def test_bdecode_primitives():
    assert bdecode(b"i42e") == 42
    assert bdecode(b"4:spam") == b"spam"
    assert bdecode(b"l4:spami42ee") == [b"spam", 42]
    assert bdecode(b"d3:bar4:spam3:fooi42ee") == {"bar": b"spam", "foo": 42}


def test_parse_torrent():
    raw_torrent = b"d8:announce18:http://tracker.lan7:comment15:flag_in_comment4:infod4:name8:test.bin6:lengthi1024eee"
    meta = parse_torrent(raw_torrent)
    assert meta["announce"] == "http://tracker.lan"
    assert meta["comment"] == "flag_in_comment"
    assert meta["name"] == "test.bin"
    assert meta["length"] == 1024

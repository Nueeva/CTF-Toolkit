from ctf_toolkit.blockchain.calldata import parse_calldata


def test_parse_calldata():
    raw_hex = "0xe12a6d75000000000000000000000000c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff48656c6c6f20576f726c64210000000000000000000000000000000000000000"
    res = parse_calldata(raw_hex)
    assert res["selector"] == "0xe12a6d75"
    assert "Hello World!" in res["ascii_strings"]

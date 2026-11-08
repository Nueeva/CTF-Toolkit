from ctf_toolkit.blockchain.storage import decode_storage_slot_string


def test_decode_storage_slot_string():
    # 'hello' (5 chars) -> length * 2 = 10 (0x0a)
    # data: 'hello' (68656c6c6f) padded with zeroes, ending with 0a
    slot_val = "0x68656c6c6f00000000000000000000000000000000000000000000000000000a"
    decoded = decode_storage_slot_string(slot_val)
    assert decoded == "hello"

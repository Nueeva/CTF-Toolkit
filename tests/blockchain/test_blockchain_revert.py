from ctf_toolkit.blockchain.revert import decode_revert_reason


def test_decode_revert_reason_error_string():
    # 08c379a0 + offset 0x20 + length 0x04 + 'test'
    hex_err = "0x08c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000"
    res = decode_revert_reason(hex_err)
    assert res["error_type"] == "Error(string)"
    assert res["reason"] == "test"


def test_decode_revert_reason_panic():
    # 4e487b71 + panic code 0x12 (division by zero)
    hex_panic = "0x4e487b710000000000000000000000000000000000000000000000000000000000000012"
    res = decode_revert_reason(hex_panic)
    assert res["error_type"] == "Panic(uint256)"
    assert res["panic_code"] == 0x12
    assert "Division by zero" in str(res["panic_description"])

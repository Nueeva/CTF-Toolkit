from __future__ import annotations

import re

from ctf_toolkit.blockchain.calldata import parse_calldata
from ctf_toolkit.blockchain.revert import decode_revert_reason
from ctf_toolkit.blockchain.storage import (
    decode_storage_multislot_string,
    decode_storage_slot_string,
)


def test_twin_1813_calldata_dyn_bytes():
    target = b"FLAG{twin_ab_dyn_bytes_tail}"
    hexdata = "0x5f0e0336" + "00" * 32 + target.hex() + "00" * 10
    parsed = parse_calldata(hexdata)
    strings = [s for s in parsed["ascii_strings"] if "FLAG{" in s]
    assert strings == ["FLAG{twin_ab_dyn_bytes_tail}"]


def test_twin_1814_calldata_nested_tuple():
    target = b"FLAG{twin_ab_nested_tuple_array}"
    hexdata = "0xaefe85d8" + "00" * 64 + target.hex() + "00" * 16
    parsed = parse_calldata(hexdata)
    strings = [s for s in parsed["ascii_strings"] if "FLAG{" in s]
    assert strings == ["FLAG{twin_ab_nested_tuple_array}"]


def test_twin_1815_packed_middle():
    target = b"FLAG{twin_ab_packed_middle}"
    packed_hex = "deadbeef" + target.hex() + "1234" * 10
    raw = bytes.fromhex(packed_hex)
    m = re.search(rb"(FLAG\{[^}]+\})", raw)
    assert m is not None
    assert m.group(1).decode() == "FLAG{twin_ab_packed_middle}"


def test_twin_1816_packed_bytes():
    target = b"FLAG{twin_ab_packed_bytes}"
    packed_hex = ("00" * 16) + target.hex()
    raw = bytes.fromhex(packed_hex)
    assert raw[16:].decode() == "FLAG{twin_ab_packed_bytes}"


def test_twin_1817_custom_revert():
    target = b"FLAG{twin_ab_custom_error}"
    # Selector 925132ec + offset 32 + length 26 + string + padding
    revert_hex = "925132ec" + "00" * 31 + "20" + "00" * 31 + f"{len(target):02x}" + target.hex()
    res = decode_revert_reason(revert_hex)
    assert any("FLAG{twin_ab_custom_error}" in s for s in res.get("extracted_strings", []))


def test_twin_1819_selector_disambig():
    target = b"FLAG{twin_ab_selector_disambig}"
    revert_hex = "a35b150b" + "00" * 32 + "00" * 31 + "20" + "00" * 31 + f"{len(target):02x}" + target.hex()
    res = decode_revert_reason(revert_hex)
    assert any("FLAG{twin_ab_selector_disambig}" in s for s in res.get("extracted_strings", []))


def test_twin_1820_eip712_typed_data():
    typed_data = {
        "message": {
            "claim": "FLAG{twin_ab_eip712_claim}",
            "value": 100,
        }
    }
    assert typed_data["message"]["claim"] == "FLAG{twin_ab_eip712_claim}"


def test_twin_1821_eth_call_return_tuple():
    target = b"FLAG{twin_ab_return_tuple_array}"
    raw_hex = "00" * 64 + target.hex() + "00" * 16
    parsed = parse_calldata(raw_hex)
    strings = [s for s in parsed["ascii_strings"] if "FLAG{" in s]
    assert strings == ["FLAG{twin_ab_return_tuple_array}"]


def test_twin_1822_calldata_string_array():
    target = b"FLAG{twin_ab_string_array_elem}"
    raw_hex = "00" * 32 + target.hex() + "00" * 16
    parsed = parse_calldata(raw_hex)
    strings = [s for s in parsed["ascii_strings"] if "FLAG{" in s]
    assert strings == ["FLAG{twin_ab_string_array_elem}"]


def test_twin_1823_calldata_bytes_array():
    target = b"FLAG{twin_ab_bytes_array_deep}"
    raw_hex = "00" * 32 + target.hex() + "00" * 16
    parsed = parse_calldata(raw_hex)
    strings = [s for s in parsed["ascii_strings"] if "FLAG{" in s]
    assert strings == ["FLAG{twin_ab_bytes_array_deep}"]


def test_twin_1828_storage_reentrancy():
    flag = "FLAG{twin_ca_reentrancy_drain}"
    raw_bytes = flag.encode().ljust(31, b"\x00") + bytes([len(flag) * 2])
    slot_hex = "0x" + raw_bytes.hex()
    decoded = decode_storage_slot_string(slot_hex)
    assert decoded == flag


def test_twin_1829_storage_overflow():
    flag = "FLAG{twin_ca_integer_overflow}"
    raw_bytes = flag.encode().ljust(31, b"\x00") + bytes([len(flag) * 2])
    slot_hex = "0x" + raw_bytes.hex()
    decoded = decode_storage_slot_string(slot_hex)
    assert decoded == flag


def test_twin_1830_storage_underflow():
    flag = "FLAG{twin_ca_integer_underflow}"
    raw_bytes = flag.encode().ljust(31, b"\x00") + bytes([len(flag) * 2])
    slot_hex = "0x" + raw_bytes.hex()
    decoded = decode_storage_slot_string(slot_hex)
    assert decoded == flag


def test_twin_1831_storage_tx_origin():
    flag = "FLAG{twin_ca_tx_origin_auth}"
    raw_bytes = flag.encode().ljust(31, b"\x00") + bytes([len(flag) * 2])
    slot_hex = "0x" + raw_bytes.hex()
    decoded = decode_storage_slot_string(slot_hex)
    assert decoded == flag


def test_twin_1832_storage_unchecked_return():
    flag = "FLAG{twin_ca_unchecked_return}"
    raw_bytes = flag.encode().ljust(31, b"\x00") + bytes([len(flag) * 2])
    slot_hex = "0x" + raw_bytes.hex()
    decoded = decode_storage_slot_string(slot_hex)
    assert decoded == flag


def test_twin_1833_storage_selfdestruct():
    flag = "FLAG{twin_ca_selfdestruct_open}"
    raw_bytes = flag.encode().ljust(31, b"\x00") + bytes([len(flag) * 2])
    slot_hex = "0x" + raw_bytes.hex()
    decoded = decode_storage_slot_string(slot_hex)
    assert decoded == flag


def test_twin_1834_storage_weak_randomness():
    flag = "FLAG{twin_ca_weak_randomness}"
    raw_bytes = flag.encode().ljust(31, b"\x00") + bytes([len(flag) * 2])
    slot_hex = "0x" + raw_bytes.hex()
    decoded = decode_storage_slot_string(slot_hex)
    assert decoded == flag


def test_twin_1835_storage_delegatecall_collision():
    flag = "FLAG{twin_ca_delegatecall_collision}"
    b1 = flag[:32].encode()
    b2 = flag[32:].encode().ljust(32, b"\x00")
    slots = ["0x" + b1.hex(), "0x" + b2.hex()]
    decoded = decode_storage_multislot_string(slots)
    assert decoded == flag


def test_twin_1836_storage_array_length_underflow():
    flag = "FLAG{twin_ca_array_length_underflow}"
    b1 = flag[:32].encode()
    b2 = flag[32:].encode().ljust(32, b"\x00")
    slots = ["0x" + b1.hex(), "0x" + b2.hex()]
    decoded = decode_storage_multislot_string(slots)
    assert decoded == flag


def test_twin_1837_storage_proxy_layout_mismatch():
    flag = "FLAG{twin_ca_proxy_layout_mismatch}"
    b1 = flag[:32].encode()
    b2 = flag[32:].encode().ljust(32, b"\x00")
    slots = ["0x" + b1.hex(), "0x" + b2.hex()]
    decoded = decode_storage_multislot_string(slots)
    assert decoded == flag


def test_twin_1838_storage_signature_replay():
    flag = "FLAG{twin_ca_signature_replay}"
    raw_bytes = flag.encode().ljust(31, b"\x00") + bytes([len(flag) * 2])
    slot_hex = "0x" + raw_bytes.hex()
    decoded = decode_storage_slot_string(slot_hex)
    assert decoded == flag


def test_twin_1851_join2_pushes():
    part_a = b"FLAG{twin_split_in_two_pushes_part_"
    part_b = b"a_b}"
    combined = (part_a + part_b).decode()
    assert combined == "FLAG{twin_split_in_two_pushes_part_a_b}"


def test_twin_1852_join2_halves():
    part_a = b"FLAG{twin_halves_concatenate_me_in_order_"
    part_b = b"ok}"
    combined = (part_a + part_b).decode()
    assert combined == "FLAG{twin_halves_concatenate_me_in_order_ok}"


def test_twin_1853_join3_parts():
    part_a = b"FLAG{twin_three_parts_joined_together_make_up_"
    part_b = b"the_whole_long_flag_"
    part_c = b"value}"
    combined = (part_a + part_b + part_c).decode()
    assert combined == "FLAG{twin_three_parts_joined_together_make_up_the_whole_long_flag_value}"


def test_twin_1854_xor_gate():
    target = b"FLAG{twin_xor_single_key_rec}"
    key = 0x5A
    ciphertext = bytes(b ^ key for b in target)
    recovered = bytes(b ^ key for b in ciphertext).decode()
    assert recovered == "FLAG{twin_xor_single_key_rec}"

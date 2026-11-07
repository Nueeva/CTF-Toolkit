from __future__ import annotations

from ctf_toolkit.blockchain.storage import (
    compute_array_storage_slot,
    compute_mapping_storage_slot,
    decode_storage_multislot_string,
    decode_storage_slot_string,
    extract_packed_storage_locator,
)


def test_twin_1998_struct_in_map() -> None:
    # mapping(address => struct{id, note, ref}) slot 4
    addr = "0xe5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"
    base_slot = compute_mapping_storage_slot(addr, 4)
    # field 1 is note
    note_slot = hex(int(base_slot, 16) + 1)
    # mock storage dump
    target_str = "FLAG{twin_map_struct}"
    encoded = target_str.encode("utf-8").ljust(31, b"\x00") + bytes([len(target_str) * 2])
    storage = {note_slot: "0x" + encoded.hex()}
    
    val = storage[note_slot]
    res = decode_storage_slot_string(val)
    assert res == target_str


def test_twin_1999_array_index2() -> None:
    # string[] array at slot 3, index 2
    target_slot = compute_array_storage_slot(3, index=2)
    target_str = "FLAG{twin_arr_index2}"
    encoded = target_str.encode("utf-8").ljust(31, b"\x00") + bytes([len(target_str) * 2])
    storage = {target_slot: "0x" + encoded.hex()}
    
    val = storage[target_slot]
    res = decode_storage_slot_string(val)
    assert res == target_str


def test_twin_2000_packed_locator() -> None:
    # slot 0 packs locator at byte offset 1, width 2
    # uint16 target slot = 12 (0x000c)
    slot0_val = "0x0000000000000000000000000000000000000000000000000007ea001c000c00"
    target_slot_num = extract_packed_storage_locator(slot0_val, offset_bytes=1, width_bytes=2)
    assert target_slot_num == 12

    target_slot_hex = f"0x{target_slot_num:064x}"
    target_str = "FLAG{twin_packed_locate}"
    encoded = target_str.encode("utf-8").ljust(31, b"\x00") + bytes([len(target_str) * 2])
    storage = {target_slot_hex: "0x" + encoded.hex()}
    
    res = decode_storage_slot_string(storage[target_slot_hex])
    assert res == target_str


def test_twin_2001_mapping_uint_long() -> None:
    # mapping(uint => string) slot 7, key 88888
    # long string splits into multiple slots
    base_slot = compute_mapping_storage_slot(88888, 7)
    target = "FLAG{twin_map_uint_long_order_reference_text_extended_payload}"
    chunk1 = target[:32]
    chunk2 = target[32:].ljust(32, "\x00")
    slots = ["0x" + chunk1.encode("utf-8").hex(), "0x" + chunk2.encode("utf-8").hex()]
    res = decode_storage_multislot_string(slots)
    assert res == target


def test_twin_2002_array_struct() -> None:
    # struct{uint, string, uint}[] at slot 1, index 1 (element_slots=3, string is field 1)
    base_slot = compute_array_storage_slot(1, index=1, element_slots=3)
    string_slot = hex(int(base_slot, 16) + 1)
    target_str = "FLAG{twin_arr_struct}"
    encoded = target_str.encode("utf-8").ljust(31, b"\x00") + bytes([len(target_str) * 2])
    storage = {string_slot: "0x" + encoded.hex()}
    
    res = decode_storage_slot_string(storage[string_slot])
    assert res == target_str


def test_twin_2003_deep_vault() -> None:
    # Vault recovery phrase long text in storage
    target = "FLAG{twin_deep_vault_cold_storage_phrase}"
    chunk1 = target[:32]
    chunk2 = target[32:].ljust(32, "\x00")
    slots = ["0x" + chunk1.encode("utf-8").hex(), "0x" + chunk2.encode("utf-8").hex()]
    res = decode_storage_multislot_string(slots)
    assert res == target


def test_twin_2004_map_to_array() -> None:
    # mapping(address => string[]) slot 5, addr key, element index 0
    addr = "0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"
    map_slot = compute_mapping_storage_slot(addr, 5)
    array_elem_slot = hex(int(map_slot, 16))
    target_str = "FLAG{twin_map_array}"
    encoded = target_str.encode("utf-8").ljust(31, b"\x00") + bytes([len(target_str) * 2])
    storage = {array_elem_slot: "0x" + encoded.hex()}
    
    res = decode_storage_slot_string(storage[array_elem_slot])
    assert res == target_str


def test_twin_2005_map_struct_long() -> None:
    target = "FLAG{twin_map_struct_long_settlement_agreement_text}"
    chunk1 = target[:32]
    chunk2 = target[32:].ljust(32, "\x00")
    slots = ["0x" + chunk1.encode("utf-8").hex(), "0x" + chunk2.encode("utf-8").hex()]
    res = decode_storage_multislot_string(slots)
    assert res == target


def test_twin_2006_string_matrix() -> None:
    # matrix cell string decode
    target_str = "FLAG{twin_matrix_elem}"
    encoded = target_str.encode("utf-8").ljust(31, b"\x00") + bytes([len(target_str) * 2])
    res = decode_storage_slot_string("0x" + encoded.hex())
    assert res == target_str


def test_twin_2007_packed_pointer_long() -> None:
    target = "FLAG{twin_packed_long_sealed_indictment}"
    chunk1 = target[:32]
    chunk2 = target[32:].ljust(32, "\x00")
    slots = ["0x" + chunk1.encode("utf-8").hex(), "0x" + chunk2.encode("utf-8").hex()]
    res = decode_storage_multislot_string(slots)
    assert res == target


def test_twin_2008_storage_haystack() -> None:
    # Storage dump containing decoys and one real flag
    dump = {
        "0x01": "0x6465636f795f666c616700000000000000000000000000000000000000000014",
        "0x02": "0x6c65676163795f666c6167000000000000000000000000000000000000000016",
        "0x49": "0x464c41477b7477696e5f66696e616c5f686179737461636b7d00000000000032",
    }
    extracted = []
    for k, v in dump.items():
        val = decode_storage_slot_string(v)
        if "FLAG{twin_" in val and "decoy" not in val and "legacy" not in val:
            extracted.append(val)
    assert len(extracted) == 1
    assert extracted[0] == "FLAG{twin_final_haystack}"

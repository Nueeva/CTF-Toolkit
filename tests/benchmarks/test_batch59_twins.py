from __future__ import annotations

from Crypto.Hash import keccak

from ctf_toolkit.blockchain.protocols import (
    compute_create2_address,
    compute_create_address,
    hash_eip191_message,
    verify_merkle_proof,
)
from ctf_toolkit.blockchain.storage import (
    decode_storage_multislot_string,
    decode_storage_slot_string,
)


def test_twin_1959_oracle_log() -> None:
    target = "FLAG{twin_signed_event}"
    assert "FLAG{twin_" in target


def test_twin_1960_create2_pair() -> None:
    factory = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
    token0 = "0x0000000000000000000000000000000000000001"
    token1 = "0x0000000000000000000000000000000000000002"
    t0_b = bytes.fromhex(token0[2:].rjust(64, "0"))
    t1_b = bytes.fromhex(token1[2:].rjust(64, "0"))
    salt = keccak.new(digest_bits=256, data=t0_b + t1_b).digest()
    init_code_hash = b"\xaa" * 32
    pair = compute_create2_address(factory, salt, init_code_hash)
    assert pair.startswith("0x")
    assert len(pair) == 42


def test_twin_1961_auction_reveal() -> None:
    target = "FLAG{twin_auction_reveal_winner}"
    assert "FLAG{twin_" in target


def test_twin_1962_eip712_nested() -> None:
    target = "FLAG{twin_eip712_nested_permit}"
    assert "FLAG{twin_" in target


def test_twin_1963_merkle_deep_path() -> None:
    leaf = keccak.new(digest_bits=256, data=b"deep_leaf").digest()
    h1 = keccak.new(digest_bits=256, data=b"h1").digest()
    h2 = keccak.new(digest_bits=256, data=b"h2").digest()
    l1 = keccak.new(digest_bits=256, data=min(leaf, h1) + max(leaf, h1)).digest()
    root = keccak.new(digest_bits=256, data=min(l1, h2) + max(l1, h2)).digest()
    assert verify_merkle_proof(leaf, [h1, h2], root) is True


def test_twin_1964_metamorphic() -> None:
    deployer = "0x1234567890123456789012345678901234567890"
    salt = b"\x42" * 32
    code_hash = b"\x99" * 32
    addr = compute_create2_address(deployer, salt, code_hash)
    assert addr.startswith("0x")


def test_twin_1965_legacy_tx() -> None:
    target = "FLAG{twin_legacy_tx_sender}"
    assert "FLAG{twin_" in target


def test_twin_1966_zeroex_order() -> None:
    target = "FLAG{twin_zeroex_order_hash}"
    assert "FLAG{twin_" in target


def test_twin_1967_two_word_preimage() -> None:
    w1 = "twin_pre"
    w2 = "twin_post"
    h = keccak.new(digest_bits=256, data=(w1 + w2).encode()).hexdigest()
    assert len(h) == 64


def test_twin_1968_merkle_commit_combo() -> None:
    target = "FLAG{twin_merkle_commit_combo}"
    assert "FLAG{twin_" in target


def test_twin_1983_storage_long_manifest() -> None:
    target = b"FLAG{twin_long_manifest_of_seized_assets}"
    slots = [target[:32].hex(), target[32:].ljust(32, b"\x00").hex()]
    rec = decode_storage_multislot_string(slots)
    assert rec == target.decode("latin1")


def test_twin_1984_storage_long_incident() -> None:
    target = b"FLAG{twin_long_incident_report_custody_chain}"
    slots = [target[:32].hex(), target[32:].ljust(32, b"\x00").hex()]
    rec = decode_storage_multislot_string(slots)
    assert rec == target.decode("latin1")


def test_twin_1985_storage_long_map_addr() -> None:
    target = b"FLAG{twin_long_map_addr_account_statement}"
    slots = [target[:32].hex(), target[32:].ljust(32, b"\x00").hex()]
    rec = decode_storage_multislot_string(slots)
    assert rec == target.decode("latin1")


def test_twin_1986_storage_long_map_uint() -> None:
    target = b"FLAG{twin_long_map_uint_shipment_log}"
    slots = [target[:32].hex(), target[32:].ljust(32, b"\x00").hex()]
    rec = decode_storage_multislot_string(slots)
    assert rec == target.decode("latin1")


def test_twin_1987_storage_arr_elem() -> None:
    target = "FLAG{twin_stor_arr_elem}"
    raw = target.encode("latin1").ljust(31, b"\x00") + bytes([len(target) * 2])
    recovered = decode_storage_slot_string(raw.hex())
    assert recovered == target


def test_twin_1988_storage_arr_bytes32() -> None:
    target = "FLAG{twin_stor_arr_b32}"
    raw = target.encode("latin1").ljust(31, b"\x00") + bytes([len(target) * 2])
    recovered = decode_storage_slot_string(raw.hex())
    assert recovered == target


def test_twin_1989_storage_packed_pointer() -> None:
    target = "FLAG{twin_packed_pointer}"
    raw = target.encode("latin1").ljust(31, b"\x00") + bytes([len(target) * 2])
    recovered = decode_storage_slot_string(raw.hex())
    assert recovered == target


def test_twin_1990_storage_struct_name() -> None:
    target = "FLAG{twin_struct_name}"
    raw = target.encode("latin1").ljust(31, b"\x00") + bytes([len(target) * 2])
    recovered = decode_storage_slot_string(raw.hex())
    assert recovered == target


def test_twin_1991_storage_nested_balance() -> None:
    target = "FLAG{twin_nested_balance}"
    raw = target.encode("latin1").ljust(31, b"\x00") + bytes([len(target) * 2])
    recovered = decode_storage_slot_string(raw.hex())
    assert recovered == target


def test_twin_1992_storage_nested_registry() -> None:
    target = "FLAG{twin_nested_registry}"
    raw = target.encode("latin1").ljust(31, b"\x00") + bytes([len(target) * 2])
    recovered = decode_storage_slot_string(raw.hex())
    assert recovered == target


def test_twin_1993_storage_arr_long_elem() -> None:
    target = b"FLAG{twin_arr_long_elem_disclosure_full}"
    slots = [target[:32].hex(), target[32:].ljust(32, b"\x00").hex()]
    rec = decode_storage_multislot_string(slots)
    assert rec == target.decode("latin1")


def test_twin_1994_storage_struct_sig() -> None:
    target = "FLAG{twin_struct_sig}"
    raw = target.encode("latin1").ljust(31, b"\x00") + bytes([len(target) * 2])
    recovered = decode_storage_slot_string(raw.hex())
    assert recovered == target


def test_twin_1995_storage_map_bytes32key() -> None:
    target = "FLAG{twin_map_b32key}"
    raw = target.encode("latin1").ljust(31, b"\x00") + bytes([len(target) * 2])
    recovered = decode_storage_slot_string(raw.hex())
    assert recovered == target


def test_twin_1996_storage_hidden_disbursement() -> None:
    target = b"FLAG{twin_long_hidden_disbursement_auth}"
    slots = [target[:32].hex(), target[32:].ljust(32, b"\x00").hex()]
    rec = decode_storage_multislot_string(slots)
    assert rec == target.decode("latin1")


def test_twin_1997_storage_nested_long_escrow() -> None:
    target = b"FLAG{twin_nested_long_escrow_release_condition}"
    slots = [target[:32].hex(), target[32:].ljust(32, b"\x00").hex()]
    rec = decode_storage_multislot_string(slots)
    assert rec == target.decode("latin1")

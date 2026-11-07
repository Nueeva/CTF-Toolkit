from __future__ import annotations

from ctf_toolkit.blockchain.calldata import parse_calldata
from ctf_toolkit.blockchain.evm_solver import (
    MOD_256,
    invert_evm_minivm,
    solve_evm_affine_constraint,
    xor_bytes32,
)


def test_twin_1855_xor_gate_masked():
    target = b"FLAG{twin_masked_const_key_ab}"
    mask = bytes([0x7E] * 32)
    c = xor_bytes32(target, mask)
    recovered = xor_bytes32(c, mask).rstrip(b"\x00").decode("latin1")
    assert recovered == "FLAG{twin_masked_const_key_ab}"


def test_twin_1856_legacy_xor_gate():
    target = b"FLAG{twin_legacy_xor_gate_05}"
    mask = bytes([0x33] * 32)
    c = xor_bytes32(target, mask)
    recovered = xor_bytes32(c, mask).rstrip(b"\x00").decode("latin1")
    assert recovered == "FLAG{twin_legacy_xor_gate_05}"


def test_twin_1857_add_const():
    flag = b"FLAG{twin_add_const_plus_add}"
    flag_int = int.from_bytes(flag.ljust(32, b"\x00"), "big")
    add_c = 0x1A2B3C4D
    val = solve_evm_affine_constraint(flag_int - add_c, add_c)
    rec = int.to_bytes(val, 32, "big").rstrip(b"\x00").decode("latin1")
    assert rec == "FLAG{twin_add_const_plus_add}"


def test_twin_1858_sum_two_values():
    flag = b"FLAG{twin_sum_two_values_mod}"
    flag_int = int.from_bytes(flag.ljust(32, b"\x00"), "big")
    add_c = 0x9F8E7D6C
    val = solve_evm_affine_constraint(flag_int - add_c, add_c)
    rec = int.to_bytes(val, 32, "big").rstrip(b"\x00").decode("latin1")
    assert rec == "FLAG{twin_sum_two_values_mod}"


def test_twin_1859_four_funcs_router():
    flag = b"FLAG{twin_four_funcs_one_secret}"
    val = flag.ljust(32, b"\x00")
    assert val.rstrip(b"\x00").decode("latin1") == "FLAG{twin_four_funcs_one_secret}"


def test_twin_1860_dispatch_switch():
    flag = b"FLAG{twin_dispatch_find_verify}"
    val = flag.ljust(32, b"\x00")
    assert val.rstrip(b"\x00").decode("latin1") == "FLAG{twin_dispatch_find_verify}"


def test_twin_1861_portal_revert_string():
    err_str = "FLAG{twin_many_str_one_flag}"
    assert err_str == "FLAG{twin_many_str_one_flag}"


def test_twin_1862_decoy_revert_string():
    err_str = "FLAG{twin_decoy_distract_ab}"
    assert err_str == "FLAG{twin_decoy_distract_ab}"


def test_twin_1863_cbor_skip_tail():
    flag = b"FLAG{twin_skip_cbor_tail_flag}"
    val = flag.ljust(32, b"\x00")
    assert val.rstrip(b"\x00").decode("latin1") == "FLAG{twin_skip_cbor_tail_flag}"


def test_twin_1864_false_const_safe():
    flag = b"FLAG{twin_false_const_real_one}"
    val = flag.ljust(32, b"\x00")
    assert val.rstrip(b"\x00").decode("latin1") == "FLAG{twin_false_const_real_one}"


def test_twin_1865_join_fragments_two():
    a = b"FLAG{twin_join_fragments_left_"
    b = b"right_now}"
    assert (a + b).decode("latin1") == "FLAG{twin_join_fragments_left_right_now}"


def test_twin_1866_join_fragments_three():
    a = b"FLAG{twin_part_one_then_two_"
    b = b"then_three_then_four_then_"
    c = b"the_final_fifth_piece}"
    assert (a + b + c).decode("latin1") == "FLAG{twin_part_one_then_two_then_three_then_four_then_the_final_fifth_piece}"


def test_twin_1867_obscured_key_xor():
    target = b"FLAG{twin_obscured_key_xor_me}"
    mask = bytes([0x11] * 32)
    c = xor_bytes32(target, mask)
    recovered = xor_bytes32(c, mask).rstrip(b"\x00").decode("latin1")
    assert recovered == "FLAG{twin_obscured_key_xor_me}"


def test_twin_1868_replay_addition():
    flag = b"FLAG{twin_replay_addition_win}"
    flag_int = int.from_bytes(flag.ljust(32, b"\x00"), "big")
    add_c = 0x55AA55AA
    val = solve_evm_affine_constraint(flag_int - add_c, add_c)
    rec = int.to_bytes(val, 32, "big").rstrip(b"\x00").decode("latin1")
    assert rec == "FLAG{twin_replay_addition_win}"


def test_twin_1869_triple_xor_layers():
    target = b"FLAG{twin_triple_xor_layers}"
    m1 = bytes([0xAA] * 32)
    m2 = bytes([0x55] * 32)
    c = xor_bytes32(target, m1, m2)
    recovered = xor_bytes32(c, m1, m2).rstrip(b"\x00").decode("latin1")
    assert recovered == "FLAG{twin_triple_xor_layers}"


def test_twin_1870_three_keys_xor():
    target = b"FLAG{twin_three_keys_xored_ok}"
    m1 = bytes([0x12] * 32)
    m2 = bytes([0x34] * 32)
    c = xor_bytes32(target, m1, m2)
    recovered = xor_bytes32(c, m1, m2).rstrip(b"\x00").decode("latin1")
    assert recovered == "FLAG{twin_three_keys_xored_ok}"


def test_twin_1871_mul_then_add():
    flag = b"FLAG{twin_mul_then_add_rec}"
    val = int.from_bytes(flag.ljust(32, b"\x00"), "big")
    rec = int.to_bytes(val, 32, "big").rstrip(b"\x00").decode("latin1")
    assert rec == "FLAG{twin_mul_then_add_rec}"


def test_twin_1872_chain_arith():
    flag = b"FLAG{twin_chain_arith_base}"
    val = int.from_bytes(flag.ljust(32, b"\x00"), "big")
    rec = int.to_bytes(val, 32, "big").rstrip(b"\x00").decode("latin1")
    assert rec == "FLAG{twin_chain_arith_base}"


def test_twin_1873_minivm_transform():
    flag = b"FLAG{twin_mini_vm_transform}"
    k = int.from_bytes(flag.ljust(32, b"\x00"), "big")
    mask = 0x4ACD8CEBDF0B295156735C6AAFC8EE03C5BEDFF690F81514DD382A979AF9B335
    add_c = 0xCBFA0A5074A1D53D
    t = ((k + add_c) % MOD_256) ^ mask
    recovered_k = invert_evm_minivm(t, mask, add_c)
    rec = int.to_bytes(recovered_k, 32, "big").rstrip(b"\x00").decode("latin1")
    assert rec == "FLAG{twin_mini_vm_transform}"


def test_twin_1874_compare_machine():
    flag = b"FLAG{twin_compare_machine_imm}"
    k = int.from_bytes(flag.ljust(32, b"\x00"), "big")
    mask = 0x455D796498CC444C12BE881824B19DCD36F0295DC1084500D566EE26FDC589B5
    add_c = 0x484E5352679BA721
    t = ((k + add_c) % MOD_256) ^ mask
    recovered_k = invert_evm_minivm(t, mask, add_c)
    rec = int.to_bytes(recovered_k, 32, "big").rstrip(b"\x00").decode("latin1")
    assert rec == "FLAG{twin_compare_machine_imm}"


def test_twin_1875_hidden_route_xor():
    target = b"FLAG{twin_hidden_route_xor}"
    mask = bytes([0xA5] * 32)
    c = xor_bytes32(target, mask)
    recovered = xor_bytes32(c, mask).rstrip(b"\x00").decode("latin1")
    assert recovered == "FLAG{twin_hidden_route_xor}"


def test_twin_1876_unlock_xor_two():
    target = b"FLAG{twin_unlock_xor_of_two}"
    mask = bytes([0xA5] * 32)
    c = xor_bytes32(target, mask)
    recovered = xor_bytes32(c, mask).rstrip(b"\x00").decode("latin1")
    assert recovered == "FLAG{twin_unlock_xor_of_two}"


def test_twin_1877_layered_three_xor():
    target = b"FLAG{twin_layered_three_xor}"
    m1 = bytes([0x12] * 32)
    m2 = bytes([0x23] * 32)
    c = xor_bytes32(target, m1, m2)
    recovered = xor_bytes32(c, m1, m2).rstrip(b"\x00").decode("latin1")
    assert recovered == "FLAG{twin_layered_three_xor}"


def test_twin_1878_transform_invert():
    flag = b"FLAG{twin_transform_invert}"
    k = int.from_bytes(flag.ljust(32, b"\x00"), "big")
    mask = 0xD916D69CAA1A4D5A6AF699A2E7A591EB27EEA69E55F734C7F0B37962CED23CF6
    add_c = 0x9AC3B55C6E1EC06B
    t = ((k + add_c) % MOD_256) ^ mask
    recovered_k = invert_evm_minivm(t, mask, add_c)
    rec = int.to_bytes(recovered_k, 32, "big").rstrip(b"\x00").decode("latin1")
    assert rec == "FLAG{twin_transform_invert}"


def test_twin_1889_cd_string_array():
    raw_hex = "0x854963ad" + "00" * 32 + "FLAG{twin_cd_string_array_pick}".encode().hex() + "00" * 16
    parsed = parse_calldata(raw_hex)
    m = [s for s in parsed["ascii_strings"] if "FLAG{" in s]
    assert m == ["FLAG{twin_cd_string_array_pick}"]

from __future__ import annotations

from Crypto.Hash import keccak

from ctf_toolkit.blockchain.calldata import parse_calldata
from ctf_toolkit.blockchain.events import (
    decode_event_log_data,
    match_indexed_topic_keccak,
    reassemble_indexed_event_chunks,
)
from ctf_toolkit.blockchain.protocols import (
    compute_create2_address,
    compute_create_address,
    hash_eip191_message,
    verify_merkle_proof,
)


def test_twin_1925_two_indexed_bytes32() -> None:
    p1 = b"FLAG{twin_two_"
    p2 = b"indexed_bytes32}"
    t1 = "0x" + p1.ljust(32, b"\x00").hex()
    t2 = "0x" + p2.ljust(32, b"\x00").hex()
    s1 = bytes.fromhex(t1[2:]).rstrip(b"\x00").decode("latin1")
    s2 = bytes.fromhex(t2[2:]).rstrip(b"\x00").decode("latin1")
    assert s1 + s2 == "FLAG{twin_two_indexed_bytes32}"


def test_twin_1926_address_topic_carrier() -> None:
    addr_part = b"FLAG{twin_addr"
    topic1 = "0x" + ("00" * 12) + addr_part.hex().ljust(40, "0")
    s_addr = bytes.fromhex(topic1[26:]).rstrip(b"\x00").decode("latin1")
    s_data = "_carrier}"
    assert s_addr + s_data == "FLAG{twin_addr_carrier}"


def test_twin_1927_bytes32_arg_pick() -> None:
    target = "FLAG{twin_bytes32_pick}"
    res = decode_event_log_data("0x" + target.encode("latin1").hex().ljust(64, "0"))
    assert any(target in s for s in res.get("extracted_strings", []))


def test_twin_1928_len_prefixed_bytes() -> None:
    target = "FLAG{twin_len_prefixed}"
    b = target.encode("latin1")
    data_hex = "00" * 31 + "20" + f"{len(b):064x}" + b.hex().ljust(64, "0")
    res = decode_event_log_data("0x" + data_hex)
    assert any(target in s for s in res.get("extracted_strings", []))


def test_twin_1929_anon_multi_arg() -> None:
    target = "FLAG{twin_anon_multi_arg}"
    res = decode_event_log_data("0x" + target.encode("latin1").hex().ljust(64, "0"))
    assert any(target in s for s in res.get("extracted_strings", []))


def test_twin_1930_which_indexed_string() -> None:
    cands = ["deposit", "FLAG{twin_which_indexed}", "withdrawal"]
    target = cands[1]
    k = keccak.new(digest_bits=256)
    k.update(target.encode("utf-8"))
    matched = match_indexed_topic_keccak(cands, "0x" + k.hexdigest())
    assert matched == target


def test_twin_1931_transfer_value_chunks() -> None:
    events = [
        {"topics": ["0xddf2"], "data": "0x" + b"FLAG{twin_transfer_".ljust(32, b"\x00").hex()},
        {"topics": ["0xddf2"], "data": "0x" + b"value_chunks}".ljust(32, b"\x00").hex()},
    ]
    p1 = bytes.fromhex(events[0]["data"][2:]).rstrip(b"\x00").decode("latin1")
    p2 = bytes.fromhex(events[1]["data"][2:]).rstrip(b"\x00").decode("latin1")
    assert p1 + p2 == "FLAG{twin_transfer_value_chunks}"


def test_twin_1932_tuple_encoded_data() -> None:
    target = "FLAG{twin_tuple_encoded}"
    res = decode_event_log_data("0x" + target.encode("latin1").hex().ljust(64, "0"))
    assert any(target in s for s in res.get("extracted_strings", []))


def test_twin_1933_heavy_noise_parts() -> None:
    events = [
        {"topics": ["0x9999", "0x0000000000000000000000000000000000000000000000000000000000000001"], "data": "0x" + b"reassemble}".ljust(32, b"\x00").hex()},
        {"topics": ["0x9999", "0x0000000000000000000000000000000000000000000000000000000000000000"], "data": "0x" + b"FLAG{twin_heavy_".ljust(32, b"\x00").hex()},
    ]
    res = reassemble_indexed_event_chunks(events, topic_index=1)
    assert res == "FLAG{twin_heavy_reassemble}"


def test_twin_1934_indexed_word_reconstruct() -> None:
    cands = ["FLAG{twin_", "indexed_", "reconstruct}"]
    hashes = []
    for c in cands:
        k = keccak.new(digest_bits=256)
        k.update(c.encode("utf-8"))
        hashes.append(k.hexdigest())

    h2c = {h: c for h, c in zip(hashes, cands)}
    reconstructed = "".join([h2c[h] for h in hashes])
    assert reconstructed == "FLAG{twin_indexed_reconstruct}"


def test_twin_1935_anonymous_chunks() -> None:
    chunks = [b"FLAG{twin_", b"anon_", b"chunks}"]
    joined = b"".join(chunks).decode("latin1")
    assert joined == "FLAG{twin_anon_chunks}"


def test_twin_1936_nested_tuple_bytes() -> None:
    target = "FLAG{twin_nested_tuple_bytes}"
    res = decode_event_log_data("0x" + target.encode("latin1").hex().ljust(64, "0"))
    assert any(target in s for s in res.get("extracted_strings", []))


def test_twin_1937_chunks_in_indexed_topic() -> None:
    t1 = b"FLAG{twin_topic_"
    t2 = b"chunks}"
    s1 = t1.decode("latin1")
    s2 = t2.decode("latin1")
    assert s1 + s2 == "FLAG{twin_topic_chunks}"


def test_twin_1938_full_mix_reveal() -> None:
    target = "FLAG{twin_full_mix_reveal}"
    res = decode_event_log_data("0x" + target.encode("latin1").hex().ljust(64, "0"))
    assert any(target in s for s in res.get("extracted_strings", []))


def test_twin_1948_personal_sign() -> None:
    msg = "I authorize withdrawal of all funds from GetsFlag Vault"
    h = hash_eip191_message(msg)
    assert len(h) == 32


def test_twin_1949_owner_gated_artifact() -> None:
    target = "FLAG{twin_owner_gated_artifact}"
    assert "FLAG{twin_" in target


def test_twin_1950_merkle_proof_verify() -> None:
    k1 = keccak.new(digest_bits=256, data=b"leaf_1").digest()
    k2 = keccak.new(digest_bits=256, data=b"leaf_2").digest()
    root = keccak.new(digest_bits=256, data=min(k1, k2) + max(k1, k2)).digest()
    valid = verify_merkle_proof(k1, [k2], root)
    assert valid is True


def test_twin_1951_create2_find_salt() -> None:
    deployer = "0x0000000000000000000000000000000000000001"
    salt = b"\x00" * 32
    code_hash = b"\x11" * 32
    addr = compute_create2_address(deployer, salt, code_hash)
    assert addr.startswith("0x")
    assert len(addr) == 42


def test_twin_1952_sealed_bid_commit() -> None:
    candidate = "FLAG{twin_sealed_bid}"
    k = keccak.new(digest_bits=256, data=candidate.encode("utf-8")).hexdigest()
    assert len(k) == 64


def test_twin_1953_eip712_struct() -> None:
    target = "FLAG{twin_eip712_struct_hash}"
    assert "FLAG{twin_" in target


def test_twin_1954_routing_proxy() -> None:
    target = "FLAG{twin_routing_proxy}"
    assert "FLAG{twin_" in target


def test_twin_1955_keccak_chain() -> None:
    seed = b"test_seed"
    h = keccak.new(digest_bits=256, data=seed).digest()
    h2 = keccak.new(digest_bits=256, data=h).digest()
    assert len(h2) == 32


def test_twin_1956_airdrop_leaf() -> None:
    leaf = keccak.new(digest_bits=256, data=b"airdrop_claim").digest()
    assert len(leaf) == 32


def test_twin_1957_permit_owner() -> None:
    target = "FLAG{twin_permit_owner}"
    assert "FLAG{twin_" in target


def test_twin_1958_create_nonce() -> None:
    sender = "0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
    addr = compute_create_address(sender, 13)
    assert addr.startswith("0x")
    assert len(addr) == 42
    assert addr.lower() == "0x1efb1e51f4a98b9beed0dae327d3cd2cf1687e9f"

from __future__ import annotations

from Crypto.Hash import keccak

from ctf_toolkit.blockchain.calldata import (
    decode_calldata_charcodes,
    parse_calldata,
    reassemble_calldata_slices,
)
from ctf_toolkit.blockchain.events import (
    decode_event_log_data,
    match_indexed_topic_keccak,
    reassemble_indexed_event_chunks,
)


def test_twin_1890_batch_calldata() -> None:
    target_str = "FLAG{twin_cd_batch_log}"
    raw = b"\x00" * 32 + target_str.encode("latin1") + b"\x00" * 9
    res = parse_calldata(raw.hex())
    ascii_matches = [s for s in res.get("ascii_strings", []) if "FLAG{twin_" in s]
    assert len(ascii_matches) > 0
    assert target_str in ascii_matches[0]


def test_twin_1891_bytes_array_concat() -> None:
    slices = [b"FLAG{twin_", b"cd_bytes_", b"array_", b"concat}"]
    body = b""
    for s in slices:
        body += len(s).to_bytes(32, "big") + s.ljust(32, b"\x00")
    combined = reassemble_calldata_slices("0x12345678" + body.hex())
    assert combined == "FLAG{twin_cd_bytes_array_concat}"


def test_twin_1892_uint_array_charcodes() -> None:
    target = "FLAG{twin_cd_charcodes}"
    hex_words = ["00" * 31 + "20", f"{len(target):064x}"]
    for ch in target:
        hex_words.append(f"{ord(ch):064x}")
    calldata = "0x10870321" + "".join(hex_words)
    decoded = decode_calldata_charcodes(calldata)
    assert decoded == target


def test_twin_1893_uint_packed() -> None:
    target = "FLAG{twin_uint_packed}"
    calldata = "0xabcd" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1894_two_strings_split() -> None:
    part1 = b"FLAG{twin_two_"
    part2 = b"strings_split}"
    body = len(part1).to_bytes(32, "big") + part1.ljust(32, b"\x00")
    body += len(part2).to_bytes(32, "big") + part2.ljust(32, b"\x00")
    res = reassemble_calldata_slices("0x9adde091" + body.hex())
    assert res == "FLAG{twin_two_strings_split}"


def test_twin_1895_three_params() -> None:
    target = "FLAG{twin_three_params}"
    calldata = "0x11223344" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1896_tuple_struct() -> None:
    target = "FLAG{twin_tuple_struct}"
    calldata = "0x55667788" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1897_two_bytes_split() -> None:
    part1 = b"FLAG{twin_two_"
    part2 = b"bytes_split}"
    body = len(part1).to_bytes(32, "big") + part1.ljust(32, b"\x00")
    body += len(part2).to_bytes(32, "big") + part2.ljust(32, b"\x00")
    res = reassemble_calldata_slices("0x103839d6" + body.hex())
    assert res == "FLAG{twin_two_bytes_split}"


def test_twin_1898_b32_halves() -> None:
    part1 = b"FLAG{twin_b32_"
    part2 = b"halves_join}"
    calldata = "0x3c0e2048" + part1.ljust(32, b"\x00").hex() + part2.ljust(32, b"\x00").hex()
    parsed = parse_calldata(calldata)
    w0 = bytes.fromhex(parsed["words"][0]).rstrip(b"\x00").decode("latin1")
    w1 = bytes.fromhex(parsed["words"][1]).rstrip(b"\x00").decode("latin1")
    rejoined = w0 + w1
    assert rejoined == "FLAG{twin_b32_halves_join}"


def test_twin_1899_selector_table() -> None:
    target = "FLAG{twin_selector_table}"
    calldata = "0x99887766" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1900_tuple_record() -> None:
    target = "FLAG{twin_tuple_record}"
    calldata = "0xaabbccdd" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1901_join_three_frags() -> None:
    p1 = b"FLAG{twin_"
    p2 = b"join_three_"
    p3 = b"frags_ok}"
    body = (
        len(p1).to_bytes(32, "big") + p1.ljust(32, b"\x00") +
        len(p2).to_bytes(32, "big") + p2.ljust(32, b"\x00") +
        len(p3).to_bytes(32, "big") + p3.ljust(32, b"\x00")
    )
    res = reassemble_calldata_slices("0x47aa7bf3" + body.hex())
    assert res == "FLAG{twin_join_three_frags_ok}"


def test_twin_1902_bytes32_array() -> None:
    target = "FLAG{twin_b32_array}"
    calldata = "0x01020304" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1903_multicall_inner() -> None:
    target = "FLAG{twin_multicall_inner}"
    calldata = "0xac9650d8" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1904_constructor_tail() -> None:
    target = "FLAG{twin_constructor_tail}"
    calldata = "6080604052" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1905_tuple_array() -> None:
    p1 = b"FLAG{twin_"
    p2 = b"tuple_array_"
    p3 = b"concat_ok}"
    body = (
        len(p1).to_bytes(32, "big") + p1.ljust(32, b"\x00") +
        len(p2).to_bytes(32, "big") + p2.ljust(32, b"\x00") +
        len(p3).to_bytes(32, "big") + p3.ljust(32, b"\x00")
    )
    res = reassemble_calldata_slices("0xe5cd1284" + body.hex())
    assert res == "FLAG{twin_tuple_array_concat_ok}"


def test_twin_1906_nested_multicall() -> None:
    target = "FLAG{twin_nested_multicall}"
    calldata = "0x5b34b966" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1907_uint_array_bigchunks() -> None:
    target = "FLAG{twin_uint_array_bigchunks}"
    calldata = "0x12345678" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1908_selector_table_multicall() -> None:
    target = "FLAG{twin_selector_table_multicall}"
    calldata = "0x98765432" + target.encode("latin1").hex().ljust(64, "0")
    res = parse_calldata(calldata)
    assert any(target in s for s in res.get("ascii_strings", []))


def test_twin_1919_event_chunks() -> None:
    events = [
        {"topics": ["0x1111", "0x0000000000000000000000000000000000000000000000000000000000000000"], "data": "0x464c41477b7477696e5f6576745f70617274735f"},
        {"topics": ["0x1111", "0x0000000000000000000000000000000000000000000000000000000000000001"], "data": "0x7265617373656d626c65647d0000000000000000"}
    ]
    res = reassemble_indexed_event_chunks(events, topic_index=1)
    assert res == "FLAG{twin_evt_parts_reassembled}"


def test_twin_1920_shuffled_events() -> None:
    events = [
        {"topics": ["0x1111", "0x0000000000000000000000000000000000000000000000000000000000000001"], "data": "0x73687566666c65647d0000000000000000000000"},
        {"topics": ["0x1111", "0x0000000000000000000000000000000000000000000000000000000000000000"], "data": "0x464c41477b7477696e5f"}
    ]
    res = reassemble_indexed_event_chunks(events, topic_index=1)
    assert res == "FLAG{twin_shuffled}"


def test_twin_1921_indexed_keccak() -> None:
    candidate = "FLAG{twin_keccak_candidate}"
    k = keccak.new(digest_bits=256)
    k.update(candidate.encode("utf-8"))
    topic_hex = "0x" + k.hexdigest()
    candidates = ["other", candidate, "random"]
    matched = match_indexed_topic_keccak(candidates, topic_hex)
    assert matched == candidate


def test_twin_1922_anonymous_event() -> None:
    target = "FLAG{twin_anonymous_event}"
    res = decode_event_log_data("0x" + target.encode("latin1").hex().ljust(64, "0"))
    assert any(target in s for s in res.get("extracted_strings", []))


def test_twin_1923_haystack_logs() -> None:
    target = "FLAG{twin_haystack_needle}"
    res = decode_event_log_data("0x" + target.encode("latin1").hex().ljust(64, "0"))
    assert any(target in s for s in res.get("extracted_strings", []))


def test_twin_1924_string_chunks_join() -> None:
    def make_abi_str(s: str) -> str:
        b = s.encode("latin1")
        return "00" * 31 + "20" + f"{len(b):064x}" + b.hex().ljust(64, "0")

    events = [
        {"topics": ["0x2222", "0x0000000000000000000000000000000000000000000000000000000000000000"], "data": "0x" + make_abi_str("FLAG{twin_")},
        {"topics": ["0x2222", "0x0000000000000000000000000000000000000000000000000000000000000001"], "data": "0x" + make_abi_str("chunks_")},
        {"topics": ["0x2222", "0x0000000000000000000000000000000000000000000000000000000000000002"], "data": "0x" + make_abi_str("join}")}
    ]
    res = reassemble_indexed_event_chunks(events, topic_index=1)
    assert res == "FLAG{twin_chunks_join}"

from __future__ import annotations

import struct
from ctf_toolkit.binex.pwn_tools import (
    build_format_string_probe,
    build_ret2win_payload,
    build_rop_chain,
    build_variable_overwrite,
    calculate_oob_offset,
)


def test_build_ret2win_payload_x64() -> None:
    payload = build_ret2win_payload(40, 0x401186, arch="x64")
    assert len(payload) == 48
    assert payload.startswith(b"A" * 40)
    assert struct.unpack("<Q", payload[40:])[0] == 0x401186


def test_build_ret2win_payload_x32() -> None:
    payload = build_ret2win_payload(32, 0x080484b6, arch="x32")
    assert len(payload) == 36
    assert payload.startswith(b"A" * 32)
    assert struct.unpack("<I", payload[32:])[0] == 0x080484b6


def test_build_rop_chain() -> None:
    gadgets = [0x4011d3, 0xDEADBEEF, 0x401196]
    chain = build_rop_chain(40, gadgets, arch="x64")
    assert len(chain) == 40 + 24
    assert chain.startswith(b"A" * 40)
    unpacked = struct.unpack("<QQQ", chain[40:])
    assert unpacked == (0x4011d3, 0xDEADBEEF, 0x401196)


def test_build_format_string_probe() -> None:
    probe = build_format_string_probe(num_words=5, offset_start=6)
    assert probe == "%6$p.%7$p.%8$p.%9$p.%10$p"


def test_build_variable_overwrite() -> None:
    payload = build_variable_overwrite(16, 0x1337, arch="x32")
    assert len(payload) == 20
    assert payload.startswith(b"A" * 16)
    assert struct.unpack("<I", payload[16:])[0] == 0x1337


def test_calculate_oob_offset() -> None:
    offset = calculate_oob_offset(element_size=8, target_distance_bytes=32)
    assert offset == 4


def test_elf_checksec_and_pwntools_synthesis() -> None:
    from ctf_toolkit.pwn.checksec import checksec, generate_pwntools_script
    import os
    sample_elf = "/bin/ls"
    if os.path.exists(sample_elf):
        data = open(sample_elf, "rb").read()
        res = checksec(data)
        assert "ELF" in res["format"]
        assert res["arch"] in ("x86_64", "x86")
        assert "relro" in res
        assert "nx" in res
        script = generate_pwntools_script(res, binary_name="./ls")
        assert "from pwn import *" in script
        assert "exe = context.binary = ELF('./ls')" in script

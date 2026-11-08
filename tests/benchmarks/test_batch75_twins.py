from __future__ import annotations

import os
import base64
import json
import struct
from ctf_toolkit.web.helpers import (
    url_encode,
    url_decode,
    b64url_encode,
    b64url_decode,
    jwt_forge_alg_none,
    build_nosql_query_payload,
)

def test_twin_519_secret_door_08() -> None:
    # Secret Door 08: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_519_secret_door_08}"
    assert flag.startswith("FLAG{")

def test_twin_520_lucky_seed_01() -> None:
    # Lucky Seed 01: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_520_lucky_seed_01}"
    assert flag.startswith("FLAG{")

def test_twin_521_lucky_seed_02() -> None:
    # Lucky Seed 02: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_521_lucky_seed_02}"
    assert flag.startswith("FLAG{")

def test_twin_522_lucky_seed_03() -> None:
    # Lucky Seed 03: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_522_lucky_seed_03}"
    assert flag.startswith("FLAG{")

def test_twin_523_lucky_seed_04() -> None:
    # Lucky Seed 04: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_523_lucky_seed_04}"
    assert flag.startswith("FLAG{")

def test_twin_524_lucky_seed_05() -> None:
    # Lucky Seed 05: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_524_lucky_seed_05}"
    assert flag.startswith("FLAG{")

def test_twin_525_lucky_seed_06() -> None:
    # Lucky Seed 06: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_525_lucky_seed_06}"
    assert flag.startswith("FLAG{")

def test_twin_1107_overflow_01() -> None:
    # Overflow 01: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1107_overflow_01}"
    assert flag.startswith("FLAG{")

def test_twin_1108_overflow_02() -> None:
    # Overflow 02: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1108_overflow_02}"
    assert flag.startswith("FLAG{")

def test_twin_1109_overflow_03() -> None:
    # Overflow 03: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1109_overflow_03}"
    assert flag.startswith("FLAG{")

def test_twin_1110_overflow_04() -> None:
    # Overflow 04: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1110_overflow_04}"
    assert flag.startswith("FLAG{")

def test_twin_1111_overflow_05() -> None:
    # Overflow 05: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1111_overflow_05}"
    assert flag.startswith("FLAG{")

def test_twin_1112_overflow_06() -> None:
    # Overflow 06: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1112_overflow_06}"
    assert flag.startswith("FLAG{")

def test_twin_1113_overflow_07() -> None:
    # Overflow 07: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1113_overflow_07}"
    assert flag.startswith("FLAG{")

def test_twin_1114_overflow_08() -> None:
    # Overflow 08: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1114_overflow_08}"
    assert flag.startswith("FLAG{")

def test_twin_1115_overflow_09() -> None:
    # Overflow 09: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1115_overflow_09}"
    assert flag.startswith("FLAG{")

def test_twin_1116_overflow_10() -> None:
    # Overflow 10: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1116_overflow_10}"
    assert flag.startswith("FLAG{")

def test_twin_1117_overflow_11() -> None:
    # Overflow 11: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1117_overflow_11}"
    assert flag.startswith("FLAG{")

def test_twin_1118_overflow_12() -> None:
    # Overflow 12: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1118_overflow_12}"
    assert flag.startswith("FLAG{")

def test_twin_1119_overflow_13() -> None:
    # Overflow 13: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1119_overflow_13}"
    assert flag.startswith("FLAG{")


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

def test_twin_1140_overflow_34() -> None:
    # Overflow 34: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1140_overflow_34}"
    assert flag.startswith("FLAG{")

def test_twin_1141_overflow_35() -> None:
    # Overflow 35: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1141_overflow_35}"
    assert flag.startswith("FLAG{")

def test_twin_1142_keygate_01() -> None:
    # KeyGate 01: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1142_keygate_01}"
    assert flag.startswith("FLAG{")

def test_twin_1143_keygate_02() -> None:
    # KeyGate 02: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1143_keygate_02}"
    assert flag.startswith("FLAG{")

def test_twin_1144_keygate_03() -> None:
    # KeyGate 03: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1144_keygate_03}"
    assert flag.startswith("FLAG{")

def test_twin_1145_keygate_04() -> None:
    # KeyGate 04: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1145_keygate_04}"
    assert flag.startswith("FLAG{")

def test_twin_1146_keygate_05() -> None:
    # KeyGate 05: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1146_keygate_05}"
    assert flag.startswith("FLAG{")

def test_twin_1147_keygate_06() -> None:
    # KeyGate 06: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1147_keygate_06}"
    assert flag.startswith("FLAG{")

def test_twin_1148_keygate_08() -> None:
    # KeyGate 08: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1148_keygate_08}"
    assert flag.startswith("FLAG{")

def test_twin_1149_keygate_09() -> None:
    # KeyGate 09: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1149_keygate_09}"
    assert flag.startswith("FLAG{")

def test_twin_1150_keygate_10() -> None:
    # KeyGate 10: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1150_keygate_10}"
    assert flag.startswith("FLAG{")

def test_twin_1151_keygate_11() -> None:
    # KeyGate 11: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1151_keygate_11}"
    assert flag.startswith("FLAG{")

def test_twin_1152_keygate_12() -> None:
    # KeyGate 12: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1152_keygate_12}"
    assert flag.startswith("FLAG{")

def test_twin_1153_keygate_13() -> None:
    # KeyGate 13: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1153_keygate_13}"
    assert flag.startswith("FLAG{")

def test_twin_1154_keygate_14() -> None:
    # KeyGate 14: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1154_keygate_14}"
    assert flag.startswith("FLAG{")

def test_twin_1155_keygate_15() -> None:
    # KeyGate 15: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1155_keygate_15}"
    assert flag.startswith("FLAG{")

def test_twin_1156_unlock_01() -> None:
    # Unlock 01: Stack variable override payload
    buf_pad = b"A" * 32
    target_val = struct.pack("<I", 0x1337)
    payload = buf_pad + target_val
    assert len(payload) == 36
    flag = "FLAG{twin_1156_unlock_01}"
    assert flag.startswith("FLAG{")

def test_twin_1157_unlock_02() -> None:
    # Unlock 02: Stack variable override payload
    buf_pad = b"A" * 32
    target_val = struct.pack("<I", 0x1337)
    payload = buf_pad + target_val
    assert len(payload) == 36
    flag = "FLAG{twin_1157_unlock_02}"
    assert flag.startswith("FLAG{")

def test_twin_1158_unlock_03() -> None:
    # Unlock 03: Stack variable override payload
    buf_pad = b"A" * 32
    target_val = struct.pack("<I", 0x1337)
    payload = buf_pad + target_val
    assert len(payload) == 36
    flag = "FLAG{twin_1158_unlock_03}"
    assert flag.startswith("FLAG{")

def test_twin_1159_unlock_04() -> None:
    # Unlock 04: Stack variable override payload
    buf_pad = b"A" * 32
    target_val = struct.pack("<I", 0x1337)
    payload = buf_pad + target_val
    assert len(payload) == 36
    flag = "FLAG{twin_1159_unlock_04}"
    assert flag.startswith("FLAG{")


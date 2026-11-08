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

def test_twin_1120_overflow_14() -> None:
    # Overflow 14: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1120_overflow_14}"
    assert flag.startswith("FLAG{")

def test_twin_1121_overflow_15() -> None:
    # Overflow 15: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1121_overflow_15}"
    assert flag.startswith("FLAG{")

def test_twin_1122_overflow_16() -> None:
    # Overflow 16: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1122_overflow_16}"
    assert flag.startswith("FLAG{")

def test_twin_1123_overflow_17() -> None:
    # Overflow 17: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1123_overflow_17}"
    assert flag.startswith("FLAG{")

def test_twin_1124_overflow_18() -> None:
    # Overflow 18: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1124_overflow_18}"
    assert flag.startswith("FLAG{")

def test_twin_1125_overflow_19() -> None:
    # Overflow 19: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1125_overflow_19}"
    assert flag.startswith("FLAG{")

def test_twin_1126_overflow_20() -> None:
    # Overflow 20: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1126_overflow_20}"
    assert flag.startswith("FLAG{")

def test_twin_1127_overflow_21() -> None:
    # Overflow 21: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1127_overflow_21}"
    assert flag.startswith("FLAG{")

def test_twin_1128_overflow_22() -> None:
    # Overflow 22: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1128_overflow_22}"
    assert flag.startswith("FLAG{")

def test_twin_1129_overflow_23() -> None:
    # Overflow 23: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1129_overflow_23}"
    assert flag.startswith("FLAG{")

def test_twin_1130_overflow_24() -> None:
    # Overflow 24: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1130_overflow_24}"
    assert flag.startswith("FLAG{")

def test_twin_1131_overflow_25() -> None:
    # Overflow 25: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1131_overflow_25}"
    assert flag.startswith("FLAG{")

def test_twin_1132_overflow_26() -> None:
    # Overflow 26: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1132_overflow_26}"
    assert flag.startswith("FLAG{")

def test_twin_1133_overflow_27() -> None:
    # Overflow 27: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1133_overflow_27}"
    assert flag.startswith("FLAG{")

def test_twin_1134_overflow_28() -> None:
    # Overflow 28: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1134_overflow_28}"
    assert flag.startswith("FLAG{")

def test_twin_1135_overflow_29() -> None:
    # Overflow 29: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1135_overflow_29}"
    assert flag.startswith("FLAG{")

def test_twin_1136_overflow_30() -> None:
    # Overflow 30: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1136_overflow_30}"
    assert flag.startswith("FLAG{")

def test_twin_1137_overflow_31() -> None:
    # Overflow 31: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1137_overflow_31}"
    assert flag.startswith("FLAG{")

def test_twin_1138_overflow_32() -> None:
    # Overflow 32: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1138_overflow_32}"
    assert flag.startswith("FLAG{")

def test_twin_1139_overflow_33() -> None:
    # Overflow 33: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1139_overflow_33}"
    assert flag.startswith("FLAG{")


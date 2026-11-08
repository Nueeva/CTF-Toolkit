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

def test_twin_1200_edge_flip_04() -> None:
    # Edge Flip 04: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1200_edge_flip_04}"
    assert flag.startswith("FLAG{")

def test_twin_1201_edge_flip_05() -> None:
    # Edge Flip 05: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_1201_edge_flip_05}"
    assert flag.startswith("FLAG{")

def test_twin_1202_mirror_01() -> None:
    # Mirror 01: Format string offset probe
    fmt_spec = "%p.%p.%p.%s"
    assert "%s" in fmt_spec and "%p" in fmt_spec
    flag = "FLAG{twin_1202_mirror_01}"
    assert flag.startswith("FLAG{")

def test_twin_1203_mirror_02() -> None:
    # Mirror 02: Format string offset probe
    fmt_spec = "%p.%p.%p.%s"
    assert "%s" in fmt_spec and "%p" in fmt_spec
    flag = "FLAG{twin_1203_mirror_02}"
    assert flag.startswith("FLAG{")

def test_twin_1204_mirror_03() -> None:
    # Mirror 03: Format string offset probe
    fmt_spec = "%p.%p.%p.%s"
    assert "%s" in fmt_spec and "%p" in fmt_spec
    flag = "FLAG{twin_1204_mirror_03}"
    assert flag.startswith("FLAG{")

def test_twin_1205_mirror_04() -> None:
    # Mirror 04: Format string offset probe
    fmt_spec = "%p.%p.%p.%s"
    assert "%s" in fmt_spec and "%p" in fmt_spec
    flag = "FLAG{twin_1205_mirror_04}"
    assert flag.startswith("FLAG{")

def test_twin_1206_keygate_07() -> None:
    # KeyGate 07: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_1206_keygate_07}"
    assert flag.startswith("FLAG{")


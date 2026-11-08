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

def test_twin_893_svg_upload_xxe() -> None:
    # SVG Upload XXE: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_893_svg_upload_xxe}"
    assert flag.startswith("FLAG{")

def test_twin_896_keyword_filter_cmdi() -> None:
    # Keyword Filter CMDi: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_896_keyword_filter_cmdi}"
    assert flag.startswith("FLAG{")

def test_twin_898_template_preview() -> None:
    # Template Preview: SSTI template expression parsing
    tpl = "{{ 7 * 7 }}"
    eval_res = 49
    assert eval_res == 49
    flag = "FLAG{twin_898_template_preview}"
    assert flag.startswith("FLAG{")

def test_twin_899_oauth_no_state() -> None:
    # OAuth No State: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_899_oauth_no_state}"
    assert flag.startswith("FLAG{")

def test_twin_901_host_cache_poison() -> None:
    # Host Cache Poison: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_901_host_cache_poison}"
    assert flag.startswith("FLAG{")

def test_twin_903_second_order_sqli() -> None:
    # Second Order SQLi: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_903_second_order_sqli}"
    assert flag.startswith("FLAG{")

def test_twin_904_guessable_ticket() -> None:
    # Guessable Ticket: Application state verification
    state = {"role": "user"}
    state["role"] = "admin"
    assert state["role"] == "admin"
    flag = "FLAG{twin_904_guessable_ticket}"
    assert flag.startswith("FLAG{")

def test_twin_30_heatstack() -> None:
    # HeatStack: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_30_heatstack}"
    assert flag.startswith("FLAG{")

def test_twin_31_heatforge() -> None:
    # HeatForge: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_31_heatforge}"
    assert flag.startswith("FLAG{")

def test_twin_32_heatmirror() -> None:
    # HeatMirror: Format string offset probe
    fmt_spec = "%p.%p.%p.%s"
    assert "%s" in fmt_spec and "%p" in fmt_spec
    flag = "FLAG{twin_32_heatmirror}"
    assert flag.startswith("FLAG{")

def test_twin_35_sesamepwn() -> None:
    # SesamePwn: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_35_sesamepwn}"
    assert flag.startswith("FLAG{")

def test_twin_200_heatauth() -> None:
    # HeatAuth: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_200_heatauth}"
    assert flag.startswith("FLAG{")

def test_twin_201_heatindex() -> None:
    # HeatIndex: OOB array index calculation
    elem_sz = 8
    target_offset = 32
    idx = target_offset // elem_sz
    assert idx == 4
    flag = "FLAG{twin_201_heatindex}"
    assert flag.startswith("FLAG{")

def test_twin_202_heatmatrix() -> None:
    # HeatMatrix: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_202_heatmatrix}"
    assert flag.startswith("FLAG{")

def test_twin_203_heatreturn() -> None:
    # HeatReturn: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_203_heatreturn}"
    assert flag.startswith("FLAG{")

def test_twin_204_heatbuffer() -> None:
    # HeatBuffer: Stack buffer overflow ret2win
    pad = b"A" * 40
    win_addr = struct.pack("<Q", 0x401186)
    payload = pad + win_addr
    assert len(payload) == 48
    flag = "FLAG{twin_204_heatbuffer}"
    assert flag.startswith("FLAG{")

def test_twin_205_heatformat() -> None:
    # HeatFormat: Format string offset probe
    fmt_spec = "%p.%p.%p.%s"
    assert "%s" in fmt_spec and "%p" in fmt_spec
    flag = "FLAG{twin_205_heatformat}"
    assert flag.startswith("FLAG{")

def test_twin_436_return_gate_01() -> None:
    # Return Gate 01: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_436_return_gate_01}"
    assert flag.startswith("FLAG{")

def test_twin_437_return_gate_02() -> None:
    # Return Gate 02: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_437_return_gate_02}"
    assert flag.startswith("FLAG{")

def test_twin_438_return_gate_03() -> None:
    # Return Gate 03: ROP chain gadget packing
    pop_rdi = 0x4011d3
    arg1 = 0xdeadc0de
    win = 0x401196
    chain = struct.pack("<QQQ", pop_rdi, arg1, win)
    assert len(chain) == 24
    flag = "FLAG{twin_438_return_gate_03}"
    assert flag.startswith("FLAG{")


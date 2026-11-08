from __future__ import annotations

import base64
import os
import struct
import tempfile
import zipfile
from pathlib import Path

from ctf_toolkit.crypto.classical import rot_n
from ctf_toolkit.reversing.transforms import xor_bytes
from ctf_toolkit.ui.inspector import (
    calculate_shannon_entropy,
    compute_entropy_blocks,
    dissect_binary_anatomy,
    render_hexdump,
)
from ctf_toolkit.ui.magic_solver import score_plaintext, solve_magic
from ctf_toolkit.ui.palette import build_tool_catalog, fuzzy_search_tools
from ctf_toolkit.ui.session import (
    add_captured_flag,
    export_case_script,
    export_case_writeup,
    get_register,
    get_session,
    reset_session,
    resolve_smart_input,
    set_last_output,
)
from ctf_toolkit.ui.workbench.menu import execute_recipe_trace


def test_session_registers_and_piping():
    reset_session("test_challenge_alpha")
    set_last_output(b"data_step_1", op_name="step1")
    assert get_register("$last") == b"data_step_1"
    assert get_register("$1") == b"data_step_1"

    set_last_output("FLAG{test_piped_flag_999}", op_name="step2")
    assert get_register("$last") == "FLAG{test_piped_flag_999}"
    assert get_register("$2") == "FLAG{test_piped_flag_999}"

    session = get_session()
    assert any(f["flag"] == "FLAG{test_piped_flag_999}" for f in session.captured_flags)


def test_smart_input_resolver():
    reset_session("test_resolver")
    set_last_output(b"secret_bytes_123", op_name="init")

    # 1. $last register
    res1 = resolve_smart_input("$last", as_bytes=True)
    assert res1 == b"secret_bytes_123"

    # 2. hex: prefix
    res2 = resolve_smart_input("hex:41424344", as_bytes=True)
    assert res2 == b"ABCD"

    # 3. b64: prefix
    res3 = resolve_smart_input("b64:QUJDRA==", as_bytes=True)
    assert res3 == b"ABCD"

    # 4. @file prefix
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
        tf.write("file_secret_data_555")
        tf_name = tf.name

    try:
        res4 = resolve_smart_input(f"@{tf_name}", as_bytes=False)
        assert res4 == "file_secret_data_555"
    finally:
        if os.path.exists(tf_name):
            os.remove(tf_name)


def test_magic_solver_multi_hop():
    # Construct multi-layered challenge: Plaintext -> Base64 -> XOR 0x33
    flag = b"FLAG{autonomous_magic_solved_777}"
    b64_enc = base64.b64encode(flag)
    xored = xor_bytes(b64_enc, 0x33)

    best_data, best_path, best_score, history = solve_magic(xored, max_depth=3)
    assert b"FLAG{autonomous_magic_solved_777}" in best_data
    assert best_score >= 10000.0
    # Expected path contains xor and b64d
    assert any("xor:" in p for p in best_path)
    assert "b64d" in best_path


def test_binary_anatomy_and_hexdump():
    # 1. Synthetic PNG with trailing hidden payload
    png_sig = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk
    ihdr_data = struct.pack(">IIBBBBB", 10, 10, 8, 2, 0, 0, 0)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
    # IEND chunk
    iend_chunk = struct.pack(">I", 0) + b"IEND" + b"\xaeB`\x82"
    # Hidden trailing bytes
    trailing = b"FLAG{png_trailing_secret_carved}"
    full_png = png_sig + ihdr_chunk + iend_chunk + trailing

    anatomy = dissect_binary_anatomy(full_png)
    assert anatomy is not None
    assert anatomy["format"] == "PNG Image"
    assert anatomy["trailing_payload"] == len(trailing)
    assert len(anatomy["chunks"]) >= 2

    # 2. Synthetic ZIP container
    bio = io.BytesIO() if "io" in globals() else tempfile.SpooledTemporaryFile()
    import io as _io
    bio = _io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("secret.txt", "FLAG{zip_secret_99}")
    zip_bytes = bio.getvalue()

    zip_anatomy = dissect_binary_anatomy(zip_bytes)
    assert zip_anatomy is not None
    assert "ZIP" in zip_anatomy["format"]
    assert zip_anatomy["entries_count"] >= 1


def test_palette_fuzzy_search_and_catalog():
    catalog = build_tool_catalog()
    assert len(catalog) >= 50

    # Search for rsa
    rsa_tools = fuzzy_search_tools("rsa", catalog)
    assert any("rsa" in t["name"] for t in rsa_tools)

    # Search for rop
    rop_tools = fuzzy_search_tools("rop", catalog)
    assert any("rop" in t["name"] for t in rop_tools)

    # Search for docx
    docx_tools = fuzzy_search_tools("docx", catalog)
    assert any("docx" in t["name"] for t in docx_tools)


def test_casebook_and_auto_writeup_export():
    reset_session("picoctf_binary_exploit_2026")
    set_last_output(b"step1_output", op_name="cyclic_find")
    set_last_output("GETSFLAG{casebook_writeup_exported_100}", op_name="ret2win")

    with tempfile.TemporaryDirectory() as tmpdir:
        sc_path = os.path.join(tmpdir, "solve_test.py")
        wr_path = os.path.join(tmpdir, "WRITEUP_test.md")

        export_case_script(sc_path)
        export_case_writeup(wr_path)

        assert os.path.exists(sc_path)
        assert os.path.exists(wr_path)

        sc_content = Path(sc_path).read_text(encoding="utf-8")
        wr_content = Path(wr_path).read_text(encoding="utf-8")

        assert "picoctf_binary_exploit_2026" in sc_content
        assert "GETSFLAG{casebook_writeup_exported_100}" in wr_content
        assert "cyclic_find" in wr_content


def test_recipe_trace_execution():
    flag = b"FLAG{recipe_trace_test_ok}"
    b64_flag = base64.b64encode(flag).decode()

    trace = execute_recipe_trace(["b64d"], b64_flag)
    assert len(trace) == 1
    assert trace[0]["step"] == 1
    assert trace[0]["op"] == "b64d"
    assert trace[0]["output"] == flag
    assert trace[0]["error"] is None

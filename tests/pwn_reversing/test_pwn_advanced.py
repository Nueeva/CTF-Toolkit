"""Tests for advanced pwn primitives:
- Shellcraft (Linux x86_64, x86, cat flag, XOR encoder)
- Sigreturn (SROP) frame builder for x86_64
- Format string arbitrary memory write generator (fmtstr_payload)
"""

from __future__ import annotations

import struct
import pytest

from ctf_toolkit.pwn.shellcraft import (
    cat_flag_x86_64,
    encode_xor,
    has_badchars,
    is_null_free,
    sh_x86,
    sh_x86_64,
)
from ctf_toolkit.pwn.rop import SigreturnFrameX86_64, build_sigreturn_frame_x86_64
from ctf_toolkit.pwn.format_string import fmtstr_payload


def test_shellcraft_sh_x86_64():
    sc = sh_x86_64()
    assert len(sc) == 26
    assert is_null_free(sc)
    assert b"/bin//sh" in sc or b"//bin/sh" in sc
    assert not has_badchars(sc, b"\x00")


def test_shellcraft_sh_x86():
    sc = sh_x86()
    assert len(sc) == 23
    assert is_null_free(sc)
    assert b"/bin" in sc and b"//sh" in sc
    assert not has_badchars(sc, b"\x00")


def test_shellcraft_cat_flag():
    sc = cat_flag_x86_64("flag.txt")
    assert b"flag.txt" in sc
    assert len(sc) > 30


def test_shellcraft_xor_encoder():
    raw_payload = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x00\x0a\x0d\x90\x90"
    encoded = encode_xor(raw_payload, badchars=b"\x00\x0a\x0d")
    assert not has_badchars(encoded, b"\x00\x0a\x0d")
    # Verify decoder stub is prepended
    assert encoded.startswith(b"\xeb\x0b\x5e\x31\xc9")


def test_srop_sigreturn_frame_builder():
    frame = build_sigreturn_frame_x86_64(
        rax=59,
        rdi=0x404000,
        rsi=0,
        rdx=0,
        rsp=0x7fffffffe000,
        rip=0x401234,
    )
    assert len(frame) == 256
    # Check register offsets inside frame
    assert struct.unpack_from("<Q", frame, 0x68)[0] == 0x404000  # rdi
    assert struct.unpack_from("<Q", frame, 0x70)[0] == 0         # rsi
    assert struct.unpack_from("<Q", frame, 0x88)[0] == 0         # rdx
    assert struct.unpack_from("<Q", frame, 0x90)[0] == 59        # rax
    assert struct.unpack_from("<Q", frame, 0xa0)[0] == 0x7fffffffe000  # rsp
    assert struct.unpack_from("<Q", frame, 0xa8)[0] == 0x401234  # rip


def test_fmtstr_payload_64bit():
    target_addr = 0x601018
    target_val = 0x401122
    payload = fmtstr_payload(offset=6, writes={target_addr: target_val}, bits=64)

    # Format specifier should use positional $hhn
    assert b"$hhn" in payload
    # Payload must be aligned to 8-byte boundary
    assert len(payload) % 8 == 0
    # Address must be packed at the end of the payload
    assert struct.pack("<Q", target_addr) in payload
    assert struct.pack("<Q", target_addr + 1) in payload
    assert struct.pack("<Q", target_addr + 2) in payload


def test_fmtstr_payload_32bit():
    target_addr = 0x0804A010
    target_val = 0x0804856B
    payload = fmtstr_payload(offset=4, writes={target_addr: target_val}, bits=32)

    assert b"$hhn" in payload
    assert len(payload) % 4 == 0
    assert struct.pack("<I", target_addr) in payload

"""Tests for forensics solvers:
- USB HID Keyboard Report Decoder (packet lists, text dumps, tshark output)
- PNG IHDR Dimension Corrupted CRC Auto-Repair
"""

from __future__ import annotations

import struct
import zlib
import pytest

from ctf_toolkit.forensics.usb_hid import (
    decode_usb_hid_from_text,
    decode_usb_hid_packets,
)
from ctf_toolkit.forensics.png_tools import repair_png_dimensions_from_crc


def test_usb_hid_keyboard_packets_decode():
    # Simulate typing "flag{ctf}"
    # 'f': 0x09, 'l': 0x0f, 'a': 0x04, 'g': 0x0a, '{': shift+0x2f
    # 'c': 0x06, 't': 0x17, 'f': 0x09, '}': shift+0x30
    packets = [
        bytes([0, 0, 0x09, 0, 0, 0, 0, 0]), bytes(8),
        bytes([0, 0, 0x0F, 0, 0, 0, 0, 0]), bytes(8),
        bytes([0, 0, 0x04, 0, 0, 0, 0, 0]), bytes(8),
        bytes([0, 0, 0x0A, 0, 0, 0, 0, 0]), bytes(8),
        bytes([0x02, 0, 0x2F, 0, 0, 0, 0, 0]), bytes(8),  # '{'
        bytes([0, 0, 0x06, 0, 0, 0, 0, 0]), bytes(8),
        bytes([0, 0, 0x17, 0, 0, 0, 0, 0]), bytes(8),
        bytes([0, 0, 0x09, 0, 0, 0, 0, 0]), bytes(8),
        bytes([0x02, 0, 0x30, 0, 0, 0, 0, 0]), bytes(8),  # '}'
    ]
    typed = decode_usb_hid_packets(packets)
    assert typed == "flag{ctf}"


def test_usb_hid_from_text_dump():
    # Standard tshark format (colon-separated or raw hex)
    text_dump = """
    00:00:1e:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:1f:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:20:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:2a:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:21:00:00:00:00:00
    00:00:00:00:00:00:00:00
    """
    # Types '1', '2', '3', Backspace, '4' -> '124'
    res = decode_usb_hid_from_text(text_dump)
    assert res == "124"


def test_png_ihdr_dimension_repair_height():
    true_w, true_h = 1280, 720
    tail = b"\x08\x02\x00\x00\x00"  # 8-bit truecolor
    true_payload = struct.pack(">II", true_w, true_h) + tail
    crc = zlib.crc32(b"IHDR" + true_payload) & 0xFFFFFFFF

    # Corrupt height to 1
    corrupted_payload = struct.pack(">II", true_w, 1) + tail
    mock_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        + corrupted_payload
        + struct.pack(">I", crc)
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )

    patched, w, h = repair_png_dimensions_from_crc(mock_png)
    assert (w, h) == (true_w, true_h)
    assert struct.pack(">II", true_w, true_h) in patched


def test_png_ihdr_dimension_repair_width():
    true_w, true_h = 800, 600
    tail = b"\x08\x06\x00\x00\x00"  # RGBA
    true_payload = struct.pack(">II", true_w, true_h) + tail
    crc = zlib.crc32(b"IHDR" + true_payload) & 0xFFFFFFFF

    # Corrupt width to 1
    corrupted_payload = struct.pack(">II", 1, true_h) + tail
    mock_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        + corrupted_payload
        + struct.pack(">I", crc)
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )

    patched, w, h = repair_png_dimensions_from_crc(mock_png)
    assert (w, h) == (true_w, true_h)

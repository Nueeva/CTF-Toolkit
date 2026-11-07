from __future__ import annotations

import re


def decode_zero_width(text: str) -> bytes:
    """Decode zero-width spaces (\u200b=0, \u200c=1) to bytes."""
    bits: list[str] = []
    for ch in text:
        if ch == "\u200b":
            bits.append("0")
        elif ch == "\u200c":
            bits.append("1")
    bit_str = "".join(bits)
    byte_vals = [
        int(bit_str[i : i + 8], 2)
        for i in range(0, len(bit_str), 8)
        if len(bit_str[i : i + 8]) == 8
    ]
    return bytes(byte_vals)


def encode_zero_width(data: bytes) -> str:
    """Encode bytes into zero-width characters (\u200b and \u200c)."""
    out: list[str] = []
    for b in data:
        bits = f"{b:08b}"
        for bit in bits:
            out.append("\u200c" if bit == "1" else "\u200b")
    return "".join(out)


def decode_trailing_whitespace(lines: list[str]) -> bytes:
    """Extract trailing tabs (1) and spaces (0) from line endings to bytes."""
    bits: list[str] = []
    for line in lines:
        m = re.search(r"[\t ]+$", line.rstrip("\r\n"))
        if m:
            for ch in m.group(0):
                bits.append("1" if ch == "\t" else "0")
    bit_str = "".join(bits)
    byte_vals = [
        int(bit_str[i : i + 8], 2)
        for i in range(0, len(bit_str), 8)
        if len(bit_str[i : i + 8]) == 8
    ]
    return bytes(byte_vals)

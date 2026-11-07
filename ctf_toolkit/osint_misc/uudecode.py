"""UUencode and UUdecode utility functions."""

from __future__ import annotations

import binascii


def decode_uu(data: str | bytes) -> bytes:
    """Decode UUencoded data, supporting full begin/end envelopes or bare lines."""
    if isinstance(data, bytes):
        text = data.decode("latin-1", errors="ignore")
    else:
        text = data

    lines = text.strip().splitlines()
    out = bytearray()
    in_body = False
    has_begin = any(line.strip().startswith("begin ") for line in lines)

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("begin "):
            in_body = True
            continue
        if line == "end" or line == "`":
            if has_begin and line == "end":
                in_body = False
            continue
        if not has_begin or in_body:
            try:
                out.extend(binascii.a2b_uu(raw_line.rstrip("\r\n") + "\n"))
            except binascii.Error:
                try:
                    out.extend(binascii.a2b_uu(line + "\n"))
                except Exception:
                    pass
    return bytes(out)


def encode_uu(data: bytes, filename: str = "data.txt", mode: int = 644) -> str:
    """Encode binary data into standard UUencoded format with begin/end envelope."""
    lines = [f"begin {mode:o} {filename}"]
    chunk_size = 45  # Standard uuencode chunk is 45 bytes
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        lines.append(binascii.b2a_uu(chunk).decode("latin-1").rstrip("\r\n"))
    lines.append("`")
    lines.append("end")
    return "\n".join(lines) + "\n"


XXE_ALPHABET = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def decode_xx(data: str | bytes) -> bytes:
    """Decode XXencoded data, supporting begin/end headers or bare payload."""
    if isinstance(data, bytes):
        text = data.decode("latin1", errors="ignore")
    else:
        text = data

    char_map = {c: i for i, c in enumerate(XXE_ALPHABET)}
    lines = text.strip().splitlines()
    out = bytearray()
    for line in lines:
        line = line.strip()
        if line.startswith("begin ") or line == "end" or line == "+" or not line:
            continue
        n = char_map.get(line[0], 0)
        if n == 0:
            continue
        data_str = line[1:]
        line_bytes = bytearray()
        for i in range(0, len(data_str), 4):
            chunk = data_str[i : i + 4]
            if len(chunk) < 4:
                chunk = chunk.ljust(4, "+")
            v0 = char_map.get(chunk[0], 0)
            v1 = char_map.get(chunk[1], 0)
            v2 = char_map.get(chunk[2], 0)
            v3 = char_map.get(chunk[3], 0)
            b0 = (v0 << 2) | (v1 >> 4)
            b1 = ((v1 & 0xF) << 4) | (v2 >> 2)
            b2 = ((v2 & 0x3) << 6) | v3
            line_bytes.extend([b0, b1, b2])
        out.extend(line_bytes[:n])
    return bytes(out)


def encode_xx(data: bytes, filename: str = "data.xxe", mode: int = 644) -> str:
    """Encode binary data into standard XXencoded format with begin/end envelope."""
    char_map = XXE_ALPHABET
    lines = [f"begin {mode:o} {filename}"]
    chunk_size = 45
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        n_char = char_map[len(chunk)]
        encoded = [n_char]
        for j in range(0, len(chunk), 3):
            sub = chunk[j : j + 3]
            padded = sub.ljust(3, b"\x00")
            b0, b1, b2 = padded[0], padded[1], padded[2]
            v0 = (b0 >> 2) & 0x3F
            v1 = (((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)) & 0x3F
            v2 = (((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)) & 0x3F
            v3 = b2 & 0x3F
            encoded.append(char_map[v0] + char_map[v1] + char_map[v2] + char_map[v3])
        lines.append("".join(encoded))
    lines.append("+")
    lines.append("end")
    return "\n".join(lines) + "\n"


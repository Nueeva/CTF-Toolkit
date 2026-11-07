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

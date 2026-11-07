from __future__ import annotations

import struct


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def repair_png_header(png_data: bytes | bytearray) -> bytes:
    """
    Check and restore standard 8-byte PNG signature header (\x89PNG\r\n\x1a\n).
    Useful when a PNG file header is zeroed out or corrupted.
    """
    arr = bytearray(png_data)
    if len(arr) < 8:
        raise ValueError("Data too short to be a valid PNG image")
    arr[:8] = PNG_SIGNATURE
    return bytes(arr)


def extract_png_text_chunks(png_data: bytes) -> dict[str, str]:
    """
    Parse a PNG binary and extract all tEXt keyword/value pairs.
    """
    out: dict[str, str] = {}
    if len(png_data) < 8:
        return out

    idx = 8
    while idx + 8 <= len(png_data):
        length, ctype = struct.unpack(">I4s", png_data[idx : idx + 8])
        idx += 8
        if idx + length > len(png_data):
            break
        cdata = png_data[idx : idx + length]
        idx += length + 4  # skip 4-byte CRC

        if ctype == b"tEXt":
            parts = cdata.split(b"\x00", 1)
            if len(parts) == 2:
                key = parts[0].decode("latin-1", errors="ignore")
                val = parts[1].decode("latin-1", errors="ignore")
                out[key] = val
        elif ctype == b"IEND":
            break

    return out

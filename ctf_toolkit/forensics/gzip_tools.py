from __future__ import annotations

import struct


def extract_gzip_metadata(data: bytes) -> dict[str, str]:
    """Extract header metadata (FNAME, FCOMMENT, MTIME) from Gzip archive."""
    result: dict[str, str] = {}
    if len(data) < 10 or data[:2] != b"\x1f\x8b":
        return result

    cm = data[2]
    flg = data[3]
    mtime = struct.unpack("<I", data[4:8])[0]
    result["method"] = "deflate" if cm == 8 else str(cm)
    result["mtime"] = str(mtime)

    curr = 10
    if flg & 4:  # FEXTRA
        if curr + 2 <= len(data):
            xlen = struct.unpack("<H", data[curr : curr + 2])[0]
            curr += 2 + xlen
    if flg & 8:  # FNAME
        end = data.find(b"\x00", curr)
        if end != -1:
            result["filename"] = data[curr:end].decode("latin-1", errors="ignore")
            curr = end + 1
    if flg & 16:  # FCOMMENT
        end = data.find(b"\x00", curr)
        if end != -1:
            result["comment"] = data[curr:end].decode("latin-1", errors="ignore")
            curr = end + 1

    return result

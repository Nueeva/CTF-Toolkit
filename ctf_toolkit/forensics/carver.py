from __future__ import annotations

import zlib
from typing import Any

CARVE_SIGNATURES: list[tuple[str, bytes, bytes | None]] = [
    ("PNG", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    ("JPEG", b"\xff\xd8\xff", b"\xff\xd9"),
    ("GIF", b"GIF89a", b"\x00;"),
    ("ZIP", b"PK\x03\x04", None),
    ("GZIP", b"\x1f\x8b\x08", None),
    ("BZ2", b"BZh", None),
    ("PDF", b"%PDF-", b"%%EOF"),
    ("ELF", b"\x7fELF", None),
    ("ZLIB_DEFAULT", b"\x78\x9c", None),
    ("ZLIB_BEST", b"\x78\xda", None),
]


def scan_embedded_signatures(data: bytes, include_offset_zero: bool = True) -> list[dict[str, Any]]:
    """
    Scan binary blob for embedded file headers across all byte offsets (`binwalk` style).
    """
    hits: list[dict[str, Any]] = []
    start_pos = 0 if include_offset_zero else 1

    for fmt_name, magic, trailer in CARVE_SIGNATURES:
        pos = data.find(magic, start_pos)
        while pos != -1:
            end_pos = len(data)
            if trailer is not None:
                t_idx = data.find(trailer, pos + len(magic))
                if t_idx != -1:
                    end_pos = t_idx + len(trailer)
            hits.append({
                "offset": pos,
                "format": fmt_name,
                "magic_hex": magic.hex(),
                "end_offset": end_pos,
            })
            pos = data.find(magic, pos + 1)

    hits.sort(key=lambda h: h["offset"])
    return hits


def carve_embedded_files(data: bytes, include_offset_zero: bool = False) -> list[dict[str, Any]]:
    """
    Extract embedded files or decompress embedded ZLIB/GZIP streams from a binary blob (`binwalk -e` style).
    """
    hits = scan_embedded_signatures(data, include_offset_zero=include_offset_zero)
    carved: list[dict[str, Any]] = []

    for h in hits:
        offset = h["offset"]
        end_offset = h["end_offset"]
        fmt = h["format"]
        slice_bytes = data[offset:end_offset]
        decompressed: bytes | None = None

        if fmt.startswith("ZLIB"):
            try:
                decompressed = zlib.decompress(slice_bytes)
            except Exception:
                continue
        elif fmt == "GZIP":
            try:
                decompressed = zlib.decompress(slice_bytes, 16 + zlib.MAX_WBITS)
            except Exception:
                pass

        carved.append({
            "offset": offset,
            "format": fmt,
            "data": slice_bytes,
            "decompressed": decompressed,
        })

    return carved

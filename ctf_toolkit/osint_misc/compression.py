from __future__ import annotations

import bz2
import gzip
import lzma
import zlib


def decompress_blob(data: bytes) -> tuple[str, bytes]:
    """Attempt decompressing raw binary blob using zlib, gzip, bzip2, or lzma."""
    # 1. Zlib
    try:
        return "zlib", zlib.decompress(data)
    except Exception:
        pass

    # 2. Gzip
    try:
        return "gzip", gzip.decompress(data)
    except Exception:
        pass

    # 3. Bzip2
    try:
        return "bz2", bz2.decompress(data)
    except Exception:
        pass

    # 4. LZMA / XZ
    try:
        return "lzma", lzma.decompress(data)
    except Exception:
        pass

    raise ValueError("Failed to decompress blob: unsupported or corrupted compression format")

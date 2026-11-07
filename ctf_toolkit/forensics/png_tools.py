from __future__ import annotations

import struct
import zlib


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


def extract_png_all_metadata(png_data: bytes) -> dict[str, bytes]:
    """
    Extract text chunks across tEXt, zTXt (zlib decompressed), and iTXt chunks.
    """
    out: dict[str, bytes] = {}
    if len(png_data) < 8:
        return out

    idx = 8
    while idx + 8 <= len(png_data):
        length, ctype = struct.unpack(">I4s", png_data[idx : idx + 8])
        idx += 8
        if idx + length > len(png_data):
            break
        cdata = png_data[idx : idx + length]
        idx += length + 4

        if ctype == b"tEXt":
            parts = cdata.split(b"\x00", 1)
            if len(parts) == 2:
                out[parts[0].decode("latin-1", errors="ignore")] = parts[1]
        elif ctype == b"zTXt":
            parts = cdata.split(b"\x00", 1)
            if len(parts) == 2 and len(parts[1]) > 1:
                # parts[1][0] is compression method (0 = zlib deflate)
                try:
                    decomp = zlib.decompress(parts[1][1:])
                    out[parts[0].decode("latin-1", errors="ignore")] = decomp
                except Exception:
                    pass
        elif ctype == b"iTXt":
            parts = cdata.split(b"\x00", 4)
            if len(parts) >= 5:
                # parts[0]: keyword, parts[1]: [comp_flag, comp_method], parts[2]: lang, parts[3]: trans, parts[4]: text
                key = parts[0].decode("latin-1", errors="ignore")
                flag_bytes = parts[1]
                comp_flag = flag_bytes[0] if len(flag_bytes) > 0 else 0
                raw_text = parts[4]
                if comp_flag == 1:
                    try:
                        decomp = zlib.decompress(raw_text)
                        out[key] = decomp
                    except Exception:
                        pass
                else:
                    out[key] = raw_text
        elif ctype == b"IEND":
            break

    return out


def extract_png_trailing_payload(png_data: bytes) -> bytes:
    """
    Extract any appended/polyglot data occurring after the PNG IEND chunk.
    """
    iend_idx = png_data.find(b"IEND")
    if iend_idx == -1:
        return b""
    # IEND chunk length is 0, so chunk is: [4 bytes length 0][4 bytes 'IEND'][4 bytes CRC] = 12 bytes
    # iend_idx is offset of 'IEND', so +4 (IEND) + 4 (CRC) = +8
    trailer_start = iend_idx + 8
    if trailer_start < len(png_data):
        return png_data[trailer_start:]
    return b""

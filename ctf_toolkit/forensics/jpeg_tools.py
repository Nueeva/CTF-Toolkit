from __future__ import annotations

import io
from pathlib import Path

JPEG_SOI = b"\xff\xd8\xff"
JPEG_EOI = b"\xff\xd9"
SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def extract_jpeg_fragments(path: str, output_dir: str = "output/jpeg_fragments") -> list[Path]:
    source = Path(path)
    data = source.read_bytes()
    if not data:
        return []

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    parts: list[Path] = []
    idx = 0
    counter = 1
    while True:
        soi = data.find(JPEG_SOI, idx)
        if soi < 0:
            break
        eoi = data.find(JPEG_EOI, soi + 3)
        if eoi < 0:
            break
        chunk = data[soi : eoi + 2]
        out_path = out_dir / f"fragment_{counter:03d}.jpg"
        out_path.write_bytes(chunk)
        parts.append(out_path)
        counter += 1
        idx = eoi + 2

    return parts


def repair_jpeg_header(data: bytes | bytearray) -> bytes:
    """Restores standard FF D8 SOI marker if corrupted or truncated."""
    arr = bytearray(data)
    if len(arr) < 2:
        raise ValueError("Data too short to be a valid JPEG")
    arr[:2] = b"\xff\xd8"
    return bytes(arr)


def extract_jpeg_comments(jpeg_data: bytes) -> list[str]:
    """Parse COM (0xFF 0xFE) segments from JPEG stream."""
    comments: list[str] = []
    idx = 2
    while idx + 4 <= len(jpeg_data):
        if jpeg_data[idx] == 0xFF:
            marker = jpeg_data[idx + 1]
            if marker in (0xD8, 0xD9):  # SOI, EOI
                idx += 2
                continue
            length = int.from_bytes(jpeg_data[idx + 2 : idx + 4], "big")
            if marker == 0xFE:  # COM marker
                comment_payload = jpeg_data[idx + 4 : idx + 2 + length]
                comments.append(comment_payload.decode("latin-1", errors="ignore"))
            idx += 2 + length
        else:
            idx += 1
    return comments


def extract_all_jpeg_comments_bytes(jpeg_data: bytes) -> list[bytes]:
    """Extract raw byte payloads of all JPEG COM segments."""
    comments: list[bytes] = []
    idx = 2
    while idx + 4 <= len(jpeg_data):
        if jpeg_data[idx] == 0xFF:
            marker = jpeg_data[idx + 1]
            if marker in (0xD8, 0xD9):
                idx += 2
                continue
            length = int.from_bytes(jpeg_data[idx + 2 : idx + 4], "big")
            if marker == 0xFE:
                comment_payload = jpeg_data[idx + 4 : idx + 2 + length]
                comments.append(comment_payload)
            idx += 2 + length
        else:
            idx += 1
    return comments


def concatenate_jpeg_comments(jpeg_data: bytes) -> bytes:
    """Concatenate split COM segments into a continuous byte sequence."""
    return b"".join(extract_all_jpeg_comments_bytes(jpeg_data))



def get_jpeg_dimensions(path_or_bytes: str | Path | bytes) -> tuple[int, int]:
    """Read width and height from the first JPEG SOF marker."""
    data = path_or_bytes if isinstance(path_or_bytes, (bytes, bytearray)) else Path(path_or_bytes).read_bytes()
    idx = 2
    while idx + 9 <= len(data):
        if data[idx] == 0xFF:
            marker = data[idx + 1]
            if marker in (0xD8, 0xD9):
                idx += 2
                continue
            length = int.from_bytes(data[idx + 2 : idx + 4], "big")
            if marker in SOF_MARKERS and idx + 9 <= len(data):
                height = int.from_bytes(data[idx + 5 : idx + 7], "big")
                width = int.from_bytes(data[idx + 7 : idx + 9], "big")
                return width, height
            idx += 2 + length
        else:
            idx += 1
    raise ValueError("SOF marker not found in JPEG")


def patch_jpeg_dimensions(path: str | Path, width: int, height: int, output_path: str | Path | None = None) -> Path:
    """Patch width and height inside a JPEG SOF header (useful when CTF challenges hide flags by shrinking height)."""
    src = Path(path)
    arr = bytearray(src.read_bytes())
    idx = 2
    patched = False
    while idx + 9 <= len(arr):
        if arr[idx] == 0xFF:
            marker = arr[idx + 1]
            if marker in (0xD8, 0xD9):
                idx += 2
                continue
            length = int.from_bytes(arr[idx + 2 : idx + 4], "big")
            if marker in SOF_MARKERS:
                arr[idx + 5 : idx + 7] = int(height).to_bytes(2, "big")
                arr[idx + 7 : idx + 9] = int(width).to_bytes(2, "big")
                patched = True
                break
            idx += 2 + length
        else:
            idx += 1
    if not patched:
        raise ValueError("SOF marker not found in JPEG")
    out = Path(output_path) if output_path else src.with_name(f"{src.stem}_patched{src.suffix}")
    out.write_bytes(bytes(arr))
    return out

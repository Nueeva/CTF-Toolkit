from __future__ import annotations

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


def _find_sof_segment(data: bytes) -> tuple[int, int]:
    i = 0
    length = len(data)
    while i + 4 < length:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xD8 or marker == 0xD9:
            i += 2
            continue
        if marker == 0xDA:
            break
        seg_len = int.from_bytes(data[i + 2 : i + 4], "big")
        if seg_len < 2 or i + 2 + seg_len > length:
            break
        if marker in SOF_MARKERS and seg_len >= 7:
            return i, seg_len
        i += 2 + seg_len
    raise ValueError("SOF segment JPEG tidak ditemukan")


def get_jpeg_dimensions(path: str) -> tuple[int, int]:
    data = Path(path).read_bytes()
    if not data.startswith(JPEG_SOI):
        raise ValueError("bukan JPEG (SOI tidak ditemukan)")
    sof_idx, _ = _find_sof_segment(data)
    height = int.from_bytes(data[sof_idx + 5 : sof_idx + 7], "big")
    width = int.from_bytes(data[sof_idx + 7 : sof_idx + 9], "big")
    return width, height


def patch_jpeg_dimensions(path: str, width: int, height: int, output_path: str | None = None) -> Path:
    if width <= 0 or height <= 0 or width > 65535 or height > 65535:
        raise ValueError("width/height harus 1..65535")
    source = Path(path)
    data = bytearray(source.read_bytes())
    if not data.startswith(JPEG_SOI):
        raise ValueError("bukan JPEG (SOI tidak ditemukan)")

    sof_idx, _ = _find_sof_segment(data)
    data[sof_idx + 5 : sof_idx + 7] = height.to_bytes(2, "big")
    data[sof_idx + 7 : sof_idx + 9] = width.to_bytes(2, "big")

    out = Path(output_path) if output_path else source.with_name(f"{source.stem}_patched.jpg")
    out.write_bytes(bytes(data))
    return out

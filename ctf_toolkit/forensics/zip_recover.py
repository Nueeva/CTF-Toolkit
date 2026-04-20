from __future__ import annotations

from pathlib import Path
import zipfile

ZIP_LOCAL_FILE_HEADER = b"PK\x03\x04"
ZIP_EOCD = b"PK\x05\x06"


def recover_corrupted_zip(path: str, output_path: str | None = None) -> Path:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"file tidak ditemukan: {source}")

    data = source.read_bytes()
    if not data:
        raise ValueError("file kosong")

    start = data.find(ZIP_LOCAL_FILE_HEADER)
    if start < 0:
        raise ValueError("signature ZIP local header tidak ditemukan")

    repaired = data[start:]
    eocd_idx = repaired.rfind(ZIP_EOCD)
    if eocd_idx >= 0 and len(repaired) >= eocd_idx + 22:
        comment_len = int.from_bytes(repaired[eocd_idx + 20 : eocd_idx + 22], "little")
        expected_end = eocd_idx + 22 + comment_len
        if expected_end <= len(repaired):
            repaired = repaired[:expected_end]

    out = Path(output_path) if output_path else source.with_name(f"{source.stem}_recovered.zip")
    out.write_bytes(repaired)
    return out


def list_zip_members(path: str) -> list[str]:
    target = Path(path)
    with zipfile.ZipFile(target, "r") as zf:
        return zf.namelist()

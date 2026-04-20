from __future__ import annotations

MAGIC_TABLE = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/EXE"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x1f\x8b", "GZIP"),
]


def detect_file_magic(data: bytes) -> str:
    for magic, name in MAGIC_TABLE:
        if data.startswith(magic):
            return name
    return "Unknown"

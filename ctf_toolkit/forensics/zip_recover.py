from __future__ import annotations

import bz2
import gzip
import io
import lzma
from pathlib import Path
import re
import tarfile
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


def repair_zip_header(zip_data: bytes | bytearray) -> bytes:
    """Check and restore standard 4-byte ZIP signature header (PK\\x03\\x04)."""
    arr = bytearray(zip_data)
    if len(arr) < 4:
        raise ValueError("Data too short to be a valid ZIP archive")
    arr[:4] = ZIP_LOCAL_FILE_HEADER
    return bytes(arr)




def list_zip_members(path: str) -> list[str]:
    target = Path(path)
    with zipfile.ZipFile(target, "r") as zf:
        return zf.namelist()


def decompress_nested_stream(data: bytes, max_depth: int = 100) -> bytes:
    """
    Recursively unpacks nested archive layers across Gzip, Bzip2, XZ/LZMA, Tar, and Zip.
    Stops when the unpacked payload is no longer a recognized container.
    """
    curr = data
    for _ in range(max_depth):
        # Gzip
        if curr.startswith(b"\x1f\x8b"):
            try:
                curr = gzip.decompress(curr)
                continue
            except Exception:
                pass
        # Bzip2
        if curr.startswith(b"BZh"):
            try:
                curr = bz2.decompress(curr)
                continue
            except Exception:
                pass
        # XZ
        if curr.startswith(b"\xfd7zXZ\x00"):
            try:
                curr = lzma.decompress(curr)
                continue
            except Exception:
                pass
        # Zip
        if curr.startswith(b"PK\x03\x04"):
            try:
                zf = zipfile.ZipFile(io.BytesIO(curr))
                members = zf.namelist()
                if members:
                    curr = zf.read(members[0])
                    continue
            except Exception:
                pass
        # Tar
        try:
            tf = tarfile.open(fileobj=io.BytesIO(curr))
            members = tf.getmembers()
            if members:
                extracted = tf.extractfile(members[0])
                if extracted:
                    curr = extracted.read()
                    continue
        except Exception:
            pass

        break

    return curr


def assemble_sharded_zip(zip_data: bytes) -> bytes:
    """
    Extracts and merges ordered data shards from a zip archive.
    Sorts shards numerically (e.g. part_000, part_001, ...).
    """
    zf = zipfile.ZipFile(io.BytesIO(zip_data))
    names = zf.namelist()

    def sort_key(name: str):
        nums = re.findall(r"\d+", name)
        return int(nums[0]) if nums else name

    ordered = sorted(names, key=sort_key)
    return b"".join(zf.read(n) for n in ordered)


def fast_zip_crypto_crack(
    zip_source: bytes | str | io.BytesIO,
    passwords: list[str | bytes],
) -> tuple[bytes, bytes] | None:
    """
    High-performance dictionary attack for PKWARE ZipCrypto archives using header check byte.
    Returns (password, decrypted_first_member_bytes) if cracked, else None.
    """
    if isinstance(zip_source, str):
        with open(zip_source, "rb") as f:
            raw = f.read()
    elif isinstance(zip_source, io.BytesIO):
        raw = zip_source.getvalue()
    else:
        raw = bytes(zip_source)

    zf = zipfile.ZipFile(io.BytesIO(raw))
    info = zf.infolist()[0]

    if info.flag_bits & 0x8:
        check_byte = (info._raw_time >> 8) & 0xFF
    else:
        check_byte = (info.CRC >> 24) & 0xFF

    # Local file header offset
    lh_offset = info.header_offset
    nlen = int.from_bytes(raw[lh_offset + 26 : lh_offset + 28], "little")
    elen = int.from_bytes(raw[lh_offset + 28 : lh_offset + 30], "little")
    enc_header_offset = lh_offset + 30 + nlen + elen
    enc_header = raw[enc_header_offset : enc_header_offset + 12]

    for cand in passwords:
        pwd = cand.encode("utf-8") if isinstance(cand, str) else cand
        decrypter = zipfile._ZipDecrypter(pwd)
        h = decrypter(enc_header)
        if h[-1] == check_byte:
            try:
                content = zf.read(info.filename, pwd=pwd)
                return pwd, content
            except Exception:
                pass

    return None

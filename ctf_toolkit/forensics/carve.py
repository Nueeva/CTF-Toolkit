"""
Container carving and payload transformation for forensic specimens.

A specimen rarely stores the flag in a single obvious place. It hides in an
appended archive, a base64 blob inside a metadata field, a hex string in a log
line, or a rot13 comment. This module finds those carriers and unwraps them so
the caller only has to scan plain text.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import io
import lzma
import re
import tarfile
import zipfile
import zlib

MAGIC = [
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"%PDF", "pdf"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
]

B64_RE = re.compile(rb"(?:[A-Za-z0-9+/]{16,}={0,2})")
HEX_RE = re.compile(rb"\b(?:[0-9a-fA-F]{2}){8,}\b")


def carve_streams(data: bytes, limit: int = 8) -> list[tuple[str, bytes]]:
    """Locate embedded container headers and return (kind, bytes) slices."""
    found = []
    for magic, kind in MAGIC:
        start = 0
        while len(found) < limit:
            idx = data.find(magic, start)
            if idx < 0:
                break
            if idx == 0 and kind in ("png", "jpeg", "pdf"):
                start = idx + 1
                continue
            tail = data[idx:]
            blob = _trim_container(tail, kind)
            if blob and len(blob) > 32:
                found.append((kind, blob))
            start = idx + 1
    return found[:limit]


def _trim_container(blob: bytes, kind: str) -> bytes:
    if kind == "zip":
        end = blob.rfind(b"PK\x05\x06")
        if end >= 0:
            return blob[: end + 22]
        return blob
    if kind == "gzip":
        try:
            gzip.decompress(blob)
            return blob
        except Exception:
            return blob
    if kind == "bzip2":
        try:
            bz2.decompress(blob)
            return blob
        except Exception:
            return blob
    if kind == "xz":
        try:
            lzma.decompress(blob)
            return blob
        except Exception:
            return blob
    return blob


def expand_container(kind: str, blob: bytes, max_members: int = 40) -> list[tuple[str, bytes]]:
    """Unpack one container into (member_name, bytes) pairs."""
    out = []
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                for name in zf.namelist()[:max_members]:
                    if name.endswith("/"):
                        continue
                    try:
                        out.append((name, zf.read(name)))
                    except RuntimeError:
                        out.append((name, b"<encrypted>"))
        elif kind == "gzip":
            out.append(("gunzip.bin", gzip.decompress(blob)))
        elif kind == "bzip2":
            out.append(("bunzip2.bin", bz2.decompress(blob)))
        elif kind == "xz":
            out.append(("unxz.bin", lzma.decompress(blob)))
        elif kind in ("tar",):
            with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
                for m in tf.getmembers()[:max_members]:
                    if m.isfile():
                        fh = tf.extractfile(m)
                        if fh is not None:
                            out.append((m.name, fh.read()))
    except Exception:
        pass
    return out


def transform_candidates(text: str) -> list[tuple[str, str]]:
    """Every plausible reversible transform of a text blob."""
    out = [("raw", text)]
    stripped = text.strip()
    if not stripped:
        return out

    # base64 blocks
    for m in B64_RE.finditer(stripped.encode("latin-1", "ignore")):
        chunk = m.group(0)
        if len(chunk) % 4:
            chunk += b"=" * (-len(chunk) % 4)
        try:
            dec = base64.b64decode(chunk, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            dec_txt = dec.decode("utf-8")
        except UnicodeDecodeError:
            dec_txt = dec.decode("latin-1")
        if sum(c.isprintable() for c in dec_txt) / max(1, len(dec_txt)) > 0.85:
            out.append(("b64", dec_txt))

    # hex strings
    for m in HEX_RE.finditer(stripped.encode("latin-1", "ignore")):
        chunk = m.group(0)
        try:
            dec = bytes.fromhex(chunk.decode())
            dec_txt = dec.decode("latin-1")
        except ValueError:
            continue
        if sum(c.isprintable() for c in dec_txt) / max(1, len(dec_txt)) > 0.85:
            out.append(("hex", dec_txt))

    # rot13 and single-byte caesar over the whole string
    out.append(("rot13", _rot13(stripped)))
    for shift in (1, -1, 2, -2, 3, -3, 5, -5, 13, -13):
        out.append((f"caesar{shift}", _caesar(stripped, shift)))

    # url encoding
    if "%" in stripped:
        try:
            from urllib.parse import unquote
            out.append(("url", unquote(stripped)))
        except Exception:
            pass
    return out


def _rot13(s: str) -> str:
    import codecs
    return codecs.decode(s, "rot13")


def _caesar(s: str, shift: int) -> str:
    res = []
    for ch in s:
        if "a" <= ch <= "z":
            res.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            res.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            res.append(ch)
    return "".join(res)


def carve_and_expand(data: bytes, depth: int = 2) -> list[tuple[str, bytes]]:
    """Recursively carve embedded containers out of a blob."""
    out: list[tuple[str, bytes]] = []
    if depth <= 0:
        return out
    for kind, blob in carve_streams(data):
        for name, member in expand_container(kind, blob):
            out.append((f"{kind}:{name}", member))
            if depth > 1 and len(member) < 8 * 1024 * 1024:
                out.extend(carve_and_expand(member, depth - 1))
    return out


def decompress_any(blob: bytes) -> bytes | None:
    """Try the common compressors on an unknown blob."""
    for fn in (gzip.decompress, bz2.decompress, lzma.decompress, zlib.decompress):
        try:
            return fn(blob)
        except Exception:
            continue
    for wbits in (15, -15, 31):
        try:
            return zlib.decompress(blob, wbits)
        except Exception:
            continue
    return None
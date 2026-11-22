"""Format validation and bounded extraction for copied evidence."""

from __future__ import annotations

import io
import re
import stat
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

from ctf_toolkit.forensics.png_tools import PNG_SIGNATURE

from .transforms import MAX_ARTIFACT_BYTES, MAX_CHILDREN, encoding_candidates

ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")
GZIP_SIGNATURE = b"\x1f\x8b"
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")
_MAX_DIRECTORY_ENTRIES = 4096
_MAX_PNG_CHUNKS = 4096
_PNG_DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
SUPPORTED_COMPRESSION = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)


@dataclass(frozen=True)
class Extracted:
    label: str
    operation: str
    data: bytes
    source: dict


@dataclass
class Inspection:
    format: str = "unknown"
    confidence: str = "unknown"
    encodings: list[str] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    children: list[Extracted] = field(default_factory=list)

    def report(self) -> dict:
        encoding_status = {0: "none", 1: "candidate"}.get(len(self.encodings), "ambiguous")
        return {
            "format": self.format,
            "confidence": self.confidence,
            "encodings": self.encodings,
            "encoding_status": encoding_status,
            "sections": self.sections,
            "issues": self.issues,
        }


def _png(data: bytes, byte_budget: int, item_budget: int) -> Inspection:
    result = Inspection("png", "candidate")
    view = memoryview(data)
    pos = len(PNG_SIGNATURE)
    saw_image_data = False
    while pos + 12 <= len(data) and len(result.sections) < _MAX_PNG_CHUNKS:
        length, name = struct.unpack_from(">I4s", view, pos)
        stop = pos + 12 + length
        if stop > len(data):
            result.issues.append("PNG chunk extends past the file")
            return result
        if not result.sections and (name != b"IHDR" or length != 13):
            result.issues.append("PNG does not begin with a valid IHDR")
            return result
        if name == b"IHDR":
            if result.sections:
                result.issues.append("PNG repeats IHDR")
                return result
            width, height, depth, color, compression, filtering, interlace = struct.unpack_from(">IIBBBBB", view, pos + 8)
            if (not 0 < width < 2**31 or not 0 < height < 2**31 or depth not in _PNG_DEPTHS.get(color, ())
                    or compression != 0 or filtering != 0 or interlace not in (0, 1)):
                result.issues.append("PNG IHDR fields failed validation")
                return result
        stored_crc = struct.unpack_from(">I", view, stop - 4)[0]
        if zlib.crc32(view[pos + 4 : stop - 4]) != stored_crc:
            result.issues.append(f"PNG chunk CRC mismatch at byte {pos}")
            return result
        result.sections.append(
            {"name": name.decode("ascii", "replace"), "start": pos, "stop": stop}
        )
        saw_image_data |= name == b"IDAT"
        if name == b"IEND" and length == 0 and saw_image_data:
            result.confidence = "confirmed"
            if stop < len(data):
                tail = {"kind": "bytes", "start": stop, "stop": len(data)}
                result.sections.append({"name": "Trailing bytes", **tail})
                if item_budget and len(data) - stop <= byte_budget:
                    result.children.append(Extracted("PNG trailing bytes", "png_tail", data[stop:], tail))
                else:
                    result.issues.append("PNG trailing bytes exceed the remaining analysis budget")
            return result
        if name == b"IEND":
            break
        pos = stop
    result.issues.append("PNG has no valid IEND within the chunk budget")
    return result


def _zip_directory(data: bytes) -> tuple[int, int]:
    """Check the central directory before ZipFile allocates one object per entry."""
    signature = b"PK\x05\x06"
    cursor = len(data)
    while True:
        end = data.rfind(signature, max(0, len(data) - 65557), cursor)
        if end < 0:
            raise ValueError("ZIP end of central directory is missing")
        cursor = end
        if end + 22 > len(data):
            continue
        disk, directory_disk, here, count, size, start, comment = struct.unpack_from(
            "<HHHHIIH", data, end + 4
        )
        if end + 22 + comment == len(data):
            break
    if disk or directory_disk or here != count or count == 65535:
        raise ValueError("Split and ZIP64 archives are outside the case analyzer profile")
    if count > _MAX_DIRECTORY_ENTRIES:
        raise ValueError("ZIP central directory exceeds the entry limit")
    if start + size != end:
        raise ValueError("ZIP central directory has an invalid byte range")
    offset = start
    for _ in range(count):
        if offset + 46 > end or data[offset : offset + 4] != b"PK\x01\x02":
            raise ValueError("ZIP central directory contains an invalid entry")
        offset += 46 + sum(struct.unpack_from("<HHH", data, offset + 28))
    if offset != end:
        raise ValueError("ZIP central directory does not match its entry count")
    return start, end


def _zip(data: bytes, byte_budget: int, item_budget: int) -> Inspection:
    result = Inspection("zip", "candidate")
    try:
        start, stop = _zip_directory(data)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            result.confidence = "confirmed"
            result.sections.append({"name": "Central directory", "start": start, "stop": stop})
            for index, member in enumerate(archive.infolist()):
                if member.is_dir():
                    continue
                label = member.filename
                result.sections.append({
                    "name": label, "member_index": index, "header_offset": member.header_offset,
                    "size": member.file_size, "compressed_size": member.compress_size,
                    "crc32": f"{member.CRC:08x}",
                })
                if len(result.children) == item_budget:
                    if "ZIP extraction stopped at the remaining item or depth limit" not in result.issues:
                        result.issues.append("ZIP extraction stopped at the remaining item or depth limit")
                    continue
                if member.flag_bits & 1:
                    result.issues.append(f"Encrypted ZIP member skipped: {label}")
                    continue
                mode = (member.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode) or member.compress_type not in SUPPORTED_COMPRESSION:
                    result.issues.append(f"Unsupported ZIP member skipped: {label}")
                    continue
                limit = min(MAX_ARTIFACT_BYTES, byte_budget)
                if member.file_size > limit:
                    result.issues.append(f"ZIP member exceeds the remaining byte budget: {label}")
                    continue
                try:
                    with archive.open(member) as stream:
                        content = stream.read(limit + 1)
                    if len(content) != member.file_size:
                        raise ValueError("stored and actual size disagree")
                except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, zlib.error) as exc:
                    result.issues.append(f"Could not read ZIP member {label}: {exc}")
                    continue
                byte_budget -= len(content)
                location = {
                    "kind": "zip_member", "name": label, "member_index": index,
                    "header_offset": member.header_offset,
                }
                result.children.append(Extracted(label, "zip_member", content, location))
    except (ValueError, OSError, zipfile.BadZipFile, NotImplementedError) as exc:
        result.issues.append(str(exc))
    return result


def _gzip(data: bytes, byte_budget: int, item_budget: int) -> Inspection:
    result = Inspection("gzip", "candidate")
    start = 0
    while start < len(data):
        if not data.startswith(GZIP_SIGNATURE, start):
            result.issues.append("Bytes remain after the last GZIP member")
            break
        if len(result.children) >= item_budget:
            result.issues.append("GZIP extraction stopped at the remaining item or depth limit")
            break
        limit = min(MAX_ARTIFACT_BYTES, byte_budget)
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            content = decompressor.decompress(memoryview(data)[start:], limit + 1)
        except zlib.error as exc:
            result.issues.append(f"GZIP stream failed validation: {exc}")
            break
        if len(content) > limit:
            result.issues.append("GZIP member exceeds the remaining byte budget")
            break
        if not decompressor.eof:
            result.issues.append("GZIP stream is incomplete")
            break
        result.confidence = "confirmed"
        stop = len(data) - len(decompressor.unused_data)
        source = {"kind": "gzip_stream", "start": start, "stop": stop}
        label = f"GZIP member {len(result.children) + 1}"
        result.sections.append({"name": label, **source})
        result.children.append(Extracted(label, "gzip_member", content, source))
        byte_budget -= len(content)
        start = stop
    return result


def inspect_artifact(
    data: bytes, *, byte_budget: int = MAX_ARTIFACT_BYTES, item_budget: int = MAX_CHILDREN
) -> Inspection:
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("Input exceeds the artifact size limit")
    if data.startswith(PNG_SIGNATURE):
        return _png(data, byte_budget, item_budget)
    if data.startswith(ZIP_SIGNATURES):
        return _zip(data, byte_budget, item_budget)
    if data.startswith(GZIP_SIGNATURE):
        return _gzip(data, byte_budget, item_budget)
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return Inspection()
    if not decoded or _CONTROL_CHARACTERS.search(decoded):
        return Inspection()
    return Inspection("utf8", "confirmed", encodings=encoding_candidates(data))

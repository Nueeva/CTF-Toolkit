"""Deterministic, original case exercises."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

from ctf_toolkit.crypto.classical import caesar_encrypt

from .store import Workspace


def _chunk(tag: bytes, data: bytes) -> bytes:
    payload = tag + data
    return struct.pack(">I", len(data)) + payload + struct.pack(">I", zlib.crc32(payload))


def layered_png() -> bytes:
    image = (b"\x89PNG\r\n\x1a\n" +
             _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) +
             _chunk(b"IDAT", zlib.compress(b"\0\xff\xff\xff")) + _chunk(b"IEND", b""))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name in ("desk/message.b64", "archive/copy.b64"):
            archive.writestr(zipfile.ZipInfo(name), b"aGVsbG8=")
    return image + output.getvalue()


def timeline_inputs() -> list[tuple[str, bytes]]:
    header = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    frame = b"\x02\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x08\x88\xb5" + b"training"
    capture = header + b"".join(
        struct.pack("<IIII", 1795230900, nanos, len(frame), len(frame)) + frame
        for nanos in (1, 2)
    )
    log = (
        b'192.0.2.8 - - [21/Nov/2026:10:15:00 +0700] "GET /status HTTP/1.1" 200 12\n'
        b'192.0.2.8 - - [21/Nov/2026:03:15:00 +0000] "GET /status HTTP/1.1" 200 12\n'
    )
    structured = b'{"datetime":"2026-11-21T10:15:00","message":"Operator checked the exhibit","timestamp_desc":"operator note"}\n'
    return [("capture.pcap", capture), ("access.log", log), ("observations.jsonl", structured)]


def populate(workspace: Workspace, exercise: str) -> list[dict]:
    if exercise == "layered":
        files = [("exhibit.png", layered_png())]
    elif exercise == "timeline":
        files = timeline_inputs()
    elif exercise == "caesar":
        files = [
            ("indonesia.txt", caesar_encrypt("Berkas di ruang baca disimpan untuk diperiksa bersama besok.", 9).encode()),
            ("english.txt", caesar_encrypt("The exhibit was copied before the afternoon review began.", 15).encode()),
        ]
    else:
        raise ValueError("Unknown case exercise")
    return [workspace.add(name, data) for name, data in files]

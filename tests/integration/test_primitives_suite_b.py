from __future__ import annotations

import struct
from ctf_toolkit.forensics.png_tools import repair_png_header, extract_png_text_chunks, PNG_SIGNATURE
from ctf_toolkit.osint_misc.config_hunter import parse_vcf, parse_ics


def test_repair_png_header():
    # Corrupted 8-byte zeroed header
    corrupted = b"\x00" * 8 + b"\x00\x00\x00\rIHDR"
    repaired = repair_png_header(corrupted)
    assert repaired[:8] == PNG_SIGNATURE
    assert repaired[8:] == b"\x00\x00\x00\rIHDR"


def test_extract_png_text_chunks():
    # Construct a minimal synthetic PNG with a tEXt chunk
    # Header: 8 bytes
    # IHDR: length 0, ctype IHDR, crc 0
    # tEXt: length 16, ctype tEXt, data b"Author\x00JohnDoe", crc 0
    # IEND: length 0, ctype IEND, crc 0
    text_data = b"Author\x00JohnDoe"
    chunk_text = struct.pack(">I4s", len(text_data), b"tEXt") + text_data + struct.pack(">I", 0)
    chunk_iend = struct.pack(">I4s", 0, b"IEND") + struct.pack(">I", 0)
    png_bytes = PNG_SIGNATURE + chunk_text + chunk_iend

    extracted = extract_png_text_chunks(png_bytes)
    assert extracted.get("Author") == "JohnDoe"


def test_parse_vcf():
    vcf = """
BEGIN:VCARD
VERSION:3.0
FN:Alice Smith
EMAIL:alice@example.com
NOTE:SecretNote123
END:VCARD
"""
    cards = parse_vcf(vcf)
    assert len(cards) == 1
    assert cards[0]["FN"] == "Alice Smith"
    assert cards[0]["NOTE"] == "SecretNote123"


def test_parse_ics():
    ics = """
BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:evt-42
SUMMARY:Team Standup
X-FLAG:CTFSecretToken
END:VEVENT
END:VCALENDAR
"""
    events = parse_ics(ics)
    assert len(events) == 1
    assert events[0]["UID"] == "evt-42"
    assert events[0]["X-FLAG"] == "CTFSecretToken"

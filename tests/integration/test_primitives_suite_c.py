from __future__ import annotations

import io
import zipfile
from ctf_toolkit.forensics.jpeg_tools import repair_jpeg_header, extract_jpeg_comments
from ctf_toolkit.forensics.zip_recover import repair_zip_header, ZIP_LOCAL_FILE_HEADER
from ctf_toolkit.crypto.encoding import decode_html_entities


def test_repair_jpeg_header():
    corrupted = b"\x00\x00\xff\xe0\x00\x10JFIF"
    repaired = repair_jpeg_header(corrupted)
    assert repaired[:2] == b"\xff\xd8"
    assert repaired[2:] == b"\xff\xe0\x00\x10JFIF"


def test_extract_jpeg_comments():
    # Build synthetic JPEG with a COM segment
    # COM segment: 0xFF 0xFE, length (2 bytes including length itself), text
    text = b"HelloJPEGComment"
    seg_len = (len(text) + 2).to_bytes(2, "big")
    jpeg_data = b"\xff\xd8\xff\xfe" + seg_len + text + b"\xff\xd9"
    comments = extract_jpeg_comments(jpeg_data)
    assert comments == ["HelloJPEGComment"]


def test_repair_zip_header():
    corrupted = b"\x00\x00\x00\x00\x14\x00"
    repaired = repair_zip_header(corrupted)
    assert repaired[:4] == ZIP_LOCAL_FILE_HEADER


def test_decode_html_entities():
    # &#71;&#69;&#84; -> GET
    html_str = "&#71;&#69;&#84;&#83;&#70;&#76;&#65;&#71;"
    assert decode_html_entities(html_str) == "GETSFLAG"
    assert decode_html_entities("foo &amp; bar") == "foo & bar"

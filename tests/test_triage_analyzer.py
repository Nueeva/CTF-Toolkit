from __future__ import annotations

import os
import tempfile
from ctf_toolkit.triage.analyzer import (
    shannon_entropy,
    index_of_coincidence,
    triage_data,
    triage_file,
)


def test_shannon_entropy() -> None:
    # Empty data
    assert shannon_entropy(b"") == 0.0

    # Repetitive data (single symbol -> 0 entropy)
    assert shannon_entropy(b"A" * 100) == 0.0

    # 2 symbols with equal probability -> 1 bit entropy
    assert abs(shannon_entropy(b"AB" * 50) - 1.0) < 0.001

    # 256 unique bytes evenly distributed -> 8 bits entropy
    all_bytes = bytes(range(256))
    assert abs(shannon_entropy(all_bytes) - 8.0) < 0.001


def test_index_of_coincidence() -> None:
    # English text sample (IoC typically ~0.060 - 0.070)
    english_sample = (
        "Cryptography is the practice and study of techniques for secure communication "
        "in the presence of adversarial third parties. More generally, cryptography is about "
        "constructing and analyzing protocols that prevent third parties or the public from "
        "reading private messages."
    )
    ioc = index_of_coincidence(english_sample)
    assert ioc >= 0.055

    # Short / single character string
    assert index_of_coincidence("A") == 0.0


def test_triage_magic_signatures() -> None:
    # PNG
    png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20
    rep_png = triage_data(png_data)
    assert rep_png.magic_type == "PNG Image"
    assert rep_png.category_hint == "forensics"

    # ELF
    elf_data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
    rep_elf = triage_data(elf_data)
    assert rep_elf.magic_type == "ELF Executable/Binary"
    assert rep_elf.category_hint == "binex/reversing"

    # ZIP
    zip_data = b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 30
    rep_zip = triage_data(zip_data)
    assert rep_zip.magic_type == "ZIP Archive"


def test_triage_encodings_and_suggestions() -> None:
    # Hex
    hex_str = b"47455453464c41477b6865785f7472696167657d"
    rep_hex = triage_data(hex_str)
    assert "Hexadecimal" in rep_hex.encodings_detected
    assert any("hex_decode" in s for s in rep_hex.suggestions)

    # Base64
    b64_str = b"R0VUU0ZMQUd7YmFzZTY0X3RyaWFnZV92ZWN0b3J9"
    rep_b64 = triage_data(b64_str)
    assert "Base64" in rep_b64.encodings_detected

    # Zero-width
    zw_text = "secret\u200b\u200c\u200b\u200cdata".encode("utf-8")
    rep_zw = triage_data(zw_text)
    assert "Zero-Width Steganography" in rep_zw.encodings_detected


def test_triage_embedded_flag() -> None:
    blob = b"Random binary data \x90\x90\x90 FLAG{embedded_in_triage} more data"
    rep = triage_data(blob)
    assert "FLAG{embedded_in_triage}" in rep.flags_found


def test_triage_file() -> None:
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"\x89PNG\r\n\x1a\nDummy PNG payload with FLAG{temp_file_triage}")
        fpath = f.name

    try:
        rep = triage_file(fpath)
        assert rep.magic_type == "PNG Image"
        assert "FLAG{temp_file_triage}" in rep.flags_found
        summary = rep.summary()
        assert "TRIAGE REPORT" in summary
        assert "PNG Image" in summary
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)

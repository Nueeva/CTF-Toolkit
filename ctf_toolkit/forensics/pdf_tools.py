from __future__ import annotations

import base64
import re
import zlib


def extract_pdf_metadata(pdf_bytes: bytes) -> dict[str, str]:
    """Extract standard metadata fields from raw PDF bytes without external dependencies."""
    content = pdf_bytes.decode("latin1", errors="ignore")
    fields = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"]
    result: dict[str, str] = {}

    for field in fields:
        # 1. Match literal string /Field (value)
        match_literal = re.search(rf"/{field}\s*\((.*?)\)", content, re.DOTALL)
        if match_literal:
            raw_val = match_literal.group(1)
            # Unescape octal characters e.g. \173 -> {
            unescaped = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), raw_val)
            # Unescape standard escapes \(, \), \\
            unescaped = unescaped.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
            result[field] = unescaped
            continue

        # 2. Match hex string /Field <hex>
        match_hex = re.search(rf"/{field}\s*<([0-9a-fA-F\s]+)>", content)
        if match_hex:
            raw_hex = re.sub(r"\s+", "", match_hex.group(1))
            try:
                result[field] = bytes.fromhex(raw_hex).decode("utf-8", errors="replace")
            except Exception:
                result[field] = raw_hex

    return result


def extract_pdf_decompressed_streams(pdf_bytes: bytes) -> list[bytes]:
    """Extract and decompress all streams in PDF handling FlateDecode and ASCII85Decode."""
    streams = re.findall(rb"<<(.*?)>>\s*stream[\r\n]+(.*?)[\r\n]+endstream", pdf_bytes, re.DOTALL)
    decompressed: list[bytes] = []
    for meta, sdata in streams:
        raw = sdata.strip()
        is_a85 = b"ASCII85Decode" in meta
        is_flate = b"FlateDecode" in meta
        data_to_decompress = raw
        if is_a85:
            if not data_to_decompress.startswith(b"<~"):
                data_to_decompress = b"<~" + data_to_decompress
            if not data_to_decompress.endswith(b"~>"):
                data_to_decompress = data_to_decompress + b"~>"
            try:
                data_to_decompress = base64.a85decode(data_to_decompress, adobe=True)
            except Exception:
                pass
        if is_flate:
            try:
                decompressed.append(zlib.decompress(data_to_decompress))
                continue
            except Exception:
                pass
        decompressed.append(data_to_decompress)
    return decompressed


def extract_pdf_all_text_tokens(pdf_bytes: bytes) -> list[str]:
    """Extract all text string tokens inside parentheses from PDF streams."""
    streams = extract_pdf_decompressed_streams(pdf_bytes)
    all_data = pdf_bytes + b"\n" + b"\n".join(streams)
    tokens: list[str] = []
    for m in re.finditer(rb"\((.*?)\)\s*(?:Tj|TJ)", all_data):
        tokens.append(m.group(1).decode("latin-1", errors="ignore"))
    return tokens

from __future__ import annotations

import re


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

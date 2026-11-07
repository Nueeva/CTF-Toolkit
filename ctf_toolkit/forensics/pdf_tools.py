from __future__ import annotations

import re


def extract_pdf_metadata(pdf_bytes: bytes) -> dict[str, str]:
    """Extract standard metadata fields from raw PDF bytes without external dependencies."""
    content = pdf_bytes.decode("latin1", errors="ignore")
    fields = ["Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate"]
    result: dict[str, str] = {}

    for field in fields:
        # Match /Field (value) or /Field <hex>
        match = re.search(rf"/{field}\s*\((.*?)\)", content, re.DOTALL)
        if match:
            raw_val = match.group(1)
            # Unescape octal characters e.g. \173 -> {
            unescaped = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), raw_val)
            # Unescape standard escapes \(, \), \\
            unescaped = unescaped.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
            result[field] = unescaped

    return result

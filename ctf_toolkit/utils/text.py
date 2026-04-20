from __future__ import annotations

import math
import re
from collections import Counter

ASCII_PRINTABLE_START = 32
ASCII_PRINTABLE_END = 126


def redact_sensitive_text(text: str) -> str:
    redacted = re.sub(r"(?i)(password\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", text)
    redacted = re.sub(r"(?i)(token\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", redacted)
    redacted = re.sub(r"(?i)(secret\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", redacted)
    redacted = re.sub(r'(?i)("password"\s*:\s*")[^"]*(")', r"\1[REDACTED]\2", redacted)
    redacted = re.sub(r'(?i)("token"\s*:\s*")[^"]*(")', r"\1[REDACTED]\2", redacted)
    redacted = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+", r"\1[REDACTED]", redacted)
    return redacted


def extract_printable_strings(raw_bytes: bytes, min_len: int = 4) -> list[str]:
    results: list[str] = []
    current: list[str] = []
    for b in raw_bytes:
        if ASCII_PRINTABLE_START <= b <= ASCII_PRINTABLE_END:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def hexdump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

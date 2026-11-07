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


BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def base45_decode(s: str) -> bytes:
    """Decode a Base45 (RFC 9285) encoded string into bytes."""
    res = bytearray()
    for i in range(0, len(s), 3):
        chunk = s[i : i + 3]
        if len(chunk) == 3:
            c0, c1, c2 = [BASE45_CHARSET.index(c) for c in chunk]
            val = c0 + c1 * 45 + c2 * 45 * 45
            res.append(val // 256)
            res.append(val % 256)
        elif len(chunk) == 2:
            c0, c1 = [BASE45_CHARSET.index(c) for c in chunk]
            val = c0 + c1 * 45
            res.append(val)
        else:
            raise ValueError(f"Invalid Base45 chunk length at index {i}")
    return bytes(res)


def base45_encode(data: bytes) -> str:
    """Encode bytes into a Base45 (RFC 9285) string."""
    res: list[str] = []
    for i in range(0, len(data), 2):
        chunk = data[i : i + 2]
        if len(chunk) == 2:
            val = chunk[0] * 256 + chunk[1]
            c0 = val % 45
            c1 = (val // 45) % 45
            c2 = val // (45 * 45)
            res.extend([BASE45_CHARSET[c0], BASE45_CHARSET[c1], BASE45_CHARSET[c2]])
        else:
            val = chunk[0]
            c0 = val % 45
            c1 = val // 45
            res.extend([BASE45_CHARSET[c0], BASE45_CHARSET[c1]])
    return "".join(res)

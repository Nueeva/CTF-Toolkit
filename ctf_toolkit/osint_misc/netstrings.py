from __future__ import annotations

import re


def parse_netstrings(data: bytes | str) -> list[str]:
    """Parse DJB netstring formatted byte/text stream (<len>:<content>,) into a list of strings."""
    raw = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    items: list[str] = []
    idx = 0
    pattern = re.compile(r"(\d+):")

    while idx < len(raw):
        match = pattern.match(raw, idx)
        if not match:
            break
        length = int(match.group(1))
        content_start = match.end()
        content_end = content_start + length

        if content_end <= len(raw):
            items.append(raw[content_start:content_end])
            idx = content_end
            if idx < len(raw) and raw[idx] == ",":
                idx += 1
        else:
            break

    return items


def encode_netstring(s: str | bytes) -> bytes:
    """Encode string or bytes into netstring format: <len>:<content>,"""
    content = s.encode("utf-8") if isinstance(s, str) else s
    return f"{len(content)}:".encode("ascii") + content + b","
